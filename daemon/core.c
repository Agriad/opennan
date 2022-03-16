#include "core.h"

#include <stdbool.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <pcap.h>
#include <fcntl.h>
#include <netinet/ether.h>
#include <netinet/in.h>

#include <utils.h>
#include <peer.h>
#include <rx.h>
#include <tx.h>
#include <log.h>
#include <timer.h>

#include "netutils.h"
#include "cmd.h"

#define ETHER_LENGTH 14
#define ETHER_DST_OFFSET 0
#define ETHER_SRC_OFFSET 6
#define ETHER_ETHERTYPE_OFFSET 12

static void nan_neighbor_add(struct nan_peer *peer, void *data)
{
    struct io_state *io_state = data;
    neighbor_add(io_state->host_ifindex, &peer->addr, &peer->ipv6_addr);
}

static void nan_neighbor_remove(struct nan_peer *peer, void *data)
{
    struct io_state *io_state = data;
    log_debug("Peer removed %s", ether_addr_to_string(&peer->addr));
    neighbor_remove(io_state->host_ifindex, &peer->ipv6_addr);
}

int nan_init(struct daemon_state *state, const char *wlan, const char *host, int channel, const char *dump)
{
    int err;
    char hostname[HOST_NAME_LENGTH_MAX + 1];

    srand(clock_time_usec());

    if ((err = netutils_init()))
        return err;

    if ((err = io_state_init(&state->io_state, wlan, host, channel, NULL)))
        return err;

    if (gethostname(hostname, sizeof(hostname)))
        return -errno;

    init_nan_state(&state->nan_state, hostname, &state->io_state.if_ether_addr,
                   channel, clock_time_usec());

    nan_peer_set_callbacks(&state->nan_state.peers,
                           nan_neighbor_add, &state->io_state,
                           nan_neighbor_remove, &state->io_state);

    state->dump = dump;
    state->last_cmd = NULL;

    return 0;
}

void nan_free(struct daemon_state *state)
{
    if (state->last_cmd)
        free(state->last_cmd);
    io_state_free(&state->io_state);
    netutils_cleanup();
}

static void ev_timer_rearm(struct ev_loop *loop, ev_timer *timer, double in)
{
    ev_timer_stop(loop, timer);
    ev_timer_set(timer, in, 0);
    ev_timer_start(loop, timer);
}

inline static void ev_timer_rearm_usec(struct ev_loop *loop, ev_timer *timer, uint64_t in_usec)
{
    ev_timer_rearm(loop, timer, (double)USEC_TO_SEC(in_usec));
}

static void dump_frame(const char *dump_file, const struct pcap_pkthdr *header, const uint8_t *buf)
{
    if (!dump_file)
        return;

    /* Make sure file exists because 'pcap_dump_open_append' does NOT create file for you */
    fclose(fopen(dump_file, "a+"));
    pcap_t *p = pcap_open_dead(DLT_IEEE802_11_RADIO, BUF_MAX_LENGTH);
    pcap_dumper_t *dumper = pcap_dump_open_append(p, dump_file);
    pcap_dump((u_char *)dumper, header, buf);
    pcap_close(p);
    pcap_dump_close(dumper);
}

void nan_send_beacon(struct daemon_state *state, enum nan_beacon_type type, uint64_t now_usec)
{
    log_debug("nan send beacon: sending beacon");

    struct buf *buf = buf_new_owned(BUF_MAX_LENGTH);
    nan_build_beacon_frame(buf, &state->nan_state, type, now_usec);
    if (buf_error(buf) < 0)
    {
        log_error("Could not build beacon frame: %s", nan_beacon_type_to_string(type));
        return;
    }

    int length = buf_position(buf);
    log_trace("Send %s beacon of length %d", nan_beacon_type_to_string(type), length);
    int err = wlan_send(&state->io_state, buf_data(buf), length);
    if (err < 0)
        log_error("Could not send frame: %d", err);
}

void nan_send_discovery_beacon(struct ev_loop *loop, ev_timer *timer, int revents)
{
    (void)revents;
    struct daemon_state *state = timer->data;
    uint64_t now_usec = clock_time_usec();

    if (nan_can_send_discovery_beacon(&state->nan_state, now_usec))
    {
        nan_send_beacon(state, NAN_DISCOVERY_BEACON, now_usec);
        nan_timer_set_last_discovery_beacon_usec(&state->nan_state.timer, now_usec);
    }

    uint64_t next_beacon_time_usec = nan_timer_next_discovery_beacon_usec(&state->nan_state.timer, now_usec);
    ev_timer_rearm_usec(loop, timer, next_beacon_time_usec);
}

void nan_send_buffered_frames(struct daemon_state *state)
{
    struct buf *buf = NULL;
    while (circular_buf_get(state->nan_state.buffer, (any_t *)&buf, false) != -1)
    {
        int length = buf_position(buf);
        log_trace("Send buffered frame of length %d", length);
        int err = wlan_send(&state->io_state, buf_data(buf), length);

        buf_free(buf);
        if (err < 0)
            log_error("Could not send frame: %d", err);
    }
}

void nan_send_service_discovery_frame(struct daemon_state *state)
{
    list_t announced_services = list_init();
    nan_get_services_to_announce(&state->nan_state.services, announced_services);
    if (list_len(announced_services) > 0)
    {
        struct buf *buf = buf_new_owned(BUF_MAX_LENGTH);
        nan_build_service_discovery_frame(buf, &state->nan_state, &NAN_NETWORK_ID, announced_services);

        int length = buf_position(buf);
        int err = wlan_send(&state->io_state, buf_data(buf), length);

        log_trace("Send service discovery frame for services:");
        struct nan_service *service;
        LIST_FOR_EACH(announced_services, service, log_trace(" * %s", service->service_name))

        buf_free(buf);
        if (err < 0)
            log_error("Could not send service discovery frame: %d", err);

        nan_update_announced_services(announced_services);
    }
    list_free(announced_services, false);
}

void nan_handle_discovery_window(struct ev_loop *loop, ev_timer *timer, int revents)
{
    (void)revents;
    struct daemon_state *state = timer->data;
    uint64_t now_usec = clock_time_usec();

    if (!nan_timer_in_dw(&state->nan_state.timer, now_usec) ||
        !nan_timer_initial_scan_done(&state->nan_state.timer, now_usec))
    {
        uint64_t next_dw_usec = nan_timer_next_dw_usec(&state->nan_state.timer, now_usec);
        log_trace("not in dw, next: %lu (%lu tu)", next_dw_usec, USEC_TO_TU(next_dw_usec));
        ev_timer_rearm(loop, timer, (double)USEC_TO_SEC(next_dw_usec));
        return;
    }

    log_trace("In discovery window at %lu", nan_timer_get_synced_time_usec(&state->nan_state.timer, now_usec));

    nan_send_beacon(state, NAN_SYNC_BEACON, now_usec);
    nan_send_buffered_frames(state);
    nan_send_service_discovery_frame(state);

    now_usec = clock_time_usec();
    uint64_t dw_end_usec = nan_timer_dw_end_usec(&state->nan_state.timer, now_usec);
    ev_timer_rearm_usec(loop, &state->ev_state.discovery_window_end, dw_end_usec);

    uint64_t next_dw_usec = nan_timer_next_dw_usec(&state->nan_state.timer, now_usec);
    ev_timer_rearm_usec(loop, timer, next_dw_usec);
}

void nan_handle_discovery_window_end(struct ev_loop *loop, ev_timer *timer, int revents)
{
    (void)loop;
    (void)revents;
    struct daemon_state *state = timer->data;
    uint64_t now_usec = clock_time_usec();

    log_trace("discovery window end");

    nan_master_election(&state->nan_state.sync, state->nan_state.peers.peers, now_usec);
    nan_check_anchor_master_expiration(&state->nan_state.sync);
}

void nan_clean_peers(struct ev_loop *loop, ev_timer *timer, int revents)
{
    (void)revents;
    struct daemon_state *state = timer->data;
    uint64_t now_usec = clock_time_usec();

    nan_peers_clean(&state->nan_state.peers, now_usec);

    ev_timer_again(loop, timer);
}

void nan_receive_frame(uint8_t *user, const struct pcap_pkthdr *header, const uint8_t *buf)
{
    log_trace("Received frame of length %d", header->caplen);
    struct daemon_state *state = (void *)user;
    struct buf *frame = buf_new_const(buf, header->caplen);

    int result = nan_rx(frame, &state->nan_state);
    if (result < RX_OK)
    {
        log_trace("unhandled frame: %s", nan_rx_result_to_string(result));
        dump_frame(state->dump, header, buf);
    }
    if (result > RX_OK)
        log_trace("unhandled frame: %s", nan_rx_result_to_string(result));

    buf_free(frame);
}

void wlan_device_ready(struct ev_loop *loop, ev_io *handle, int revents)
{
    (void)loop;
    (void)revents;
    struct daemon_state *state = handle->data;
    pcap_dispatch(state->io_state.wlan_handle, 1, &nan_receive_frame, handle->data);
}

void host_device_ready(struct ev_loop *loop, ev_io *handle, int revents)
{
    (void)loop;
    (void)revents;
    struct daemon_state *state = handle->data;

    int size = ETHER_MAX_LEN;
    struct buf *buf = buf_new_owned(size);
    int err = host_receive(&state->io_state, (uint8_t *)buf_current(buf), &size);
    if (err < 0)
    {
        log_error("Could not read from host: %d", err);
        goto cleanup;
    }
    buf_resize(buf, size);

    struct ether_addr destination;
    if (size < (int)sizeof(destination))
    {
        log_error("Received host data to short");
        goto cleanup;
    }
    read_ether_addr(buf, &destination);

    /*
    offset += read_ether_addr(buf, offset, &source);

    uint16_t frame_type;
    offset += read_be16(buf, offset, &frame_type);

    // IPv6
    if (frame_type == 0x86dd)
    {
        // IP version (4b) + traffic class (8b) + flow label (20b) + payload length
        offset += 4 + 2;

        uint8_t next_header;
        offset += read_u8(buf, offset, &next_header);

        // IP hop limit + source
        offset += 1 + 16;

        struct in6_addr ipv6_destination_address;
        struct in6_addr ipv6_mdns_address = {{0xff02, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xfb}};

        offset += read_bytes_copy(buf, offset, (uint8_t *)&ipv6_destination_address, 16);
        if (!IN6_ARE_ADDR_EQUAL(&ipv6_destination_address, &ipv6_mdns_address))
            goto cleanup;

        // 17 = UDP, 59 = no next header
        while (offset < len && next_header != 17 && next_header != 59)
        {
            uint8_t header_extension_length;
            offset += read_u8(buf, offset, &next_header);
            offset += read_u8(buf, offset, &header_extension_length);
            // IP extension specific data + header extension length
            offset += 6 + header_extension_length;
        }

        if (offset >= len || next_header != 17)
            goto cleanup;

        // UDP source port
        offset += 2;

        uint16_t destination_port;
        offset += read_be16(buf, offset, &destination_port);
        if (destination_port != 5354)
            goto cleanup;

        // UDP length + checksum
        offset += 2 + 2 ;
    }
    */

    bool is_multicast = destination.ether_addr_octet[0] & 0x01;
    if (is_multicast)
    {
        log_trace("Received multicast data for %s", ether_addr_to_string(&destination));
        goto cleanup;
    }

    if (ether_addr_equal(&state->nan_state.self_address, &destination))
    {
        log_trace("Received frame for self");
        host_send(&state->io_state, buf_data(buf), size);
        goto cleanup;
    }

    struct nan_peer *peer;
    if (nan_peer_get(&state->nan_state.peers, &destination, &peer) == PEER_MISSING)
    {
        log_trace("Drop frame to non-peer %s", ether_addr_to_string(&destination));
        goto cleanup;
    }

    log_info("Received host data for peer %s (%s)",
             ether_addr_to_string(&peer->addr), ipv6_addr_to_string(&peer->ipv6_addr));

cleanup:
    buf_free(buf);
}

void stdin_ready(struct ev_loop *loop, ev_io *handler, int revents)
{
    (void)revents;
    (void)loop;
    char buf[BUF_MAX_LENGTH];
    fgets(buf, BUF_MAX_LENGTH, stdin);

    size_t len = 0;
    while (buf[len] != '\n')
    {
        len++;
    }
    char *cmd = malloc(len + 1);
    memcpy(cmd, buf, len);
    cmd[len] = '\0';

    struct daemon_state *state = handler->data;
    nan_handle_cmd(&state->nan_state, cmd, &state->last_cmd);
    free(cmd);
}

void nan_schedule(struct ev_loop *loop, struct daemon_state *state)
{
    state->ev_state.loop = loop;

    /* Timer for discovery beacon */
    state->ev_state.send_discovery_beacon.data = (void *)state;
    ev_timer_init(&state->ev_state.send_discovery_beacon, nan_send_discovery_beacon, 0, 0);
    ev_timer_start(loop, &state->ev_state.send_discovery_beacon);

    /* Timer for dicovery window */
    state->ev_state.discovery_window.data = (void *)state;
    ev_timer_init(&state->ev_state.discovery_window, nan_handle_discovery_window, 0, 0);
    ev_timer_start(loop, &state->ev_state.discovery_window);

    /* Timer for dicovery window end, started by discovery window timer */
    state->ev_state.discovery_window_end.data = (void *)state;
    ev_timer_init(&state->ev_state.discovery_window_end, nan_handle_discovery_window_end, 0, 0);

    /* Timer to clean outdated peers */
    state->ev_state.clean_peers.data = (void *)state;
    ev_timer_init(&state->ev_state.clean_peers, nan_clean_peers,
                  0, (double)USEC_TO_SEC(state->nan_state.peers.clean_interval_usec));
    ev_timer_start(loop, &state->ev_state.clean_peers);

    /* Trigger frame reception from WLAN device */
    state->ev_state.read_wlan.data = (void *)state;
    ev_io_init(&state->ev_state.read_wlan, wlan_device_ready, state->io_state.wlan_fd, EV_READ);
    ev_io_start(loop, &state->ev_state.read_wlan);

    /* Trigger frame reception from host device */
    state->ev_state.read_host.data = (void *)state;
    ev_io_init(&state->ev_state.read_host, host_device_ready, state->io_state.host_fd, EV_READ);
    ev_io_start(loop, &state->ev_state.read_host);

    /* Trigger for user input from stdin */
    state->ev_state.read_stdin.data = (void *)state;
    ev_io_init(&state->ev_state.read_stdin, stdin_ready, STDIN_FILENO, EV_READ);
    ev_io_start(loop, &state->ev_state.read_stdin);
}
