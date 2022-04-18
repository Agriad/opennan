#include <stdio.h>
#include <pcap/pcap.h>

#include "test.h"

// int main(int argc, char *argv[])
// {
// 	log_set_level(LOG_INFO);

// 	bool dump = false;
// 	char *dump_file = FAILED_DUMP;

// 	char wlan[IFNAMSIZ] = "";
// 	char host[IFNAMSIZ] = DEFAULT_NAN_DEVICE;
// 	int channel = 6;

// 	struct daemon_state state;
// 	state.start_time_usec = clock_time_usec();

// 	struct ev_loop *loop = EV_DEFAULT;
// 	nan_schedule(loop, &state);
// 	ev_run(loop, 0);

// 	nan_free(&state);

// 	return EXIT_SUCCESS;
// }

// void nan_schedule(struct ev_loop *loop, struct daemon_state *state)
// {
//     state->ev_state.loop = loop;

//     /* Timer for discovery beacon */
//     state->ev_state.send_discovery_beacon.data = (void *)state;
//     ev_timer_init(&state->ev_state.send_discovery_beacon, nan_send_discovery_beacon, 0, 0);
//     ev_timer_start(loop, &state->ev_state.send_discovery_beacon);

//     /* Timer for dicovery window */
//     state->ev_state.discovery_window.data = (void *)state;
//     ev_timer_init(&state->ev_state.discovery_window, nan_handle_discovery_window, 0, 0);
//     ev_timer_start(loop, &state->ev_state.discovery_window);
// }

// void nan_handle_discovery_window(struct ev_loop *loop, ev_timer *timer, int revents)
// {
//     struct daemon_state *state = timer->data;
//     uint64_t now_usec = clock_time_usec();

//     nan_send_beacon(state, NAN_SYNC_BEACON, now_usec);
// }

// void nan_send_beacon_test(struct daemon_state *state, enum nan_beacon_type type, uint64_t now_usec)
// {
//     struct buf *buf = buf_new_owned(BUF_MAX_LENGTH);

//     struct nan_beacon_frame *beacon_header = (struct nan_beacon_frame *)(buf_current(buf));
//     int buf_address = buf_current(buf);

//     nan_build_beacon_frame(buf, &state->nan_state, type, now_usec);

//     if (buf_error(buf) < 0)
//     {
//         log_error("Could not build beacon frame: %s", nan_beacon_type_to_string(type));
//         return;
//     }

//     int length = buf_position(buf);
//     int err = wlan_send(&state->io_state, buf_data(buf), length);
//     if (err < 0)
//         log_error("Could not send frame: %d", err);
// }

// int wlan_send_test(const struct io_state *state, const uint8_t *buffer, int length)
// {
//     if (!state || !state->wlan_handle)
//         return -EINVAL;

//     int result = pcap_inject(state->wlan_handle, buffer, length);

//     if (result < 0)
//         log_error("unable to inject packet (%s)", pcap_geterr(state->wlan_handle));
//     else
//         log_trace("injected %d bytes", result);

//     return result;
// }

static int open_nonblocking_device(const char *dev, pcap_t **pcap_handle, const struct ether_addr *bssid_filter)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_create(dev, errbuf);
    if (handle == NULL)
    {
        printf("pcap: unable to open device %s (%s)\n", dev, errbuf);
        return -1;
    }

    pcap_set_snaplen(handle, 65535);
    pcap_set_promisc(handle, 1);
    pcap_set_timeout(handle, 1);
#ifdef __APPLE__
    /* On Linux, we activate monitor mode via nl80211 */
    pcap_set_rfmon(handle, 1);
#endif /* __APPLE__ */

    if (pcap_activate(handle) < 0)
    {
        printf("pcap: unable to activate device %s (%s)\n", dev, pcap_geterr(handle));
        pcap_close(handle);
        return -1;
    }

    if (pcap_setnonblock(handle, 1, errbuf) < 0)
    {
        printf("pcap: cannot set to non-blocking mode (%s)\n", errbuf);
        pcap_close(handle);
        return -1;
    }

    /* FIXME direction does not seem to have an effect (we get our own frames every time we poll) */
    if (pcap_setdirection(handle, PCAP_D_IN) < 0)
    {
        printf("pcap: unable to monitor only incoming traffic on device %s (%s)\n", dev, pcap_geterr(handle));
    }

    if (pcap_datalink(handle) != DLT_IEEE802_11_RADIO)
    {
        printf("pcap: device %s does not support radiotap headers\n", dev);
        pcap_close(handle);
        return -1;
    }

    if (bssid_filter)
    {
        struct bpf_program filter;
        char filter_str[128];
        snprintf(filter_str, sizeof(filter_str), "wlan addr3 %s", ether_ntoa(bssid_filter));
        if (pcap_compile(handle, &filter, filter_str, 1, PCAP_NETMASK_UNKNOWN) < 0)
        {
            printf("pcap: could not create filter (%s)\n", pcap_geterr(handle));
            return -1;
        }

        if (pcap_setfilter(handle, &filter) < 0)
        {
            printf("pcap: could not set filter (%s)\n", pcap_geterr(handle));
            return -1;
        }
    }

    int fd = pcap_get_selectable_fd(handle);
    if (fd < 0)
    {
        printf("pcap: unable to get fd\n");
        return -1;
    }

    *pcap_handle = handle;
    return fd;
}

int main() {
    int length = 77;
    uint8_t own_buffer[length];
    pcap_t *wlan_handle;
    char wlan_ifname[IFNAMSIZ];

    // open_nonblocking_device(wlan_ifname, wlan_handle, bssid_filter);
    // open_nonblocking_device(wlan_ifname, wlan_handle, NULL);

    // for(int i = 0; i < length; i++) {
    //     own_buffer[i] = 0xff;
    // }

    printf("here1\n");
    int result = pcap_inject(wlan_handle, own_buffer, length);
    printf("here2\n");


    // while(1) {
    //     int result = pcap_inject(wlan_handle, own_buffer, length);

    //     if (result < 0)
    //         printf("unable to inject packet (%s)", pcap_geterr(wlan_handle));
    //     else
    //         printf("injected %d bytes", result);
    //     sleep(0.5);
    // }
}

// wlan send: for loop - 0: 0
// 11:52:00 DEBUG io.c:376: wlan send: for loop - 1: 0
// 11:52:00 DEBUG io.c:376: wlan send: for loop - 2: b
// 11:52:00 DEBUG io.c:376: wlan send: for loop - 3: 0
// 11:52:00 DEBUG io.c:376: wlan send: for loop - 4: 26
// 11:52:00 DEBUG io.c:376: wlan send: for loop - 5: 0
// 11:52:00 DEBUG io.c:376: wlan send: for loop - 6: 0
// 11:52:00 DEBUG io.c:376: wlan send: for loop - 7: 0
// 11:52:00 DEBUG io.c:376: wlan send: for loop - 8: 10
// 11:52:00 DEBUG io.c:376: wlan send: for loop - 9: 2
// 11:52:00 DEBUG io.c:376: wlan send: for loop - 10: c8
// 11:52:00 DEBUG io.c:376: wlan send: for loop - 11: 80
// 11:52:00 DEBUG io.c:376: wlan send: for loop - 12: 0
// 11:52:00 DEBUG io.c:376: wlan send: for loop - 13: 0
// 11:52:00 DEBUG io.c:376: wlan send: for loop - 14: 0
// 11:52:00 DEBUG io.c:376: wlan send: for loop - 15: ff
// 11:52:00 DEBUG io.c:376: wlan send: for loop - 16: ff
// 11:52:00 DEBUG io.c:376: wlan send: for loop - 17: ff
// 11:52:00 DEBUG io.c:376: wlan send: for loop - 18: ff
// 11:52:00 DEBUG io.c:376: wlan send: for loop - 19: ff
// 11:52:00 DEBUG io.c:376: wlan send: for loop - 20: ff
// 11:52:00 DEBUG io.c:376: wlan send: for loop - 21: 0
// 11:52:00 DEBUG io.c:376: wlan send: for loop - 22: c0
// 11:52:00 DEBUG io.c:376: wlan send: for loop - 23: ca
// 11:52:00 DEBUG io.c:376: wlan send: for loop - 24: ae
// 11:52:00 DEBUG io.c:376: wlan send: for loop - 25: 65
// 11:52:00 DEBUG io.c:376: wlan send: for loop - 26: 79
// 11:52:00 DEBUG io.c:376: wlan send: for loop - 27: 50
// 11:52:00 DEBUG io.c:376: wlan send: for loop - 28: 6f
// 11:52:00 DEBUG io.c:376: wlan send: for loop - 29: 9a
// 11:52:00 DEBUG io.c:376: wlan send: for loop - 30: 1
// 11:52:00 DEBUG io.c:376: wlan send: for loop - 31: 78
// 11:52:00 DEBUG io.c:376: wlan send: for loop - 32: 1d
// 11:52:00 DEBUG io.c:376: wlan send: for loop - 33: 0
// 11:52:00 DEBUG io.c:376: wlan send: for loop - 34: 1
// 11:52:00 DEBUG io.c:376: wlan send: for loop - 35: ff
// 11:52:00 DEBUG io.c:376: wlan send: for loop - 36: ff
// 11:52:00 DEBUG io.c:376: wlan send: for loop - 37: 23
// 11:52:00 DEBUG io.c:376: wlan send: for loop - 38: 71
// 11:52:00 DEBUG io.c:376: wlan send: for loop - 39: 0
// 11:52:00 DEBUG io.c:376: wlan send: for loop - 40: 0
// 11:52:00 DEBUG io.c:376: wlan send: for loop - 41: 0
// 11:52:00 DEBUG io.c:376: wlan send: for loop - 42: 0
// 11:52:00 DEBUG io.c:376: wlan send: for loop - 43: 0
// 11:52:00 DEBUG io.c:376: wlan send: for loop - 44: 2
// 11:52:00 DEBUG io.c:376: wlan send: for loop - 45: 20
// 11:52:00 DEBUG io.c:376: wlan send: for loop - 46: 4
// 11:52:00 DEBUG io.c:376: wlan send: for loop - 47: ff
// 11:52:00 DEBUG io.c:376: wlan send: for loop - 48: 19
// 11:52:00 DEBUG io.c:376: wlan send: for loop - 49: 50
// 11:52:00 DEBUG io.c:376: wlan send: for loop - 50: 6f
// 11:52:00 DEBUG io.c:376: wlan send: for loop - 51: 9a
// 11:52:00 DEBUG io.c:376: wlan send: for loop - 52: 13
// 11:52:00 DEBUG io.c:376: wlan send: for loop - 53: 0
// 11:52:00 DEBUG io.c:376: wlan send: for loop - 54: 2
// 11:52:00 DEBUG io.c:376: wlan send: for loop - 55: 0
// 11:52:00 DEBUG io.c:376: wlan send: for loop - 56: 0
// 11:52:00 DEBUG io.c:376: wlan send: for loop - 57: 0
// 11:52:00 DEBUG io.c:376: wlan send: for loop - 58: 1
// 11:52:00 DEBUG io.c:376: wlan send: for loop - 59: d
// 11:52:00 DEBUG io.c:376: wlan send: for loop - 60: 0
// 11:52:00 DEBUG io.c:376: wlan send: for loop - 61: 0
// 11:52:00 DEBUG io.c:376: wlan send: for loop - 62: c0
// 11:52:00 DEBUG io.c:376: wlan send: for loop - 63: ca
// 11:52:00 DEBUG io.c:376: wlan send: for loop - 64: ae
// 11:52:00 DEBUG io.c:376: wlan send: for loop - 65: 65
// 11:52:00 DEBUG io.c:376: wlan send: for loop - 66: 79
// 11:52:00 DEBUG io.c:376: wlan send: for loop - 67: 0
// 11:52:00 DEBUG io.c:376: wlan send: for loop - 68: 0
// 11:52:00 DEBUG io.c:376: wlan send: for loop - 69: 0
// 11:52:00 DEBUG io.c:376: wlan send: for loop - 70: 0
// 11:52:00 DEBUG io.c:376: wlan send: for loop - 71: 0
// 11:52:00 DEBUG io.c:376: wlan send: for loop - 72: 0
// 11:52:00 DEBUG io.c:376: wlan send: for loop - 73: 0
// 11:52:00 DEBUG io.c:376: wlan send: for loop - 74: b7
// 11:52:00 DEBUG io.c:376: wlan send: for loop - 75: 94
// 11:52:00 DEBUG io.c:376: wlan send: for loop - 76: 64
// 11:52:00 DEBUG io.c:376: wlan send: for loop - 77: 75
