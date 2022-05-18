#include <errno.h>
#include <ev.h>
#include <fcntl.h>
#include <net/if.h>
#include <pcap/pcap.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/stat.h> 
#include <time.h>
#include <unistd.h>

#ifndef __APPLE__
#include <linux/if_tun.h>
#else
#include <sys/sys_domain.h>
#include <sys/kern_control.h>
#include <netinet/in.h>
#include <netinet/in_var.h>
#endif /* __APPLE__ */

#include "test.h"

#include <unistd.h>
#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <netlink/route/link.h>
#include <netlink/route/neighbour.h>
#include <linux/nl80211.h>

int main(int argc, char *argv[])
{
	bool dump = false;

	char wlan[IFNAMSIZ] = "";
    // char wlan[IFNAMSIZ] = "wlx00c0caae6579";
    char host[IFNAMSIZ] = "nan0";
	int channel = 6;

	struct daemon_state state;
	state.start_time_usec = clock_time_usec();

	if (argc - optind != 1)
	{
        printf("Incorrect number of arguments: %d\n", argc - optind);
		return EXIT_FAILURE;
	}
	strcpy(wlan, argv[optind]);

    printf("here0\n");

    if (nan_init_test(&state, wlan, host, channel, NULL) < 0)
	{
        printf("could not initialize core\n");
		return EXIT_FAILURE;
	}
    printf("here1\n");
	struct ev_loop *loop = EV_DEFAULT;
    printf("here2\n");
	nan_schedule_test(loop, &state);
    printf("here3\n");

	return EXIT_SUCCESS;
}

void init_nan_state_test(struct nan_state *state, const char *hostname,
                    struct ether_addr *addr, int channel, uint64_t now_usec)
{
    strncpy(state->hostname, hostname, HOST_NAME_LENGTH_MAX);
    state->self_address = *addr;
    state->interface_address = *addr;

    state->buffer = circular_buf_init(16);
}

int nan_init_test(struct daemon_state *state, const char *wlan, const char *host, int channel, const char *dump)
{
    int err;
    char hostname[HOST_NAME_LENGTH_MAX + 1];

    if ((err = netutils_init_test()))
        return err;

    if ((err = io_state_init_test(&state->io_state, wlan, host, channel, NULL)))
        return err;

    state->dump = dump;
    state->last_cmd = NULL;

    return 0;
}

static struct nlroute_state nlroute_state;

static struct nl80211_state nl80211_state;


static int nl80211_init_test(struct nl80211_state *state)
{
	state->socket = nl_socket_alloc();
	if (!state->socket)
	{
        printf("Failed to allocate netlink socket.\n");
		return -ENOMEM;
	}

	nl_socket_set_buffer_size(state->socket, 8192, 8192);

	if (genl_connect(state->socket))
	{
        printf("Failed to connect to generic netlink.\n");
		nl_socket_free(state->socket);
		return -ENOLINK;
	}

	state->nl80211_id = genl_ctrl_resolve(state->socket, "nl80211");
	if (state->nl80211_id < 0)
	{
        printf("nl80211 not found.\n");
		nl_socket_free(state->socket);
		return -ENOENT;
	}

	return 0;
}

int netutils_init_test()
{
	int err;
	err = nlroute_init_test(&nlroute_state);
	if (err < 0)
		return err;
	err = nl80211_init_test(&nl80211_state);
	if (err < 0)
		return err;
	return 0;
}

static int nlroute_init_test(struct nlroute_state *state)
{
	state->socket = nl_socket_alloc();
	if (!state->socket)
	{
        printf("Failed to allocate netlink socket.\n");
		return -ENOMEM;
	}

	if (nl_connect(state->socket, NETLINK_ROUTE))
	{
        printf("Failed to connect to generic netlink.\n");
		nl_socket_free(state->socket);
		return -ENOLINK;
	}

	return 0;
}

int io_state_init_test(struct io_state *state, const char *wlan, const char *host, const int channel,
                  const struct ether_addr *bssid_filter)
{
    int err;

    if ((err = io_state_init_wlan_test(state, wlan, channel, bssid_filter)))
        return err;

    if ((err = io_state_init_host_test(state, host)))
        return err;

    return 0;
}

static int io_state_init_host_test(struct io_state *state, const char *host)
{
    if (strlen(host) > 0)
    {
        strcpy(state->host_ifname, host);
        /* Host interface needs to have same ether_addr, to make active (!) monitor mode work */
        state->host_fd = open_tun_test(state->host_ifname, &state->if_ether_addr);

        int err;
        if ((err = state->host_fd) < 0)
        {
            printf("Could not open device: %s\n", state->host_ifname);
            return err;
        }
        state->host_ifindex = if_nametoindex(state->host_ifname);
        if (!state->host_ifindex)
        {
            printf("No such interface exists %s\n", state->host_ifname);
            return -ENOENT;
        }
    }
    else
    {
        printf("No host device given, start without host device\n");
    }

    return 0;
}

static int open_tun_test(char *dev, const struct ether_addr *self)
{
#ifndef __APPLE__
    static int one = 1;
    struct ifreq ifr;
    int fd, err, s;

    if ((fd = open("/dev/net/tun", O_RDWR)) < 0)
    {
        printf("tun: unable to open tun device %d\n", fd);
        return fd;
    }

    memset(&ifr, 0, sizeof(ifr));

    /* Flags: IFF_TUN   - TUN device (no Ethernet headers)
	 *        IFF_TAP   - TAP device
	 *        IFF_NO_PI - Do not provide packet information
	 */
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    if (*dev)
        strncpy(ifr.ifr_name, dev, IFNAMSIZ);

    if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0)
    {
        close(fd);
        return err;
    }
    strcpy(dev, ifr.ifr_name);

    /* Set non-blocking mode */
    if ((err = ioctl(fd, FIONBIO, &one)) < 0)
    {
        close(fd);
        return err;
    }

    // Create a socket for ioctl
    s = socket(AF_INET6, SOCK_DGRAM, 0);

    // Set HW address
    ifr.ifr_hwaddr.sa_family = 1; /* ARPHRD_ETHER */
    memcpy(ifr.ifr_hwaddr.sa_data, self, 6);
    if ((err = ioctl(s, SIOCSIFHWADDR, &ifr)) < 0)
    {
        printf("tun: unable to set HW address\n");
        close(fd);
        return err;
    }

    // Get current flags and set them
    ioctl(s, SIOCGIFFLAGS, &ifr);
    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
    if ((err = ioctl(s, SIOCSIFFLAGS, &ifr)) < 0)
    {
        printf("tun: unable to set up\n");
        close(fd);
        return err;
    }

    /* Set reduced MTU */
    ifr.ifr_mtu = 1450; /* TODO arbitary limit to fit all headers */
    if ((err = ioctl(s, SIOCSIFMTU, (void *)&ifr)) < 0)
    {
        printf("tun: unable to set MTU");
        close(fd);
        return err;
    }

    close(s);

    return fd;
#else
    for (int i = 0; i < 16; ++i)
    {
        char tuntap[IFNAMSIZ];
        sprintf(tuntap, "/dev/tap%d\n", i);

        int fd = open(tuntap, O_RDWR);
        if (fd > 0)
        {
            struct ifreq ifr;
            struct in6_aliasreq ifr6;
            int err, s;

            if (fcntl(fd, F_SETFL, O_NONBLOCK) < 0)
            {
                // log_error("fcntl error on %s", tuntap);
                printf("fcntl error on %s\n", tuntap);
                return -errno;
            }

            sprintf(dev, "tap%d", i);

            // Create a socket for ioctl
            s = socket(AF_INET6, SOCK_DGRAM, 0);

            // Set HW address
            strlcpy(ifr.ifr_name, dev, sizeof(ifr.ifr_name));
            ifr.ifr_addr.sa_len = sizeof(struct ether_addr);
            ifr.ifr_addr.sa_family = AF_LINK;
            memcpy(ifr.ifr_addr.sa_data, self, sizeof(struct ether_addr));
            if ((err = ioctl(s, SIOCSIFLLADDR, (caddr_t)&ifr)) < 0)
            {
                // log_error("tun: unable to set HW address %s", ether_ntoa(self));
                printf("tun: unable to set HW address %s\n", ether_ntoa(self));
                close(fd);
                return err;
            }

            /* Set reduced MTU */
            ifr.ifr_mtu = 1450; /* TODO arbitary limit to fit all headers */
            if ((err = ioctl(s, SIOCSIFMTU, (caddr_t)&ifr)) < 0)
            {
                // log_error("tun: unable to set MTU");
                printf("tun: unable to set MTU\n");
                close(fd);
                return err;
            }

            /* Set IPv6 address */
            memset(&ifr6, 0, sizeof(ifr6));
            strlcpy(ifr6.ifra_name, dev, sizeof(ifr6.ifra_name));

            ifr6.ifra_addr.sin6_len = sizeof(ifr6.ifra_addr);
            ifr6.ifra_addr.sin6_family = AF_INET6;
            rfc4291_addr(self, &ifr6.ifra_addr.sin6_addr);

            ifr6.ifra_prefixmask.sin6_len = sizeof(ifr6.ifra_prefixmask);
            ifr6.ifra_prefixmask.sin6_family = AF_INET6;
            memset((void *)&ifr6.ifra_prefixmask.sin6_addr, 0x00, sizeof(ifr6.ifra_prefixmask));
            for (int i = 0; i < 8; i++) /* prefix length: 64 */
                ifr6.ifra_prefixmask.sin6_addr.s6_addr[i] = 0xff;

            if (ioctl(s, SIOCAIFADDR_IN6, (caddr_t)&ifr6) < 0)
            {
                // log_error("tun: unable to set IPv6 address, %s", strerror(errno));
                printf("tun: unable to set IPv6 address, %s\n", strerror(errno));
                close(fd);
                return -errno;
            }

            close(s);

            return fd;
        }
    }
    // log_error("tun: cannot open available device");
    printf("tun: cannot open available device\n");
    return -1;
#endif /* __APPLE__ */
}

int link_ether_addr_get_test(const char *ifname, struct ether_addr *addr)
{
	int err;
	struct rtnl_link *link;
	struct nl_addr *nladdr;

	err = rtnl_link_get_kernel(nlroute_state.socket, 0, ifname, &link);
	if (err < 0)
	{
		// log_error("Could not get link: %s", nl_geterror(err));
        printf("Could not get link: %s\n", nl_geterror(err));
		return err;
	}

	nladdr = rtnl_link_get_addr(link);

	*addr = *(struct ether_addr *)nl_addr_get_binary_addr(nladdr);

	return 0;
}

int io_state_init_wlan_test(struct io_state *state, const char *wlan, const int channel,
                       const struct ether_addr *bssid_filter)
{
    strcpy(state->wlan_ifname, wlan);

    state->wlan_fd = open_nonblocking_device_test(state->wlan_ifname, &state->wlan_handle, bssid_filter);

    if (link_ether_addr_get_test(state->wlan_ifname, &state->if_ether_addr) < 0)
    {
        printf("Could not get LLC address from %s\n", state->wlan_ifname);
        return -1;
    }

    return 0;
}

static int open_nonblocking_device_test(const char *dev, pcap_t **pcap_handle, const struct ether_addr *bssid_filter)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_create(dev, errbuf);
    if (handle == NULL)
    {
        printf("pcap: unable to open device\n");
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
        printf("pcap: unable to activate device\n");
        pcap_close(handle);
        return -1;
    }

    if (pcap_setnonblock(handle, 1, errbuf) < 0)
    {
        printf("pcap: cannot set to non-blocking mode\n");
        pcap_close(handle);
        return -1;
    }

    /* FIXME direction does not seem to have an effect (we get our own frames every time we poll) */
    if (pcap_setdirection(handle, PCAP_D_IN) < 0)
    {
        printf("pcap: unable to monitor only incoming traffic on device\n");
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

void nan_handle_discovery_window_test(struct ev_loop *loop, ev_timer *timer, int revents)
{
    printf("here5\n");
    (void)revents;
    struct daemon_state *state = timer->data;
    uint64_t now_usec = clock_time_usec();

    nan_send_beacon_test(state, NAN_SYNC_BEACON, now_usec);
}

void nan_schedule_test(struct ev_loop *loop, struct daemon_state *state)
{
    printf("here4\n");

    state->ev_state.loop = loop;

    // /* Timer for discovery beacon */

    /* Timer for dicovery window */
    state->ev_state.discovery_window.data = (void *)state;
    // ev_timer_init(&state->ev_state.discovery_window, nan_handle_discovery_window_test, 0, 0);

    uint8_t own_buffer[] = {
        0x00, 
        0x00,
        0x0b,
        0x00,
        0x26,
        0x00,
        0x00,
        0x00,
        0x10,
        0x02,
        0xc8,
        0x80,
        0x00,
        0x00,
        0x00,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0x00,
        0xc0,
        0xca,
        0xae,
        0x65,
        0x79,
        0x50,
        0x6f,
        0x9a,
        0x01,
        0x78,
        0x1d,
        0x00,
        0x01,
        0xff,
        0xff,
        0x23,
        0x71,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x02,
        0x20,
        0x04,
        0xff,
        0x19,
        0x50,
        0x6f,
        0x9a,
        0x13,
        0x00,
        0x02,
        0x00,
        0x00,
        0x00,
        0x01,
        0x0d,
        0x00,
        0x00,
        0xc0,
        0xca,
        0xae,
        0x65,
        0x79,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0xb7,
        0x94,
        0x64,
        0x75,
    };

    own_buffer[35] = 0x12;
    own_buffer[36] = 0x12;
    own_buffer[37] = 0x12;
    own_buffer[38] = 0x12;
    own_buffer[39] = 0x12;
    own_buffer[40] = 0x12;
    own_buffer[41] = 0x12;
    own_buffer[42] = 0x12;
    own_buffer[43] = 0x12;

    struct io_state io_state1 = state->io_state;

    wlan_send_test(&state->io_state, own_buffer, 78);
}

void nan_send_beacon_test(struct daemon_state *state, enum nan_beacon_type type, uint64_t now_usec)
{
    struct buf *buf = buf_new_owned(BUF_MAX_LENGTH);

    if (buf_error(buf) < 0)
    {
        printf("Could not build beacon frame");
        return;
    }

    int length = buf_position(buf);

    int err = wlan_send_test(&state->io_state, buf_data(buf), length);
    if (err < 0)
    {   
        printf("Could not send frame\n");
    }
}

int wlan_send_test(const struct io_state *state, const uint8_t *buffer, int length)
{
    if (!state || !state->wlan_handle)
        return -EINVAL;

    int result = pcap_inject(state->wlan_handle, buffer, length);

    if (result < 0)
    {
        printf("unable to inject packet\n");
    }
    else
    {
        printf("injected packet\n");
    }

    return result;
}

uint64_t clock_time_usec()
{
    int result;
    struct timespec now;
    uint64_t now_us = 0;

    result = clock_gettime(CLOCK_MONOTONIC, &now);
    if (!result)
    {
        now_us = now.tv_sec * 1000000;
        now_us += now.tv_nsec / 1000;
    }
    return now_us;
}

const uint8_t *buf_data(struct buf *buf)
{
    return buf->data + buf->start;
}

size_t buf_position(struct buf *buf)
{
    return abs(buf->data - buf->current);
}

int buf_error(struct buf *buf)
{
    return buf->error;
}

struct buf *buf_new_owned(size_t size)
{
    struct buf *buf = (struct buf *)malloc(sizeof(struct buf));
    buf->data = (const uint8_t *)malloc(size);
    buf->current = &(*(uint8_t *)buf->data);
    buf->size = size;
    buf->start = 0;
    buf->end = size;
    buf->owned = true;
    buf->error = 0;
    return buf;
}

void ieee80211_init_state(struct ieee80211_state *state)
{
    state->sequence_number = 0;
    state->fcs = true;
}

void nan_service_state_init(struct nan_service_state *state)
{
    state->published_services = list_init();
    state->subscribed_services = list_init();
    state->last_instance_id = 0;
}

struct list_entry
{
    any_t data;
    struct list_entry *next;
};

struct list_entry *list_entry_new(any_t item)
{
    struct list_entry *entry = malloc(sizeof(struct list_entry));
    entry->data = item;
    entry->next = NULL;
    return entry;
};

list_t list_init()
{
    return (list_t)list_entry_new(NULL);
};

void nan_event_state_init(struct nan_event_state *state)
{
    state->listeners = list_init();
}

void nan_timer_state_init(struct nan_timer_state *state, const uint64_t now_usec)
{
    state->now_usec = now_usec;
    // state->base_time_usec = now_usec;
    state->base_time_usec = 1898184703;
    state->last_discovery_beacon_usec = 0;
    state->warmup_done = false;
    state->initial_scan_done = true;

    moving_average_init(state->average_error_state, state->average_error, int, 32);
}

void nan_peer_state_init(struct nan_peer_state *state)
{
    state->peers = list_init();
    state->timeout_usec = PEER_DEFAULT_TIMEOUT_USEC;
    state->clean_interval_usec = PEER_DEFAULT_CLEAN_INTERVAL_USEC;

    state->peer_add_callback = NULL;
    state->peer_add_callback_data = NULL;
    state->peer_remove_callback = NULL;
    state->peer_remove_callback_data = NULL;
}

struct circular_buf
{
	void **buffer;
	size_t head;
	size_t tail;
	size_t capacity;
	bool full;
};

circular_buf_t circular_buf_init(size_t size)
{
	circular_buf_t cbuf = malloc(sizeof(struct circular_buf));

	cbuf->buffer = malloc(size * sizeof(any_t));
	cbuf->capacity = size;
	circular_buf_reset(cbuf);

	return cbuf;
}

void circular_buf_reset(circular_buf_t cbuf)
{
	cbuf->head = 0;
	cbuf->tail = 0;
	cbuf->full = 0;
}

/*
gcc test.c -o test -lpcap -lev -I/usr/include/libnl3 $(pkg-config --cflags --libs libnl-3.0 libnl-genl-3.0 libnl-route-3.0)

*/

// sudo ./test
