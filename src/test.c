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

// static int open_nonblocking_device(const char *dev, pcap_t **pcap_handle, const struct ether_addr *bssid_filter)
// {
//     printf("open nonblocking device 1");
//     char errbuf[PCAP_ERRBUF_SIZE];
//     pcap_t *handle = pcap_create(dev, errbuf);
//     if (handle == NULL)
//     {
//         printf("pcap: unable to open device %s (%s)\n", dev, errbuf);
//         return -1;
//     }

//     pcap_set_snaplen(handle, 65535);
//     pcap_set_promisc(handle, 1);
//     pcap_set_timeout(handle, 1);
//     #ifdef __APPLE__
//     /* On Linux, we activate monitor mode via nl80211 */
//     pcap_set_rfmon(handle, 1);
//     #endif /* __APPLE__ */

//     if (pcap_activate(handle) < 0)
//     {
//         printf("pcap: unable to activate device %s (%s)\n", dev, pcap_geterr(handle));
//         pcap_close(handle);
//         return -1;
//     }

//     if (pcap_setnonblock(handle, 1, errbuf) < 0)
//     {
//         printf("pcap: cannot set to non-blocking mode (%s)\n", errbuf);
//         pcap_close(handle);
//         return -1;
//     }

//     /* FIXME direction does not seem to have an effect (we get our own frames every time we poll) */
//     if (pcap_setdirection(handle, PCAP_D_IN) < 0)
//     {
//         printf("pcap: unable to monitor only incoming traffic on device %s (%s)\n", dev, pcap_geterr(handle));
//     }

//     if (pcap_datalink(handle) != DLT_IEEE802_11_RADIO)
//     {
//         printf("pcap: device %s does not support radiotap headers\n", dev);
//         pcap_close(handle);
//         return -1;
//     }

//     if (bssid_filter)
//     {
//         struct bpf_program filter;
//         char filter_str[128];
//         snprintf(filter_str, sizeof(filter_str), "wlan addr3 %s", ether_ntoa(bssid_filter));
//         if (pcap_compile(handle, &filter, filter_str, 1, PCAP_NETMASK_UNKNOWN) < 0)
//         {
//             printf("pcap: could not create filter (%s)\n", pcap_geterr(handle));
//             return -1;
//         }

//         if (pcap_setfilter(handle, &filter) < 0)
//         {
//             printf("pcap: could not set filter (%s)\n", pcap_geterr(handle));
//             return -1;
//         }
//     }

//     int fd = pcap_get_selectable_fd(handle);
//     if (fd < 0)
//     {
//         printf("pcap: unable to get fd\n");
//         return -1;
//     }

//     *pcap_handle = handle;
//     return fd;
// }

// int main() {
//     // int length = 77;
//     // uint8_t own_buffer[length];

//     uint8_t own_buffer[] = {
//         0x00, 
//         0x00,
//         0x0b,
//         0x00,
//         0x26,
//         0x00,
//         0x00,
//         0x00,
//         0x10,
//         0x02,
//         0xc8,
//         0x80,
//         0x00,
//         0x00,
//         0x00,
//         0xff,
//         0xff,
//         0xff,
//         0xff,
//         0xff,
//         0xff,
//         0x00,
//         0xc0,
//         0xca,
//         0xae,
//         0x65,
//         0x79,
//         0x50,
//         0x6f,
//         0x9a,
//         0x01,
//         0x78,
//         0x1d,
//         0x00,
//         0x01,
//         0xff,
//         0xff,
//         0x23,
//         0x71,
//         0x00,
//         0x00,
//         0x00,
//         0x00,
//         0x00,
//         0x02,
//         0x20,
//         0x04,
//         0xff,
//         0x19,
//         0x50,
//         0x6f,
//         0x9a,
//         0x13,
//         0x00,
//         0x02,
//         0x00,
//         0x00,
//         0x00,
//         0x01,
//         0x0d,
//         0x00,
//         0x00,
//         0xc0,
//         0xca,
//         0xae,
//         0x65,
//         0x79,
//         0x00,
//         0x00,
//         0x00,
//         0x00,
//         0x00,
//         0x00,
//         0x00,
//         0xb7,
//         0x94,
//         0x64,
//         0x75,
//     };

//     pcap_t *wlan_handle;
//     // char wlan_ifname[IFNAMSIZ];
//     // char hardcoded_name[] = "wlx00c0caae6547";

//     // for (int i = 0; i < strlen("wlx00c0caae6547"); i++)
//     // {
//     //     wlan_ifname[i] = hardcoded_name[i];
//     // }
//     // wlan_ifname[] = "wlx00c0caae6547";

//     // strcpy(wlan, argv[optind]);

//     // &state = address
//     char wlan = "wlx00c0caae6547";
//     char host = "nan1";
//     int channel = 6;
//     // dump file = null

//     // &sate -> io_state 
//     // char wlan = "wlx00c0caae6547";
//     // char host = "nan1";
//     // int channel = 6;
//     // bssid filter = null

//     // state = ???
//     // char wlan = "wlx00c0caae6547";
//     // int channel = 6;
//     // bssid filter = null

//     // strcpy(state->wlan_ifname, wlan);

//     char wlan_ifname[] = "wlx00c0caae6547";
//     // wlan = null
//     // bssid filter = null

//     // open_nonblocking_device(wlan_ifname, wlan_handle, bssid_filter);
//     printf("here-1\n");
//     // open_nonblocking_device(wlan_ifname, wlan_handle, NULL);
//     open_nonblocking_device(wlan_ifname, NULL, NULL);
//     printf("here0\n");

//     // for(int i = 0; i < length; i++) {
//     //     own_buffer[i] = 0xff;
//     // }

//     printf("here1\n");
//     // int result = pcap_inject(wlan_handle, own_buffer, length);
//     int result = pcap_inject(wlan_handle, own_buffer, sizeof(own_buffer) / sizeof(own_buffer[0]));
//     printf("here2\n");


//     // while(1) {
//     //     int result = pcap_inject(wlan_handle, own_buffer, length);

//     //     if (result < 0)
//     //         printf("unable to inject packet (%s)", pcap_geterr(wlan_handle));
//     //     else
//     //         printf("injected %d bytes", result);
//     //     sleep(0.5);
//     // }
// }

// int main() {
//     uint8_t own_buffer[] = {
//         0x00, 
//         0x00,
//         0x0b,
//         0x00,
//         0x26,
//         0x00,
//         0x00,
//         0x00,
//         0x10,
//         0x02,
//         0xc8,
//         0x80,
//         0x00,
//         0x00,
//         0x00,
//         0xff,
//         0xff,
//         0xff,
//         0xff,
//         0xff,
//         0xff,
//         0x00,
//         0xc0,
//         0xca,
//         0xae,
//         0x65,
//         0x79,
//         0x50,
//         0x6f,
//         0x9a,
//         0x01,
//         0x78,
//         0x1d,
//         0x00,
//         0x01,
//         0xff,
//         0xff,
//         0x23,
//         0x71,
//         0x00,
//         0x00,
//         0x00,
//         0x00,
//         0x00,
//         0x02,
//         0x20,
//         0x04,
//         0xff,
//         0x19,
//         0x50,
//         0x6f,
//         0x9a,
//         0x13,
//         0x00,
//         0x02,
//         0x00,
//         0x00,
//         0x00,
//         0x01,
//         0x0d,
//         0x00,
//         0x00,
//         0xc0,
//         0xca,
//         0xae,
//         0x65,
//         0x79,
//         0x00,
//         0x00,
//         0x00,
//         0x00,
//         0x00,
//         0x00,
//         0x00,
//         0xb7,
//         0x94,
//         0x64,
//         0x75,
//     };

//     // pcap_t *wlan_handle;

//     // main()

//     // strcpy(wlan, argv[optind]);

//     // int argc;
//     // char *argv[];

//     // char wlan[IFNAMSIZ] = "";
// 	// char host[IFNAMSIZ] = DEFAULT_NAN_DEVICE;
// 	// int channel = 6;
//     // struct daemon_state state;

//     char wlan[IFNAMSIZ] = "wlx00c0caae6547";
// 	char host[IFNAMSIZ] = "nan0";
// 	int channel = 6;
//     struct daemon_state state;
//     // dump = null;

//     // nan_init(&state, wlan, host, channel, dump ? dump_file : 0)

//     // nan_init()

//     // struct daemon_state *state;
//     // const char *wlan;
//     // const char *host;
//     // int channel;
//     // const char *dump;

//     // err = io_state_init(&state->io_state, wlan, host, channel, NULL)

//     // io_state_init()

//     // struct io_state *state;
//     // const char *wlan;
//     // const char *host;
//     // const int channel;
//     // const struct ether_addr *bssid_filter;

//     struct io_state *state_io_state_init = &state.io_state;
//     const struct ether_addr *bssid_filter = NULL;

//     // io_state_init_wlan(state, wlan, channel, bssid_filter)

//     // io_state_init_wlan()

//     // char wlan_ifname[] = "wlx00c0caae6547";
//     // wlan = null
//     // bssid filter = null

//     // struct io_state *state;
//     // const char *wlan;
//     // const int channel;
//     // const struct ether_addr *bssid_filter;

//     // strcpy(state->wlan_ifname, wlan);
//     // state->wlan_ifindex = if_nametoindex(state->wlan_ifname);

//     strcpy(state_io_state_init->wlan_ifname, wlan);
//     state_io_state_init->wlan_ifindex = if_nametoindex(state_io_state_init->wlan_ifname);

//     // open_nonblocking_device(wlan_ifname, NULL, NULL);

//     // open_nonblocking_device()

//     // char errbuf[PCAP_ERRBUF_SIZE];
//     // pcap_t *handle = pcap_create(dev, errbuf);
//     // pcap_t **pcap_handle;

//     char errbuf[PCAP_ERRBUF_SIZE];
//     printf("here-1\n");
//     // pcap_t *handle = pcap_create(state_io_state_init->wlan_ifname, errbuf);
//     pcap_t *handle = pcap_create("wlx00c0caae6547", errbuf);
//     pcap_t **pcap_handle;
//     *pcap_handle = handle;

//     // main()

//     // struct ev_loop *loop = EV_DEFAULT;
//     // nan_schedule(loop, &state);

//     // nan_schedule(struct ev_loop *loop, struct daemon_state *state)

//     // nan_handle_discovery_window(struct ev_loop *loop, ev_timer *timer, int revents)

//     // nan_send_beacon(struct daemon_state *state, enum nan_beacon_type type, uint64_t now_usec)

//     printf("here0\n");

//     // wlan_send(const struct io_state *state, const uint8_t *buffer, int length)



//     printf("here1\n");
//     // int result = pcap_inject(state->wlan_handle, buffer, length);

//     int result = pcap_inject(state_io_state_init->wlan_handle, own_buffer, sizeof(own_buffer) / sizeof(own_buffer[0]));
//     printf("here2\n");

// }

int main(int argc, char *argv[])
{
	// log_set_level(LOG_INFO);

	bool dump = false;
	// char *dump_file = FAILED_DUMP;

	char wlan[IFNAMSIZ] = "";
    // char wlan[IFNAMSIZ] = "wlx00c0caae6579";
	// char host[IFNAMSIZ] = DEFAULT_NAN_DEVICE;
    char host[IFNAMSIZ] = "nan0";
	int channel = 6;

	struct daemon_state state;
	state.start_time_usec = clock_time_usec();

	// int c;
	// while ((c = getopt(argc, argv, "vd::n:c:hMCU")) != -1)
	// {
	// 	switch (c)
	// 	{
	// 	case 'h':
	// 		print_usage(argv[0]);
	// 		return 0;
	// 	case 'v':
	// 		log_increase_level();
	// 		break;
	// 	case 'd':
	// 		dump = true;
	// 		if (optarg)
	// 			strcpy(dump_file, optarg);
	// 		break;
	// 	case 'n':
	// 		strcpy(host, optarg);
	// 		break;
	// 	case 'c':
	// 		channel = atoi(optarg);
	// 		break;
	// 	case 'M':
	// 		state.io_state.no_monitor = true;
	// 		break;
	// 	case 'C':
	// 		state.io_state.no_channel = true;
	// 		break;
	// 	case 'U':
	// 		state.io_state.no_updown = true;
	// 		break;
	// 	case '?':
	// 		switch (optopt)
	// 		{
	// 		case 'n':
	// 		case 'c':
	// 		case 's':
	// 		case 'p':
	// 			log_error("Option -%c requires an argument.", optopt);
	// 			break;
	// 		default:
	// 			log_error("Unknown option `-%c'.", optopt);
	// 		}
	// 		return EXIT_FAILURE;
	// 	default:
	// 		abort();
	// 	}
	// }

	if (argc - optind != 1)
	{
		// log_error("Incorrect number of arguments: %d", argc - optind);
        printf("Incorrect number of arguments: %d\n", argc - optind);
		// print_usage(argv[0]);
		return EXIT_FAILURE;
	}
	strcpy(wlan, argv[optind]);

	// switch (channel)
	// {
	// case 6:
	// case 44:
	// case 149:
	// 	break;
	// default:
	// 	log_error("Unsupported channel %d (use 6, 44, or 149)", channel);
	// 	return EXIT_FAILURE;
	// }

	// log_debug("main: &state - %x", &state);
	// log_debug("main: wlan - %s", wlan);
	// log_debug("main: host - %s", host);
	// log_debug("main: channel - %i", channel);
	// log_debug("main: dump_file - %s", dump ? dump_file : 0);

	// if (nan_init_test(&state, wlan, host, channel, dump ? dump_file : 0) < 0)
    printf("here0\n");

    if (nan_init_test(&state, wlan, host, channel, NULL) < 0)
	{
		// log_error("could not initialize core");
        printf("could not initialize core\n");
		return EXIT_FAILURE;
	}
    printf("here1\n");

	// printf("88b 88    db    88b 88\n"
	// 	   "88Yb88   dPYb   88Yb88\n"
	// 	   "88 Y88  dP__Yb  88 Y88\n"
	// 	   "88  Y8 dP''''Yb 88  Y8\n");

	// if (state.io_state.wlan_ifindex)
	// 	log_info("WLAN device: %s (addr %s)", state.io_state.wlan_ifname, ether_addr_to_string(&state.io_state.if_ether_addr));
	// if (state.io_state.host_ifindex)
	// 	log_info("Host device: %s", state.io_state.host_ifname);
	// log_info("Initial Cluster ID: %s", ether_addr_to_string(&state.nan_state.cluster.cluster_id));

	struct ev_loop *loop = EV_DEFAULT;
    printf("here2\n");
	nan_schedule_test(loop, &state);
    printf("here3\n");
	// ev_run(loop, 0);

	// nan_free(&state);

	return EXIT_SUCCESS;
}

void init_nan_state_test(struct nan_state *state, const char *hostname,
                    struct ether_addr *addr, int channel, uint64_t now_usec)
{
    strncpy(state->hostname, hostname, HOST_NAME_LENGTH_MAX);
    state->self_address = *addr;
    state->interface_address = *addr;

    state->buffer = circular_buf_init(16);

    // nan_channel_state_init(&state->channel, channel);
    // nan_cluster_state_init(&state->cluster);
    // nan_sync_state_init(&state->sync, addr);
    // nan_peer_state_init(&state->peers);
    // // nan_timer_state_init(&state->timer, now_usec);
    // nan_timer_state_init(&state->timer, 1898184703);
    // nan_event_state_init(&state->events);
    // nan_service_state_init(&state->services);
    // ieee80211_init_state(&state->ieee80211);
}

int nan_init_test(struct daemon_state *state, const char *wlan, const char *host, int channel, const char *dump)
{
    int err;
    char hostname[HOST_NAME_LENGTH_MAX + 1];

    // srand(clock_time_usec());

    if ((err = netutils_init_test()))
        return err;

    if ((err = io_state_init_test(&state->io_state, wlan, host, channel, NULL)))
        return err;

    // if (gethostname(hostname, sizeof(hostname)))
    //     return -errno;

    // init_nan_state_test(&state->nan_state, hostname, &state->io_state.if_ether_addr,
    //                channel, clock_time_usec());

    // nan_peer_set_callbacks(&state->nan_state.peers,
    //                        nan_neighbor_add, &state->io_state,
    //                        nan_neighbor_remove, &state->io_state);

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
		// log_error("Failed to allocate netlink socket.");
        printf("Failed to allocate netlink socket.\n");
		return -ENOMEM;
	}

	nl_socket_set_buffer_size(state->socket, 8192, 8192);

	if (genl_connect(state->socket))
	{
		// log_error("Failed to connect to generic netlink.");
        printf("Failed to connect to generic netlink.\n");
		nl_socket_free(state->socket);
		return -ENOLINK;
	}

	state->nl80211_id = genl_ctrl_resolve(state->socket, "nl80211");
	if (state->nl80211_id < 0)
	{
		// log_error("nl80211 not found.");
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
		// log_error("Failed to allocate netlink socket.");
        printf("Failed to allocate netlink socket.\n");
		return -ENOMEM;
	}

	if (nl_connect(state->socket, NETLINK_ROUTE))
	{
		// log_error("Failed to connect to generic netlink.");
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
            // log_error("Could not open device: %s", state->host_ifname);
            printf("Could not open device: %s\n", state->host_ifname);
            return err;
        }
        state->host_ifindex = if_nametoindex(state->host_ifname);
        if (!state->host_ifindex)
        {
            // log_error("No such interface exists %s", state->host_ifname);
            printf("No such interface exists %s\n", state->host_ifname);
            return -ENOENT;
        }
    }
    else
    {
        // log_debug("No host device given, start without host device");
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
        // log_error("tun: unable to open tun device %d", fd);
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
        // log_error("tun: unable to set HW address");
        printf("tun: unable to set HW address\n");
        close(fd);
        return err;
    }

    // Get current flags and set them
    ioctl(s, SIOCGIFFLAGS, &ifr);
    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
    if ((err = ioctl(s, SIOCSIFFLAGS, &ifr)) < 0)
    {
        // log_error("tun: unable to set up");
        printf("tun: unable to set up\n");
        close(fd);
        return err;
    }

    /* Set reduced MTU */
    ifr.ifr_mtu = 1450; /* TODO arbitary limit to fit all headers */
    if ((err = ioctl(s, SIOCSIFMTU, (void *)&ifr)) < 0)
    {
        // log_error("tun: unable to set MTU");
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

    // state->wlan_ifindex = if_nametoindex(state->wlan_ifname);
    // if (!state->wlan_ifindex)
    // {
    //     log_error("No such interface exists %s", state->wlan_ifname);
    //     return -ENOENT;
    // }

    // if (!state->no_updown)
    // {
    //     if (link_down(state->wlan_ifindex) < 0)
    //     {
    //         log_error("Could set link down: %s", state->wlan_ifname);
    //         return -1;
    //     }
    // }

    // if (!state->no_monitor)
    // {
    //     if (set_monitor_mode(state->wlan_ifindex) < 0)
    //     {
    //         log_error("Could not put device in monitor mode: %s", state->wlan_ifname);
    //         return -1;
    //     }
    // }

    // if (!state->no_updown)
    // {
    //     if (link_up(state->wlan_ifindex) < 0)
    //     {
    //         log_error("Could set link up: %", state->wlan_ifname);
    //         return -1;
    //     }
    // }

    // if (!state->no_channel)
    // {
    //     if (set_channel(state->wlan_ifindex, channel))
    //     {
    //         log_error("Could not set channel of %s", state->wlan_ifname);
    //         return -1;
    //     }
    // }

    state->wlan_fd = open_nonblocking_device_test(state->wlan_ifname, &state->wlan_handle, bssid_filter);
    // if (state->wlan_fd < 0)
    // {
    //     log_error("Could not open device %s: %d", state->wlan_ifname, state->wlan_fd);
    //     return -1;
    // }

    if (link_ether_addr_get_test(state->wlan_ifname, &state->if_ether_addr) < 0)
    {
        // log_error("Could not get LLC address from %s", state->wlan_ifname);
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
        // log_error("pcap: unable to open device %s (%s)", dev, errbuf);
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
        // log_error("pcap: unable to activate device %s (%s)", dev, pcap_geterr(handle));
        printf("pcap: unable to activate device\n");
        pcap_close(handle);
        return -1;
    }

    if (pcap_setnonblock(handle, 1, errbuf) < 0)
    {
        // log_error("pcap: cannot set to non-blocking mode (%s)", errbuf);
        printf("pcap: cannot set to non-blocking mode\n");
        pcap_close(handle);
        return -1;
    }

    /* FIXME direction does not seem to have an effect (we get our own frames every time we poll) */
    if (pcap_setdirection(handle, PCAP_D_IN) < 0)
    {
        // log_warn("pcap: unable to monitor only incoming traffic on device %s (%s)", dev, pcap_geterr(handle));
        printf("pcap: unable to monitor only incoming traffic on device\n");
    }

    if (pcap_datalink(handle) != DLT_IEEE802_11_RADIO)
    {
        // log_error("pcap: device %s does not support radiotap headers", dev);
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
            // log_error("pcap: could not create filter (%s)", pcap_geterr(handle));
            printf("pcap: could not create filter (%s)\n", pcap_geterr(handle));
            return -1;
        }

        if (pcap_setfilter(handle, &filter) < 0)
        {
            // log_error("pcap: could not set filter (%s)", pcap_geterr(handle));
            printf("pcap: could not set filter (%s)\n", pcap_geterr(handle));
            return -1;
        }
    }

    int fd = pcap_get_selectable_fd(handle);
    if (fd < 0)
    {
        // log_error("pcap: unable to get fd");
        printf("pcap: unable to get fd\n");
        return -1;
    }

    *pcap_handle = handle;
    return fd;
}

void nan_handle_discovery_window_test(struct ev_loop *loop, ev_timer *timer, int revents)
{
    (void)revents;
    struct daemon_state *state = timer->data;
    uint64_t now_usec = clock_time_usec();

    // if (!nan_timer_in_dw(&state->nan_state.timer, now_usec) ||
    //     !nan_timer_initial_scan_done(&state->nan_state.timer, now_usec))
    // {
    //     uint64_t next_dw_usec = nan_timer_next_dw_usec(&state->nan_state.timer, now_usec);
    //     log_trace("not in dw, next: %lu (%lu tu)", next_dw_usec, USEC_TO_TU(next_dw_usec));
    //     ev_timer_rearm(loop, timer, (double)USEC_TO_SEC(next_dw_usec));
    //     return;
    // }

    // log_trace("In discovery window at %lu", nan_timer_get_synced_time_usec(&state->nan_state.timer, now_usec));

    nan_send_beacon_test(state, NAN_SYNC_BEACON, now_usec);
    // nan_send_buffered_frames(state);
    // nan_send_service_discovery_frame(state);

    // now_usec = clock_time_usec();
    // uint64_t dw_end_usec = nan_timer_dw_end_usec(&state->nan_state.timer, now_usec);
    // ev_timer_rearm_usec(loop, &state->ev_state.discovery_window_end, dw_end_usec);

    // uint64_t next_dw_usec = nan_timer_next_dw_usec(&state->nan_state.timer, now_usec);
    // ev_timer_rearm_usec(loop, timer, next_dw_usec);
}

void nan_schedule_test(struct ev_loop *loop, struct daemon_state *state)
{
    state->ev_state.loop = loop;

    // /* Timer for discovery beacon */
    // state->ev_state.send_discovery_beacon.data = (void *)state;
    // ev_timer_init(&state->ev_state.send_discovery_beacon, nan_send_discovery_beacon, 0, 0);
    // ev_timer_start(loop, &state->ev_state.send_discovery_beacon);

    /* Timer for dicovery window */
    state->ev_state.discovery_window.data = (void *)state;
    ev_timer_init(&state->ev_state.discovery_window, nan_handle_discovery_window_test, 0, 0);
    // ev_timer_start(loop, &state->ev_state.discovery_window);

    // /* Timer for dicovery window end, started by discovery window timer */
    // state->ev_state.discovery_window_end.data = (void *)state;
    // ev_timer_init(&state->ev_state.discovery_window_end, nan_handle_discovery_window_end, 0, 0);

    // /* Timer to clean outdated peers */
    // state->ev_state.clean_peers.data = (void *)state;
    // ev_timer_init(&state->ev_state.clean_peers, nan_clean_peers,
    //               0, (double)USEC_TO_SEC(state->nan_state.peers.clean_interval_usec));
    // ev_timer_start(loop, &state->ev_state.clean_peers);

    // /* Trigger frame reception from WLAN device */
    // state->ev_state.read_wlan.data = (void *)state;
    // ev_io_init(&state->ev_state.read_wlan, wlan_device_ready, state->io_state.wlan_fd, EV_READ);
    // ev_io_start(loop, &state->ev_state.read_wlan);

    // /* Trigger frame reception from host device */
    // state->ev_state.read_host.data = (void *)state;
    // ev_io_init(&state->ev_state.read_host, host_device_ready, state->io_state.host_fd, EV_READ);
    // ev_io_start(loop, &state->ev_state.read_host);

    // /* Trigger for user input from stdin */
    // state->ev_state.read_stdin.data = (void *)state;
    // ev_io_init(&state->ev_state.read_stdin, stdin_ready, STDIN_FILENO, EV_READ);
    // ev_io_start(loop, &state->ev_state.read_stdin);
}

void nan_send_beacon_test(struct daemon_state *state, enum nan_beacon_type type, uint64_t now_usec)
{
    struct buf *buf = buf_new_owned(BUF_MAX_LENGTH);

    // struct nan_beacon_frame *beacon_header = (struct nan_beacon_frame *)(buf_current(buf));
    // int buf_address = buf_current(buf);

    // nan_build_beacon_frame(buf, &state->nan_state, type, now_usec);

    if (buf_error(buf) < 0)
    {
        // log_error("Could not build beacon frame: %s", nan_beacon_type_to_string(type));
        printf("Could not build beacon frame");
        return;
    }

    int length = buf_position(buf);

    int err = wlan_send_test(&state->io_state, buf_data(buf), length);
    if (err < 0)
    {   
        // log_error("Could not send frame: %d", err);
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
        // log_error("unable to inject packet (%s)", pcap_geterr(state->wlan_handle));
        printf("unable to inject packet\n");
    }
    else
    {
        // log_trace("injected %d bytes", result);
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
