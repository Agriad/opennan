#include <stdint.h>
#include <pcap/pcap.h>
#include <ev.h>
#include <stdbool.h>
#include <net/if.h>

#ifdef __APPLE__
#include <net/ethernet.h>
#else
#include <netinet/ether.h>
#endif

#define HOST_NAME_LENGTH_MAX 64

// struct nan_state
// {
//     // The hostname of the device
//     char hostname[HOST_NAME_LENGTH_MAX + 1];
//     // The ethernet address of the device
//     struct ether_addr self_address;
//     // The current ethernet address of the interface
//     struct ether_addr interface_address;
//     // Buffer for outgoing frames
//     circular_buf_t buffer;

//     // Information about used channels
//     struct nan_channel_state channel;
//     // Currently known peers
//     struct nan_peer_state peers;
//     // Timer used for clock syncronization
//     struct nan_timer_state timer;
//     // Information about the current cluster
//     struct nan_cluster_state cluster;
//     // Information about the current anchor master election
//     struct nan_sync_state sync;
//     // Attached event listeners
//     struct nan_event_state events;
//     // Service engine state
//     struct nan_service_state services;
//     // Needed information for IEEE 802.11 frames
//     struct ieee80211_state ieee80211;
// };

// struct io_state
// {
//     pcap_t *wlan_handle; 
//     char wlan_ifname[IFNAMSIZ]; /* name of WLAN iface */
//     int wlan_ifindex;           /* index of WLAN iface */
//     int wlan_fd;
//     struct ether_addr if_ether_addr; /* MAC address of WLAN and host iface */
//     char host_ifname[IFNAMSIZ];      /* name of host iface */
//     int host_ifindex;                /* index of host iface */
//     int host_fd;
//     char *dumpfile;
//     bool no_monitor;
//     bool no_channel;
//     bool no_updown;
// };

// struct ev_state
// {
//     struct ev_loop *loop; //
//     ev_timer send_discovery_beacon;
//     ev_timer discovery_window;
//     ev_timer discovery_window_end;
//     ev_timer clean_peers;
//     ev_io read_stdin;
//     ev_io read_wlan;
//     ev_io read_host;
// };

// struct daemon_state
// {
//     struct nan_state nan_state; //
//     struct io_state io_state; // covered
//     struct ev_state ev_state; // covered

//     uint64_t start_time_usec;

//     const char *dump;
//     char *last_cmd;
// };
