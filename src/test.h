#include <stdint.h>
#include <pcap/pcap.h>
#include <ev.h>
#include <stdbool.h>
#include <net/if.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stddef.h>

#include "attributes.h"
#include "peer.h"
#include "timer.h"
#include "cluster.h"
#include "ieee80211.h"
#include "channel.h"
#include "event.h"
#include "service.h"
#include "circular_buffer.h"
#include "sync.h"
#include "state.h"

#ifdef __APPLE__
#include <net/ethernet.h>
#else
#include <netinet/ether.h>
#endif

#define HOST_NAME_LENGTH_MAX 64
#define BUF_MAX_LENGTH 65535
#define USEC_TO_TU(usec) (usec) / 1024
#define TU_TO_USEC(tu) (tu) * 1024
// #define PEER_DEFAULT_TIMEOUT_USEC TU_TO_USEC(512) * 10
// #define PEER_DEFAULT_CLEAN_INTERVAL_USEC TU_TO_USEC(512) * 2

/**
 * Opaque buffer structure and type
 */
typedef struct circular_buf *circular_buf_t;

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

struct io_state
{
    pcap_t *wlan_handle; 
    char wlan_ifname[IFNAMSIZ]; /* name of WLAN iface */
    int wlan_ifindex;           /* index of WLAN iface */
    int wlan_fd;
    struct ether_addr if_ether_addr; /* MAC address of WLAN and host iface */
    char host_ifname[IFNAMSIZ];      /* name of host iface */
    int host_ifindex;                /* index of host iface */
    int host_fd;
    char *dumpfile;
    bool no_monitor;
    bool no_channel;
    bool no_updown;
};

struct ev_state
{
    struct ev_loop *loop; //
    ev_timer send_discovery_beacon;
    ev_timer discovery_window;
    ev_timer discovery_window_end;
    ev_timer clean_peers;
    ev_io read_stdin;
    ev_io read_wlan;
    ev_io read_host;
};

struct daemon_state
{
    struct nan_state nan_state; //
    struct io_state io_state; // covered
    struct ev_state ev_state; // covered

    uint64_t start_time_usec;

    const char *dump;
    char *last_cmd;
};

enum nan_beacon_type
{
    NAN_SYNC_BEACON,
    NAN_DISCOVERY_BEACON
};

struct buf
{
    const uint8_t *data;
    uint8_t *current;
    int start;
    int end;
    size_t size;
    bool owned;
    int error;
};

int nan_init_test(struct daemon_state *state, const char *wlan, const char *host, int channel, const char *dump);

void nan_schedule_test(struct ev_loop *loop, struct daemon_state *state);

int io_state_init_test(struct io_state *state, const char *wlan, const char *host, const int channel,
                  const struct ether_addr *bssid_filter);

int io_state_init_wlan_test(struct io_state *state, const char *wlan, const int channel,
                       const struct ether_addr *bssid_filter);

int wlan_send_test(const struct io_state *state, const uint8_t *buffer, int length);

static int open_nonblocking_device_test(const char *dev, pcap_t **pcap_handle, const struct ether_addr *bssid_filter);

void nan_send_beacon_test(struct daemon_state *state, enum nan_beacon_type type, uint64_t now_usec);

uint64_t clock_time_usec();

const uint8_t *buf_data(struct buf *buf);

size_t buf_position(struct buf *buf);

int buf_error(struct buf *buf);

struct buf *buf_new_owned(size_t size);

void ieee80211_init_state(struct ieee80211_state *state);

void nan_service_state_init(struct nan_service_state *state);

list_t list_init();

void nan_event_state_init(struct nan_event_state *state);

void nan_timer_state_init(struct nan_timer_state *state, const uint64_t now_usec);

void nan_peer_state_init(struct nan_peer_state *state);

void nan_sync_state_init(struct nan_sync_state *state,
                         const struct ether_addr *interface_address);

circular_buf_t circular_buf_init(size_t size);

void circular_buf_reset(circular_buf_t cbuf);
