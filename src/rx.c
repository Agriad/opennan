#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <errno.h>
#include <radiotap.h>
#include <radiotap_iter.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

#include "rx.h"
#include "attributes.h"
#include "utils.h"
#include "log.h"
#include "ieee80211.h"
#include "timer.h"
#include "frame.h"
#include "list.h"
#include "tx.h"
#include "sync.h"

const char *nan_rx_result_to_string(const int result)
{
    switch (result)
    {
    case RX_IGNORE_SYNC_OUTSIDE_DW:
        return "ignore sync beacon outside dw";
    case RX_IGNORE_OUI:
        return "ignore oui";
    case RX_IGNORE_PEER:
        return "ignore peer";
    case RX_IGNORE_RSSI:
        return "ignore rssi";
    case RX_IGNORE_FAILED_CRC:
        return "ignore failed crc";
    case RX_IGNORE_NOPROMISC:
        return "ignore nopromisc";
    case RX_IGNORE_FROM_SELF:
        return "ignore from self";
    case RX_IGNORE:
        return "ignore";
    case RX_OK:
        return "ok";
    case RX_UNEXPECTED_FORMAT:
        return "unexpected format";
    case RX_UNEXPECTED_TYPE:
        return "unexpected type";
    case RX_UNEXPECTED_VALUE:
        return "unexpected value";
    case RX_TOO_SHORT:
        return "too short";
    case RX_MISSING_MANDATORY_ATTRIBUTE:
        return "missing mandatory attribute";
    default:
        return "unknown result";
    }
}

/**
 * Parse the data of master indication attribute from a 
 * received beacon and write it to the given peer.
 * 
 * @param buf - The buffer that contains the attribute's data
 * @param peer - The peer that has send the beacon
 * @returns - 0 on success, a negative value otherwise
 */
int nan_parse_master_indication_attribute(struct buf *buf, struct nan_peer *peer)
{
    uint8_t master_preference;
    uint8_t random_factor;
    read_u8(buf, &master_preference);
    read_u8(buf, &random_factor);

    // uint8_t time_stamp_backup;
    // uint8_t hmac;
    // read_le16(buf, &time_stamp_backup);
    // read_le16(buf, &hmac);

    // log_debug("nan parse master indication attribute: time stamp backup - %x", time_stamp_backup);
    // log_debug("nan parse master indication attribute: hmac - %x", hmac);

    if (buf_error(buf))
        return RX_TOO_SHORT;

    nan_peer_set_master_indication(peer, master_preference, random_factor);

    return RX_OK;
}

/**
 * Parse the data of cluster attribute from a 
 * received beacon and write it to the given peer.
 * 
 * @param buf - The buffer that contains the attribute's data
 * @param peer - The peer that has send the beacon
 * @returns - 0 on success, a negative value otherwise
 */
int nan_parse_cluster_attribute(struct buf *buf, struct nan_peer *peer)
{
    uint64_t anchor_master_rank;
    uint32_t ambtt;
    uint8_t hop_count;

    read_le64(buf, &anchor_master_rank);
    read_u8(buf, &hop_count);
    read_le32(buf, &ambtt);

    uint8_t time_stamp_backup;
    uint8_t hmac;
    // read_le16(buf, &time_stamp_backup);
    // read_le16(buf, &hmac);

    // log_debug("nan parse cluster attribute: time stamp backup - %x", time_stamp_backup);
    // log_debug("nan parse cluster attribute: hmac - %x", hmac);

    if (buf_error(buf))
        return RX_TOO_SHORT;

    nan_peer_set_anchor_master_information(peer, anchor_master_rank, ambtt, hop_count);

    return RX_OK;
}

/**
 * Parse the data of service descriptor attribute and add it to the given list.
 * 
 * @param buf - The buffer that contains the attribute's data
 * @param service_descriptors - A list of service descriptors
 * @returns - 0 on success, a negative value otherwise
 */
int nan_parse_sda(struct buf *buf, list_t service_descriptors)
{
    struct nan_service_descriptor_attribute *attribute =
        malloc(sizeof(struct nan_service_descriptor_attribute));

    read_bytes_copy(buf, (uint8_t *)&attribute->service_id, NAN_SERVICE_ID_LENGTH);
    read_u8(buf, &attribute->instance_id);
    read_u8(buf, &attribute->requestor_instance_id);
    read_u8(buf, (uint8_t *)&attribute->control);

    if (attribute->control.binding_bitmap_present)
        buf_advance(buf, 2);

    if (attribute->control.matching_filter_present)
    {
        uint8_t length;
        read_u8(buf, &length);
        buf_advance(buf, length);
    }

    if (attribute->control.service_response_filter_present)
    {
        uint8_t length;
        read_u8(buf, &length);
        buf_advance(buf, length);
    }

    if (attribute->control.service_info_present)
    {
        read_u8(buf, &attribute->service_info_length);
        attribute->service_info = malloc(attribute->service_info_length);
        read_bytes_copy(buf, (uint8_t *)attribute->service_info, attribute->service_info_length);
    }

    if (buf_error(buf))
    {
        free(attribute);
        return RX_TOO_SHORT;
    }

    if (service_descriptors)
        list_add(service_descriptors, (any_t)attribute);

    return RX_OK;
}

/**
 * Parse the data of service descriptor extension attribute and add it to the given list.
 * 
 * @param buf - The buffer that contains the attribute's data
 * @param service_descriptor_extensions - A list of service descriptor extensions
 * @returns - 0 on success, a negative value otherwise
 */
int nan_parse_sdea(struct buf *buf, size_t length, list_t service_descriptor_extensions)
{
    struct nan_service_descriptor_extension_attribute *attribute =
        malloc(sizeof(struct nan_service_descriptor_extension_attribute));

    read_u8(buf, &attribute->instance_id);
    read_le16(buf, (uint16_t *)&attribute->control);

    if (attribute->control.range_limit_present)
        buf_advance(buf, 4);

    if (attribute->control.service_update_indicator_present)
        read_u8(buf, &attribute->service_update_indicator);

    if (buf_position(buf) + 2 < length)
    {
        uint16_t length;
        read_le16(buf, &length);
        read_bytes_copy(buf, (uint8_t *)&attribute->oui, OUI_LEN);
        buf_advance(buf, 1);

        attribute->service_specific_info_length = length - 4;
        read_bytes(buf, (const uint8_t **)&attribute->service_specific_info, attribute->service_specific_info_length);
    }

    if (buf_error(buf))
    {
        free(attribute);
        return RX_TOO_SHORT;
    }

    if (service_descriptor_extensions)
        list_add(service_descriptor_extensions, (any_t)attribute);

    return RX_OK;
}
/*
int nan_handle_availability_attribute(struct nan_state *state, struct buf *buf,
                                      struct nan_peer *peer, size_t length)
{
    unsigned int offset = 0;
    uint8_t sequence_id;
    struct nan_availability_attribute_control *attribute_control;

    read_u8(buf, sequence_id);
    read_le16(buf, (uint16_t *)attribute_control);

    while (offset < length)
    {
        uint16_t entry_length;
        struct nan_availability_entry_control *entry_control;

        read_le16(buf, &entry_length);
        read_le16(buf, (uint16_t *)entry_control);

        if (entry_control->time_bitmap_present == 0)
        {
        }
        else
        {
            struct nan_availability_time_bitmap_control *time_bitmap_control;
            uint8_t time_bitmap_length;

            read_le16(buf, (uint16_t *)time_bitmap_control);
            read_u8(buf, &time_bitmap_length);
        }
    }
}
*/

/**
 * Read the next attribute from the frame
 * 
 * @param frame The frame buffer pointing to the start of a NAN attribute
 * @param attribute_id Pointer that will be set to the parsed attribtue id
 * @param attribute_length Pointer that will be set to the parsed attribtue length
 * @param data Pointer that will be set to start of the attribute's data
 */
int nan_attribute_read_next(struct buf *frame, uint8_t *attribute_id,
                            uint16_t *attribute_length, const uint8_t **data)
{
    read_u8(frame, attribute_id);
    read_le16(frame, attribute_length);
    read_bytes(frame, data, *attribute_length);

    if (buf_error(frame) < 0)
        return RX_TOO_SHORT;

    return 3 + (int)*attribute_length;
};

/**
 * Mactro to iterate through the NAN attribtues of a frame. 
 * Available variables in handle function:
 *  * attribute_id - Parsed attribute id
 *  * attribute_length - Parsed attribute length
 *  * attribute_buf - Buffer of attribute data
 * 
 * @param handle Handle function called for each attribute
 */
#define NAN_ITERATE_ATTRIBUTES(handle)                                  \
    do                                                                  \
    {                                                                   \
        const uint8_t *attribute_data;                                  \
        uint8_t attribute_id;                                           \
        uint16_t attribute_length;                                      \
        int length;                                                     \
        while (0 < (length = nan_attribute_read_next(frame,             \
                                                     &attribute_id,     \
                                                     &attribute_length, \
                                                     &attribute_data))) \
        {                                                               \
            struct buf *attribute_buf =                                 \
                buf_new_const(attribute_data, attribute_length);        \
            handle;                                                     \
            buf_free(attribute_buf);                                    \
            if (result < 0)                                             \
            {                                                           \
                log_warn("Could not parse nan attribute: %s",           \
                         nan_attribute_type_as_string(attribute_id));   \
                break;                                                  \
            }                                                           \
        }                                                               \
        if (result < 0)                                                 \
            break;                                                      \
        if (buf_rest(frame) > 0)                                        \
        {                                                               \
            result = RX_UNEXPECTED_FORMAT;                              \
            break;                                                      \
        }                                                               \
        result = RX_OK;                                                 \
    } while (0);

// gets the timestamp from the secondary data location (4 bytes after original message)
// and combines them with the largest 4 bytes digit of own timer. 
uint64_t fix_timestamp(uint32_t timestamp_backup, uint64_t synced_time_usec)
{
    uint8_t temporary_time_buffer[8] = {0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11};

    uint64_t test64 = 0xffffffffffffffff;
    uint32_t test32 = 0xeeeeeeee;
    uint16_t test16 = 0xdddd;
    uint8_t test8 = 0xcc;

    synced_time_usec = 0xffffffffffffffff;

    log_debug("fix timestamp: synced time usec - %lx", synced_time_usec);

    for (int i = 0; i < 4; i++)
    {
        // temporary_time_buffer[i] = timestamp_backup >> 8 * i;
        temporary_time_buffer[i] = 0x11;
        log_debug("fix timestamp: temporary time buffer - %i %x", i, temporary_time_buffer[i]);
    }

    for (int i = 4; i < 8; i++)
    {
        temporary_time_buffer[i] = synced_time_usec >> 8 * i;
        log_debug("fix timestamp: temporary time buffer - %i %x", i, temporary_time_buffer[i]);
    }

    for (int i = 0; i < 8; i++)
    {
        log_debug("fix timestamp: temporary time buffer - %i %x", i, temporary_time_buffer[i]);
    }

    log_debug("fix timestamp: uint64 t size - %d", sizeof(uint64_t));
    log_debug("fix timestamp: test64 - %lx", test64);
    log_debug("fix timestamp: test32 - %x", test32);
    log_debug("fix timestamp: test16 - %x", test16);
    log_debug("fix timestamp: test8 - %x", test8);

    uint64_t onion = 0x00;

    uint64_t combined_timestamp = 0;

    memcpy(&combined_timestamp, temporary_time_buffer, sizeof(uint64_t));

    // log_debug("fix timestamp: onion - %x", onion);
    log_debug("fix timestamp: timestamp - %lx", combined_timestamp);

    return combined_timestamp;
}

int nan_parse_beacon_header(struct buf *frame, int *beacon_type, uint64_t *timestamp, uint64_t synced_time_usec)
{
    uint16_t beacon_interval;
    uint16_t capability;
    uint8_t element_id;
    uint8_t length;
    struct oui oui;
    uint8_t oui_type;
    uint32_t timestamp_backup;
    // uint64_t hmac;

    // read_le64(frame, timestamp);
    read_le16(frame, &beacon_interval);
    read_le16(frame, &capability);
    read_u8(frame, &element_id);
    read_u8(frame, &length);
    read_bytes_copy(frame, (uint8_t *)&oui, OUI_LEN);
    read_u8(frame, &oui_type);
    read_le32(frame, &timestamp_backup);
    // read_le64(frame, &hmac);

    log_debug("nan parse beacon header: time stamp 1 - %lx", *timestamp);
    log_debug("nan parse beacon header: time stamp backup - %x", timestamp_backup);
    *timestamp = fix_timestamp(timestamp_backup, synced_time_usec);
    log_debug("nan parse beacon header: time stamp 2 - %lx", *timestamp);

    // for (int i = 0; i < 4; i++)
    // {
    //     log_debug("nan parse beacon header: time stamp backup - %i, %x", i, *(&time_stamp_backup + i));
    // }

    log_debug("nan parse beacon header: time stamp backup - %x", timestamp_backup);
    log_debug("nan parse beacon header: time stamp 3 - %lx", *timestamp);
    // log_debug("nan parse beacon header: hmac - %x", hmac);

    if (buf_error(frame))
        return RX_TOO_SHORT;

    if (!oui_equal(oui, NAN_OUI) || oui_type != NAN_OUI_TYPE_BEACON)
        return RX_IGNORE_OUI;

    *beacon_type = nan_get_beacon_type(beacon_interval);
    if (*beacon_type < 0)
    {
        log_warn("Unknown beacon interval %d", beacon_interval);
        return RX_UNEXPECTED_TYPE;
    }

    return RX_OK;
}


// modified for timestamp to be sent in the end of the message and only 4 bytes long
int nan_rx_beacon(struct buf *frame, struct nan_state *state,
                  const struct ether_addr *peer_address, const struct ether_addr *cluster_id,
                  const signed char rssi, const uint64_t now_usec)
{
    uint8_t *buffer = buf_data(frame);
    size_t buffer_size = buf_size(frame);

    // check HMAC
    uint8_t hmac_sent[8];

    for (int i = 0; i < 8; i++)
    {
        hmac_sent[i] = buffer[buffer_size - 8 + i];
    }

    // for (int i = 0; i < buffer_size; i++)
    // {
    //     log_debug("nan rx beacon: all buffer %i, %x", i, buffer[i]);
    // }

    uint8_t *message_buffer[buffer_size - 8 - 24];

    // memcpy(&message_buffer, buffer, buffer_size - 8);

    for (int i = 24; i < buffer_size - 8; i++)
    {
        message_buffer[i - 24] = buffer[i];
        // log_debug("nan rx beacon: message buffer %i, %x", i, buffer[i]);
    }
    
    unsigned char *hmac = HMAC(EVP_sha256(), 
        "example_key", 
        strlen("example_key"), 
        message_buffer, 
        64,
        NULL,
        NULL);

    // for (int i = 0; i < 8; i++)
    // {
    //     log_debug("nan rx beacon: hmac %i, %x", i, hmac[i]);
    // }

    // for (int i = 0; i < 8; i++)
    // {
    //     if (hmac[i] != hmac_sent[i])
    //     {
    //         return 1;
    //     }
    // }

    uint64_t timestamp = 0;
    int beacon_type = 0;
    int result = 0;
    uint32_t timestamp_backup = 0;

    uint8_t other_opennan_ether_addr[6] = {0x00, 0xC0, 0xCA, 0xAE, 0x65, 0x79};

    log_debug("nan rx beacon: here");

    uint64_t synced_time_usec = nan_timer_get_synced_time_usec(&state->timer, now_usec);

    if ((result = nan_parse_beacon_header(frame, &beacon_type, &timestamp, synced_time_usec)) != RX_OK)
    {
        log_debug("nan rx beacon: timestamp - %lx", timestamp);
        return result;
    }

    // if (buffer_size > 94)
    // {
    //     timestamp = fix_timestamp(&buffer, synced_time_usec);
    // }

    log_debug("nan rx beacon: timestamp - %lx", timestamp);
    log_debug("nan rx beacon: timestamp backup - %x", timestamp_backup);

    log_trace("nan_beacon: received %s beacon from cluster %s",
              nan_beacon_type_to_string(beacon_type),
              ether_addr_to_string(cluster_id));

    log_debug("nan_beacon: received %s beacon from cluster %s",
              nan_beacon_type_to_string(beacon_type),
              ether_addr_to_string(cluster_id));

    struct nan_peer *peer = NULL;
    enum peer_status peer_status = nan_peer_add(&state->peers, peer_address, cluster_id, now_usec);
    if (peer_status < 0)
    {
        log_warn("nan_beacon: could not add peer: %s (%d)",
                 ether_addr_to_string(peer_address), peer_status);
        return RX_IGNORE;
    }

    nan_peer_get(&state->peers, peer_address, &peer);
    if (peer == NULL)
    {
        log_warn("nan_beacon: could not get peer: %s (%d)",
                 ether_addr_to_string(peer_address), peer_status);
        return RX_IGNORE;
    }

    log_trace("nan_beacon: received %s beacon from peer %s",
              nan_beacon_type_to_string(beacon_type),
              ether_addr_to_string(peer_address));

    if (!nan_timer_initial_scan_done(&state->timer, now_usec))
        nan_timer_initial_scan_cancel(&state->timer);

    NAN_ITERATE_ATTRIBUTES({
        switch (attribute_id)
        {
        case MASTER_INDICATION_ATTRIBUTE:
            result = nan_parse_master_indication_attribute(attribute_buf, peer);
            log_debug("nan rx beacon: result - %i", result);
            break;
        case CLUSTER_ATTRIBUTE:
            result = nan_parse_cluster_attribute(attribute_buf, peer);
            break;
        default:
            log_trace("Unhandled attribute: %s", nan_attribute_type_as_string(attribute_id));
            result = RX_IGNORE;
        }
    });

    if (result < 0)
        return result;

    if (peer->anchor_master_rank != peer->last_anchor_master_rank)
    {
        log_debug("peer anchor master rank: %lu", peer->anchor_master_rank);
        log_debug("peer last anchor master rank: %lu", peer->last_anchor_master_rank);
        
        if (nan_is_master_rank_issuer(&state->self_address, peer->anchor_master_rank))
        {
            log_debug("Peer %s selected us as anchor master", ether_addr_to_string(&peer->addr));
        }
        else if (nan_is_master_rank_issuer(&peer->addr, peer->anchor_master_rank))
        {
            log_debug("Peer %s selected itself as anchor master", ether_addr_to_string(&peer->addr));
        }
        else
        {
            log_debug("Peer %s selected other peer %s as achor master:",
                      ether_addr_to_string(&peer->addr),
                      ether_addr_to_string(nan_get_address_from_master_rank(&peer->anchor_master_rank)));
        }
    }

    nan_peer_set_beacon_information(peer, rssi, timestamp);
    nan_update_master_preference(&state->sync, peer, now_usec);
    nan_check_master_candidate(&state->sync, peer);

    bool is_new_cluster = !ether_addr_equal(cluster_id, &state->cluster.cluster_id);
    bool in_initial_cluster = list_len(state->peers.peers) == 1 && peer_status == PEER_ADD;
    if (is_new_cluster || in_initial_cluster)
    {
        int result = nan_cluster_compare_grade(state->sync.master_preference, synced_time_usec,
                                               peer->master_preference, timestamp);

        log_debug("nan rx beacon: nan timer get synced time usec output - %d", synced_time_usec);

        if (result > 0)
        {
            state->cluster.cluster_id = *cluster_id;
            nan_timer_sync_time(&state->timer, now_usec, timestamp);
            log_debug("Joined new cluster: %s", ether_addr_to_string(cluster_id));
        }
        else
        {
            log_debug("Found cluster with lower cluster grade: %s", ether_addr_to_string(cluster_id));
            log_trace("Found cluster with lower cluster grade: %s", ether_addr_to_string(cluster_id));
        }
    }
    else if (beacon_type == NAN_SYNC_BEACON)
    {
        log_debug("nan rx beacon: in else if case");

        uint64_t last_anchor_master = state->sync.anchor_master_rank;

        uint64_t synced_time_tu = nan_timer_get_synced_time_tu(&state->timer, now_usec);
        nan_anchor_master_selection(&state->sync, peer, synced_time_tu);

        // Sync time, if new anchor master
        if (state->sync.anchor_master_rank != last_anchor_master)
        {
            nan_timer_sync_time(&state->timer, now_usec, timestamp);
        }
        else if (!nan_is_anchor_master_self(&state->sync))
        {
            nan_timer_sync_error(&state->timer, now_usec, timestamp);
        }
    }

    return RX_OK;
}

int nan_rx_service_discovery(struct buf *frame, struct nan_state *state,
                             const struct ether_addr *destination_address,
                             const struct ether_addr *cluster_id,
                             const struct nan_peer *peer)
{
    (void)state;
    (void)cluster_id;

    list_t service_descriptors = list_init();
    list_t service_descriptor_extensions = list_init();
    int result = 0;

    NAN_ITERATE_ATTRIBUTES({
        switch (attribute_id)
        {
        case SERVICE_DESCRIPTOR_ATTRIBUTE:
            result = nan_parse_sda(attribute_buf, service_descriptors);
            break;
        case SERVICE_DESCRIPTOR_EXTENSION_ATTRIBUTE:
            result = nan_parse_sdea(attribute_buf, attribute_length,
                                    service_descriptor_extensions);
            break;
        default:
            log_trace("Unhandled attribute: %s", nan_attribute_type_as_string(attribute_id));
            result = RX_IGNORE;
        }
    })

    if (result < 0)
    {
        log_error("Error while parsing attributes: %d", result);
        return result;
    }

    struct nan_service_descriptor_attribute *service_descriptor;
    LIST_FOR_EACH(
        service_descriptors, service_descriptor, {
            log_trace("Received service discovery for %u of type %d",
                      nan_service_id_to_string(&service_descriptor->service_id),
                      service_descriptor->control.service_control_type);
            nan_handle_received_service_discovery(&state->services, &state->events, &state->interface_address,
                                                  &peer->addr, destination_address, service_descriptor);
        })

    list_free(service_descriptors, true);
    list_free(service_descriptor_extensions, true);

    return result;
}

int nan_rx_action(struct buf *frame, struct nan_state *state,
                  const struct ether_addr *source_address, const struct ether_addr *destination_address,
                  const struct ether_addr *cluster_id, const uint64_t now_usec)
{
    if (buf_rest(frame) < (int)sizeof(struct nan_action_frame))
    {
        log_trace("nan_action: frame to short");
        return RX_TOO_SHORT;
    }
    const struct nan_action_frame *action_frame = (const struct nan_action_frame *)buf_current(frame);

    if (!oui_equal(action_frame->oui, NAN_OUI))
        return RX_IGNORE_OUI;

    struct nan_peer *peer = NULL;
    enum peer_status status = PEER_MISSING;

    status = nan_peer_add(&state->peers, source_address, cluster_id, now_usec);
    if (status < 0)
    {
        log_warn("nan_action: could not add peer: %s (%d)", ether_addr_to_string(source_address), status);
        return RX_IGNORE;
    }
    if (status == PEER_OK)
        log_debug("nan_action: peer added %s", ether_addr_to_string(source_address));

    status = nan_peer_get(&state->peers, source_address, &peer);
    if (status < 0 || peer == NULL)
    {
        log_warn("nan_action: could not get peer: %s (%d)", ether_addr_to_string(source_address), status);
        return RX_IGNORE;
    }

    if (action_frame->oui_type == NAN_OUT_TYPE_SERVICE_DISCOVERY)
    {
        // service discovery frame is just one byte shorter than action frame
        buf_advance(frame, sizeof(struct nan_service_discovery_frame));
        return nan_rx_service_discovery(frame, state, destination_address, cluster_id, peer);
    }
    if (action_frame->oui_type != NAN_OUI_TYPE_ACTION)
    {
        log_warn("Unknown action frame out type: %d", action_frame->oui_type);
        return RX_IGNORE;
    }

    buf_advance(frame, sizeof(struct nan_action_frame));
    log_trace("nan_action: received %s from %s",
              nan_action_frame_subtype_to_string(action_frame->oui_subtype),
              ether_addr_to_string(source_address));

    return RX_OK;
}

int nan_rx(struct buf *frame, struct nan_state *state)
{
    signed char rssi;
    uint8_t flags;

    uint64_t now_usec = clock_time_usec();
    if (ieee80211_parse_radiotap_header(frame, &rssi, &flags, NULL /*&now_usec*/) < 0)
    {
        log_trace("radiotap: cannot parse header");
        return RX_UNEXPECTED_FORMAT;
    }

    if (ieee80211_parse_fcs(frame, flags) < 0)
    {
        log_trace("CRC failed");
        return RX_IGNORE_FAILED_CRC;
    }

    if (buf_rest(frame) < (int)sizeof(struct ieee80211_hdr))
    {
        log_trace("ieee80211: header to short");
        return RX_TOO_SHORT;
    }

    uint8_t other_opennan_ether_addr[6] = {0x00, 0xC0, 0xCA, 0xAE, 0x65, 0x79};

    const struct ieee80211_hdr *ieee80211 = (const struct ieee80211_hdr *)buf_current(frame);
    const struct ether_addr *destination_address = &ieee80211->addr1;
    const struct ether_addr *source_address = &ieee80211->addr2;
    const struct ether_addr *cluster_id = &ieee80211->addr3;
    uint16_t frame_control = le16toh(ieee80211->frame_control);

    if (ether_addr_equal(source_address, &state->self_address))
        return RX_IGNORE_FROM_SELF;
    else if (ether_addr_equal(source_address, other_opennan_ether_addr))
        log_debug("nan rx: received from 79");
        // return RX_IGNORE_FROM_SELF;

    if (buf_advance(frame, sizeof(struct ieee80211_hdr)) < 0)
        return RX_TOO_SHORT;

    switch (frame_control & (IEEE80211_FCTL_FTYPE | IEEE80211_FCTL_STYPE))
    {
    case IEEE80211_FTYPE_MGMT | IEEE80211_STYPE_BEACON:
        return nan_rx_beacon(frame, state, source_address, cluster_id, rssi, now_usec);
    case IEEE80211_FTYPE_MGMT | IEEE80211_STYPE_ACTION:
        log_trace("Received action frame");
        return nan_rx_action(frame, state, source_address, destination_address, cluster_id, now_usec);
    default:
        log_trace("ieee80211: cannot handle type %x and subtype %x of received frame from %s",
                  frame_control & IEEE80211_FCTL_FTYPE, frame_control & IEEE80211_FCTL_STYPE, ether_addr_to_string(source_address));
        return RX_UNEXPECTED_TYPE;
    }
}
