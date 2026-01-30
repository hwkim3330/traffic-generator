/*
 * tsn_payload.h - TSN Traffic Payload Header Definition v1.0
 *
 * Standard payload header for tsngen/tsnrecv communication.
 * Enables reliable sequence tracking, latency measurement, and flow identification.
 *
 * Copyright (C) 2025
 * License: GPLv2
 */

#ifndef TSN_PAYLOAD_H
#define TSN_PAYLOAD_H

#include <stdint.h>

/*============================================================================
 * Payload Header Version
 *============================================================================*/

#define TSN_PAYLOAD_VERSION     1
#define TSN_PAYLOAD_MAGIC       0x54534E31  /* "TSN1" */

/*============================================================================
 * Payload Header Structure (24 bytes)
 *============================================================================
 *
 * Wire format (all fields network byte order except timestamp):
 *
 *   0                   1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                         Magic (0x54534E31)                   |  0-3
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |    Version    |    Flags      |   Flow ID     |   Reserved   |  4-7
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                       Sequence Number                        |  8-11
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                                                               |
 *  +                    Timestamp (ns, host order)                +  12-19
 *  |                                                               |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                       Payload Length                         |  20-23
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                         Payload Data                         |
 *  |                            ...                                |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

/* Header size */
#define TSN_PAYLOAD_HDR_SIZE    24

/* Flag bits */
#define TSN_FLAG_SEQ            0x01    /* Sequence number valid */
#define TSN_FLAG_TIMESTAMP      0x02    /* Timestamp valid */
#define TSN_FLAG_FLOW_ID        0x04    /* Flow ID valid */

/*
 * Flow ID assignment:
 *   - Single mode: flow_id = 0
 *   - Multi-TC mode: flow_id = PCP (0-7)
 *   - Multi-worker: flow_id = (tc << 4) | (worker_id & 0x0F)
 *
 * This allows RX to track sequences per-flow, avoiding false reorder
 * detection when multiple TX processes/threads send to the same PCP.
 */

#pragma pack(push, 1)
typedef struct {
    uint32_t magic;         /* Magic number: 0x54534E31 ("TSN1") */
    uint8_t  version;       /* Header version (currently 1) */
    uint8_t  flags;         /* TSN_FLAG_* bits */
    uint8_t  flow_id;       /* Flow identifier for per-flow tracking */
    uint8_t  reserved;      /* Reserved for future use (set to 0) */
    uint32_t seq_num;       /* Sequence number (network byte order) */
    uint64_t timestamp;     /* TX timestamp in ns (CLOCK_MONOTONIC_RAW, host order) */
    uint32_t payload_len;   /* Length of data following this header */
} tsn_payload_hdr_t;
#pragma pack(pop)

/*============================================================================
 * Helper Macros
 *============================================================================*/

/* Check if header is valid */
#define TSN_HDR_VALID(hdr) \
    ((hdr)->magic == htonl(TSN_PAYLOAD_MAGIC) && (hdr)->version == TSN_PAYLOAD_VERSION)

/* Check flag */
#define TSN_HDR_HAS_SEQ(hdr)       ((hdr)->flags & TSN_FLAG_SEQ)
#define TSN_HDR_HAS_TIMESTAMP(hdr) ((hdr)->flags & TSN_FLAG_TIMESTAMP)
#define TSN_HDR_HAS_FLOW_ID(hdr)   ((hdr)->flags & TSN_FLAG_FLOW_ID)

/*============================================================================
 * Flow ID Encoding/Decoding
 *============================================================================*/

/* Encode: tc (0-7) + worker (0-15) -> flow_id */
static inline uint8_t tsn_encode_flow_id(uint8_t tc, uint8_t worker_id) {
    return (uint8_t)((tc & 0x07) << 4) | (worker_id & 0x0F);
}

/* Decode: flow_id -> tc, worker */
static inline void tsn_decode_flow_id(uint8_t flow_id, uint8_t *tc, uint8_t *worker_id) {
    if (tc) *tc = (flow_id >> 4) & 0x07;
    if (worker_id) *worker_id = flow_id & 0x0F;
}

/* Simple flow_id = PCP (for single-worker mode) */
static inline uint8_t tsn_flow_id_from_pcp(uint8_t pcp) {
    return pcp & 0x07;
}

/*============================================================================
 * Sequence Number Ranges
 *============================================================================
 *
 * To avoid sequence collision in multi-TC/multi-worker scenarios:
 *
 *   TC 0: 0x00000000 - 0x0FFFFFFF (268M)
 *   TC 1: 0x10000000 - 0x1FFFFFFF
 *   TC 2: 0x20000000 - 0x2FFFFFFF
 *   ...
 *   TC 7: 0x70000000 - 0x7FFFFFFF
 *
 * Within each TC, workers get 16M sub-ranges:
 *   Worker 0: base + 0x00000000
 *   Worker 1: base + 0x01000000
 *   ...
 *   Worker 15: base + 0x0F000000
 *
 * This provides ~16M sequences per worker before wrap.
 */

#define TSN_SEQ_TC_SHIFT        28
#define TSN_SEQ_WORKER_SHIFT    24
#define TSN_SEQ_TC_MASK         0x70000000
#define TSN_SEQ_WORKER_MASK     0x0F000000
#define TSN_SEQ_COUNTER_MASK    0x00FFFFFF

/* Calculate starting sequence for given TC and worker */
static inline uint32_t tsn_seq_start(uint8_t tc, uint8_t worker_id) {
    return ((uint32_t)(tc & 0x07) << TSN_SEQ_TC_SHIFT) |
           ((uint32_t)(worker_id & 0x0F) << TSN_SEQ_WORKER_SHIFT);
}

/* Extract TC from sequence number */
static inline uint8_t tsn_seq_get_tc(uint32_t seq) {
    return (uint8_t)((seq >> TSN_SEQ_TC_SHIFT) & 0x07);
}

/* Extract worker from sequence number */
static inline uint8_t tsn_seq_get_worker(uint32_t seq) {
    return (uint8_t)((seq >> TSN_SEQ_WORKER_SHIFT) & 0x0F);
}

/*============================================================================
 * Legacy Compatibility
 *============================================================================
 *
 * For backward compatibility with old payload format (v0):
 *   Bytes 0-3:  Sequence number (network order)
 *   Bytes 4-11: Timestamp (host order)
 *
 * Detection: If magic != TSN_PAYLOAD_MAGIC, assume legacy format.
 */

#define TSN_LEGACY_HDR_SIZE     12

typedef struct {
    uint32_t seq_num;       /* Sequence number (network byte order) */
    uint64_t timestamp;     /* TX timestamp in ns (host order) */
} tsn_legacy_hdr_t;

/* Check if payload uses new format */
static inline int tsn_is_new_format(const void *payload, size_t len) {
    if (len < sizeof(uint32_t)) return 0;
    uint32_t magic = *(const uint32_t *)payload;
    return (magic == htonl(TSN_PAYLOAD_MAGIC));
}

#endif /* TSN_PAYLOAD_H */
