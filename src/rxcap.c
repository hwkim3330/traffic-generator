/*
 * rxcap - High-Performance Traffic Capture & Analysis Tool
 *
 * Copyright (C) 2025 KETI (Korea Electronics Technology Institute)
 *
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License version 2 as published by the
 * Free Software Foundation.
 *
 * Features:
 * - recvmmsg() batch receive for 10Gbps+ capture
 * - PCAP file output (Wireshark compatible)
 * - Per-PCP/TC statistics with atomic counters
 * - VLAN tag parsing (802.1Q, QinQ, 802.1ad)
 * - Latency and inter-arrival time measurement (CAS min/max)
 * - Sequence number tracking for loss detection
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <pthread.h>
#include <getopt.h>
#include <stdatomic.h>
#include <stdint.h>
#include <math.h>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netpacket/packet.h>
#include <linux/if_ether.h>
#include <sched.h>

/*============================================================================
 * PCAP File Format (no libpcap dependency)
 *============================================================================*/
#define PCAP_MAGIC          0xa1b2c3d4
#define PCAP_VERSION_MAJOR  2
#define PCAP_VERSION_MINOR  4
#define PCAP_LINKTYPE_ETH   1

#pragma pack(push, 1)
typedef struct {
    uint32_t magic;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t  thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t linktype;
} pcap_hdr_t;

typedef struct {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
} pcap_pkthdr_t;
#pragma pack(pop)

/*============================================================================
 * Simple Payload Header - 12 bytes
 * seq(4B) + timestamp(8B), both network order
 *============================================================================*/
#define SIMPLE_PAYLOAD_SIZE    12

/* 64-bit network to host order */
static inline uint64_t ntohll(uint64_t x) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return ((uint64_t)ntohl((uint32_t)(x & 0xffffffffULL)) << 32) |
            ntohl((uint32_t)(x >> 32));
#else
    return x;
#endif
}

#pragma pack(push, 1)
typedef struct {
    uint32_t seq_num;     /* Sequence number (network order) */
    uint64_t timestamp;   /* Timestamp in nanoseconds (network order) */
} simple_payload_t;
#pragma pack(pop)

/* SO_RXQ_OVFL for drop detection (if not defined) */
#ifndef SO_RXQ_OVFL
#define SO_RXQ_OVFL 40
#endif

/*============================================================================
 * Constants
 *============================================================================*/

#define VERSION "2.1.0"
#define MAX_PACKET_SIZE 9000
#define MAX_PACKET_SIZE_ALIGNED ((MAX_PACKET_SIZE + 63) & ~63)  /* 9024, multiple of 64 */
#define DEFAULT_BATCH_SIZE 256
#define STATS_INTERVAL_US 1000000
#define MAX_PCP 8
#define LATENCY_SAMPLES 10000

/*============================================================================
 * Data Structures
 *============================================================================*/

/* Per-PCP statistics */
typedef struct {
    atomic_uint_fast64_t packets;
    atomic_uint_fast64_t bytes;
    /* Per-PCP sequence tracking */
    uint32_t last_seq;
    atomic_uint_fast64_t seq_errors;
    atomic_uint_fast64_t seq_duplicates;
} pcp_stats_t;

/* Global configuration */
typedef struct {
    char interface[IFNAMSIZ];

    /* Filter */
    int filter_vlan;
    uint16_t vlan_id;
    int filter_pcp;
    uint8_t pcp;
    int seq_only;   /* Only count packets with sequence header */

    /* Options */
    int duration;
    int batch_size;
    int check_seq;
    int measure_latency;

    /* Output */
    char csv_file[256];
    char pcap_file[256];
    int verbose;
    int quiet;
    int show_pcp_stats;

    /* Performance */
    int use_affinity;
    int affinity_cpu;
} config_t;

/* Global statistics */
typedef struct {
    atomic_uint_fast64_t total_packets;
    atomic_uint_fast64_t total_bytes;
    atomic_uint_fast64_t vlan_packets;
    atomic_uint_fast64_t non_vlan_packets;
    pcp_stats_t pcp[MAX_PCP];

    /* Kernel/socket drops (from SO_RXQ_OVFL) */
    atomic_uint_fast64_t kernel_drops;

    /* Sequence tracking (atomic for stats_thread safety) */
    atomic_uint_fast64_t seq_errors;
    atomic_uint_fast64_t seq_duplicates;
    _Atomic(uint32_t) first_seq;
    _Atomic(uint32_t) last_seq;
    _Atomic(int) seq_started;

    /* Latency (if timestamp in packet) - uses CLOCK_MONOTONIC_RAW */
    atomic_uint_fast64_t latency_sum;
    atomic_uint_fast64_t latency_count;
    atomic_uint_fast64_t latency_min;
    atomic_uint_fast64_t latency_max;

    /* Inter-arrival time */
    uint64_t last_arrival_ns;  /* Only written by RX thread */
    atomic_uint_fast64_t iat_sum;
    atomic_uint_fast64_t iat_count;
    atomic_uint_fast64_t iat_min;
    atomic_uint_fast64_t iat_max;
} rx_stats_t;

/*============================================================================
 * Globals
 *============================================================================*/

static volatile sig_atomic_t g_running = 1;
static config_t g_config;
static rx_stats_t g_stats;
static pthread_t g_rx_thread;
static pthread_t g_stats_thread;
static struct timespec g_start_time;
static FILE *g_csv_fp = NULL;
static FILE *g_pcap_fp = NULL;
static pthread_mutex_t g_pcap_lock = PTHREAD_MUTEX_INITIALIZER;

/* Write pcap global header */
static int pcap_open(const char *filename) {
    g_pcap_fp = fopen(filename, "wb");
    if (!g_pcap_fp) return -1;

    pcap_hdr_t hdr = {
        .magic = PCAP_MAGIC,
        .version_major = PCAP_VERSION_MAJOR,
        .version_minor = PCAP_VERSION_MINOR,
        .thiszone = 0,
        .sigfigs = 0,
        .snaplen = 65535,
        .linktype = PCAP_LINKTYPE_ETH
    };
    fwrite(&hdr, sizeof(hdr), 1, g_pcap_fp);
    return 0;
}

/* Batch PCAP write entry */
typedef struct {
    uint8_t *data;
    int len;
    uint64_t ts_ns;
} pcap_entry_t;

/* Batch write multiple packets to pcap (single lock acquisition) */
static void pcap_write_batch(pcap_entry_t *entries, int count) {
    if (!g_pcap_fp || count == 0) return;

    pthread_mutex_lock(&g_pcap_lock);
    for (int i = 0; i < count; i++) {
        pcap_pkthdr_t pkthdr = {
            .ts_sec = (uint32_t)(entries[i].ts_ns / 1000000000ULL),
            .ts_usec = (uint32_t)((entries[i].ts_ns % 1000000000ULL) / 1000),
            .incl_len = entries[i].len,
            .orig_len = entries[i].len
        };
        fwrite(&pkthdr, sizeof(pkthdr), 1, g_pcap_fp);
        fwrite(entries[i].data, entries[i].len, 1, g_pcap_fp);
    }
    pthread_mutex_unlock(&g_pcap_lock);
}

/*============================================================================
 * Signal Handler
 *============================================================================*/

static void signal_handler(int sig) {
    (void)sig;
    g_running = 0;
}

/*============================================================================
 * Utility Functions
 *============================================================================*/

/*
 * Timestamp policy:
 * - Uses CLOCK_MONOTONIC_RAW for latency measurement
 * - This clock is not subject to NTP adjustments
 * - txgen must also use CLOCK_MONOTONIC_RAW for accurate latency
 * - For cross-machine latency, use PTP-synced HW timestamps instead
 */
static inline uint64_t get_time_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static int get_if_index(const char *ifname) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
        close(fd);
        return -1;
    }

    close(fd);
    return ifr.ifr_ifindex;
}

/*============================================================================
 * Packet Parsing
 *============================================================================*/

/*
 * Simple Payload Header (12 bytes): seq(4B) + timestamp(8B)
 */
typedef struct {
    uint8_t src_mac[6];
    uint8_t dst_mac[6];
    int has_vlan;
    uint16_t vlan_id;
    uint8_t pcp;
    uint8_t dei;
    uint16_t ethertype;
    int payload_offset;

    /* Simple payload fields: seq(4B) + timestamp(8B) */
    uint32_t seq_num;
    uint64_t timestamp;
    int has_seq;
    int has_timestamp;
} parsed_packet_t;

static int parse_packet(const uint8_t *buf, int len, parsed_packet_t *pkt) {
    if (len < 14) return -1;

    memset(pkt, 0, sizeof(*pkt));

    /* Ethernet header */
    memcpy(pkt->dst_mac, buf, 6);
    memcpy(pkt->src_mac, buf + 6, 6);

    int offset = 12;
    uint16_t ethertype = (buf[offset] << 8) | buf[offset + 1];
    offset += 2;

    /* Check for VLAN tags (single, QinQ, or 802.1ad provider) */
    while ((ethertype == 0x8100 || ethertype == 0x88a8 || ethertype == 0x9100) && offset + 4 <= len) {
        if (!pkt->has_vlan) {
            pkt->has_vlan = 1;
            uint16_t tci = (buf[offset] << 8) | buf[offset + 1];
            pkt->pcp = (tci >> 13) & 0x7;
            pkt->dei = (tci >> 12) & 0x1;
            pkt->vlan_id = tci & 0xfff;
        }
        ethertype = (buf[offset + 2] << 8) | buf[offset + 3];
        offset += 4;
    }

    pkt->ethertype = ethertype;
    pkt->payload_offset = offset;

    /* Try to extract seq/timestamp from UDP payload */
    int udp_payload_start = -1;
    int udp_payload_len = 0;

    if (ethertype == 0x0800 && len >= offset + 20 + 8) {
        /* IPv4 */
        int ip_offset = offset;
        int ihl = (buf[ip_offset] & 0x0F) * 4;
        uint8_t ip_proto = buf[ip_offset + 9];

        if (ip_proto == 17 && len >= ip_offset + ihl + 8) {  /* UDP */
            udp_payload_start = ip_offset + ihl + 8;
            udp_payload_len = len - udp_payload_start;
        }
    } else if (ethertype == 0x86dd && len >= offset + 40 + 8) {
        /* IPv6 (40-byte fixed header) */
        int ip6_offset = offset;
        uint8_t next_hdr = buf[ip6_offset + 6];

        if (next_hdr == 17 && len >= ip6_offset + 40 + 8) {  /* UDP */
            udp_payload_start = ip6_offset + 40 + 8;
            udp_payload_len = len - udp_payload_start;
        }
        /* Note: Extension headers not supported - assumes UDP follows directly */
    }

    if (udp_payload_start >= 0) {
        /* Simple format (12 bytes): seq(4B) + timestamp(8B) */
        if (udp_payload_len >= SIMPLE_PAYLOAD_SIZE) {
            /* First 4 bytes: sequence number (network order) */
            memcpy(&pkt->seq_num, buf + udp_payload_start, 4);
            pkt->seq_num = ntohl(pkt->seq_num);
            pkt->has_seq = 1;

            /* Next 8 bytes: timestamp (network order) */
            memcpy(&pkt->timestamp, buf + udp_payload_start + 4, 8);
            pkt->timestamp = ntohll(pkt->timestamp);
            pkt->has_timestamp = (pkt->timestamp != 0);
        } else if (udp_payload_len >= 4) {
            /* At least sequence number */
            memcpy(&pkt->seq_num, buf + udp_payload_start, 4);
            pkt->seq_num = ntohl(pkt->seq_num);
            pkt->has_seq = 1;
        }
    }

    return 0;
}

/*============================================================================
 * RX Thread (cleanup-safe: all error paths go through cleanup label)
 *============================================================================*/

static void *rx_thread(void *arg) {
    config_t *cfg = (config_t *)arg;

    /* All resources declared at top for cleanup */
    int sock = -1;
    int ifindex = -1;
    int batch = 0;

    uint8_t **buffers = NULL;
    uint8_t **cmsg_bufs = NULL;
    struct mmsghdr *msgs = NULL;
    struct iovec *iovecs = NULL;
    pcap_entry_t *pcap_entries = NULL;

    size_t cmsg_size = CMSG_SPACE(sizeof(uint32_t));

    /* CPU affinity */
    if (cfg->use_affinity) {
        cpu_set_t cpuset;
        CPU_ZERO(&cpuset);
        int cpu = cfg->affinity_cpu >= 0 ? cfg->affinity_cpu : 0;
        CPU_SET(cpu % sysconf(_SC_NPROCESSORS_ONLN), &cpuset);
        pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset);
    }

    sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        perror("socket");
        return NULL;
    }

    /* Increase receive buffer */
    int rcvbuf = 64 * 1024 * 1024;
    (void)setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

    /* Enable SO_RXQ_OVFL */
    int ovfl_enable = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_RXQ_OVFL, &ovfl_enable, sizeof(ovfl_enable)) < 0) {
        if (cfg->verbose) {
            fprintf(stderr, "Warning: SO_RXQ_OVFL not supported, drop counting disabled\n");
        }
    }

    ifindex = get_if_index(cfg->interface);
    if (ifindex < 0) {
        fprintf(stderr, "Failed to get interface index for %s\n", cfg->interface);
        goto cleanup;
    }

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);

    if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("bind");
        goto cleanup;
    }

    /* Promiscuous mode */
    struct packet_mreq mreq;
    memset(&mreq, 0, sizeof(mreq));
    mreq.mr_ifindex = ifindex;
    mreq.mr_type = PACKET_MR_PROMISC;
    (void)setsockopt(sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq));

    /* Allocate batch receive buffers */
    batch = cfg->batch_size;
    buffers = calloc(batch, sizeof(uint8_t *));
    cmsg_bufs = calloc(batch, sizeof(uint8_t *));
    msgs = calloc(batch, sizeof(struct mmsghdr));
    iovecs = calloc(batch, sizeof(struct iovec));

    if (!buffers || !cmsg_bufs || !msgs || !iovecs) {
        fprintf(stderr, "RX thread: alloc failed\n");
        goto cleanup;
    }

    for (int i = 0; i < batch; i++) {
        buffers[i] = aligned_alloc(64, MAX_PACKET_SIZE_ALIGNED);
        cmsg_bufs[i] = malloc(cmsg_size);
        if (!buffers[i] || !cmsg_bufs[i]) {
            fprintf(stderr, "RX thread: buffer alloc failed at %d\n", i);
            goto cleanup;
        }

        iovecs[i].iov_base = buffers[i];
        iovecs[i].iov_len = MAX_PACKET_SIZE;

        msgs[i].msg_hdr.msg_iov = &iovecs[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
        msgs[i].msg_hdr.msg_control = cmsg_bufs[i];
        msgs[i].msg_hdr.msg_controllen = cmsg_size;
    }

    if (g_pcap_fp) {
        pcap_entries = malloc(batch * sizeof(pcap_entry_t));
        if (!pcap_entries) {
            fprintf(stderr, "Warning: PCAP buffer alloc failed, disabling PCAP\n");
        }
    }

    parsed_packet_t pkt;
    uint64_t local_packets = 0;
    uint64_t local_bytes = 0;
    uint64_t last_drop_count = 0;

    while (g_running) {
        for (int i = 0; i < batch; i++) {
            msgs[i].msg_hdr.msg_controllen = cmsg_size;
        }

        int received = recvmmsg(sock, msgs, batch, MSG_DONTWAIT, NULL);

        if (received > 0) {
            int pcap_count = 0;

            for (int i = 0; i < received; i++) {
                uint64_t now_ns = get_time_ns();
                int len = msgs[i].msg_len;
                uint8_t *buf = buffers[i];

                /* SO_RXQ_OVFL drop detection */
                for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msgs[i].msg_hdr);
                     cmsg != NULL;
                     cmsg = CMSG_NXTHDR(&msgs[i].msg_hdr, cmsg)) {
                    if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SO_RXQ_OVFL) {
                        uint32_t drop_count;
                        memcpy(&drop_count, CMSG_DATA(cmsg), sizeof(drop_count));
                        if (drop_count > last_drop_count) {
                            atomic_fetch_add(&g_stats.kernel_drops, drop_count - last_drop_count);
                            last_drop_count = drop_count;
                        }
                    }
                }

                if (parse_packet(buf, len, &pkt) < 0) continue;

                /* Filters */
                if (cfg->filter_vlan && (!pkt.has_vlan || pkt.vlan_id != cfg->vlan_id)) continue;
                if (cfg->filter_pcp && (!pkt.has_vlan || pkt.pcp != cfg->pcp)) continue;
                if (cfg->seq_only && !pkt.has_seq) continue;

                local_packets++;
                local_bytes += len;

                if (pcap_entries) {
                    pcap_entries[pcap_count].data = buf;
                    pcap_entries[pcap_count].len = len;
                    pcap_entries[pcap_count].ts_ns = now_ns;
                    pcap_count++;
                }

                /* VLAN / PCP stats */
                if (pkt.has_vlan) {
                    atomic_fetch_add(&g_stats.vlan_packets, 1);
                    atomic_fetch_add(&g_stats.pcp[pkt.pcp].packets, 1);
                    atomic_fetch_add(&g_stats.pcp[pkt.pcp].bytes, len);

                    if (cfg->check_seq && pkt.has_seq) {
                        pcp_stats_t *pcp_stat = &g_stats.pcp[pkt.pcp];
                        if (pcp_stat->last_seq != 0) {
                            if (pkt.seq_num < pcp_stat->last_seq &&
                                (pcp_stat->last_seq - pkt.seq_num) > 0x80000000U) {
                                /* wraparound */
                            } else if (pkt.seq_num < pcp_stat->last_seq) {
                                pcp_stat->last_seq = 0;  /* restart */
                            } else if (pkt.seq_num == pcp_stat->last_seq) {
                                atomic_fetch_add(&pcp_stat->seq_duplicates, 1);
                            } else if (pkt.seq_num != pcp_stat->last_seq + 1) {
                                atomic_fetch_add(&pcp_stat->seq_errors, 1);
                            }
                        }
                        pcp_stat->last_seq = pkt.seq_num;
                    }
                } else {
                    atomic_fetch_add(&g_stats.non_vlan_packets, 1);

                    if (cfg->check_seq && pkt.has_seq) {
                        if (atomic_load(&g_stats.seq_started) == 0) {
                            atomic_store(&g_stats.first_seq, pkt.seq_num);
                            atomic_store(&g_stats.last_seq, pkt.seq_num);
                            atomic_store(&g_stats.seq_started, 1);
                        } else {
                            uint32_t last = atomic_load(&g_stats.last_seq);
                            if (pkt.seq_num == last) {
                                atomic_fetch_add(&g_stats.seq_duplicates, 1);
                            } else if (pkt.seq_num != last + 1) {
                                atomic_fetch_add(&g_stats.seq_errors, 1);
                            }
                            atomic_store(&g_stats.last_seq, pkt.seq_num);
                        }
                    }
                }

                /* Latency */
                if (cfg->measure_latency && pkt.has_timestamp) {
                    uint64_t latency = now_ns - pkt.timestamp;
                    atomic_fetch_add(&g_stats.latency_sum, latency);
                    atomic_fetch_add(&g_stats.latency_count, 1);

                    uint64_t cur = atomic_load(&g_stats.latency_min);
                    while (cur == 0 || latency < cur) {
                        if (atomic_compare_exchange_weak(&g_stats.latency_min, &cur, latency)) break;
                    }
                    cur = atomic_load(&g_stats.latency_max);
                    while (latency > cur) {
                        if (atomic_compare_exchange_weak(&g_stats.latency_max, &cur, latency)) break;
                    }
                }

                /* IAT */
                if (g_stats.last_arrival_ns > 0) {
                    uint64_t iat = now_ns - g_stats.last_arrival_ns;
                    atomic_fetch_add(&g_stats.iat_sum, iat);
                    atomic_fetch_add(&g_stats.iat_count, 1);

                    uint64_t cur = atomic_load(&g_stats.iat_min);
                    while (cur == 0 || iat < cur) {
                        if (atomic_compare_exchange_weak(&g_stats.iat_min, &cur, iat)) break;
                    }
                    cur = atomic_load(&g_stats.iat_max);
                    while (iat > cur) {
                        if (atomic_compare_exchange_weak(&g_stats.iat_max, &cur, iat)) break;
                    }
                }
                g_stats.last_arrival_ns = now_ns;
            }

            if (pcap_entries && pcap_count > 0) {
                pcap_write_batch(pcap_entries, pcap_count);
            }

            atomic_fetch_add(&g_stats.total_packets, local_packets);
            atomic_fetch_add(&g_stats.total_bytes, local_bytes);
            local_packets = 0;
            local_bytes = 0;
        } else if (received == 0 || (received < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))) {
            struct timespec ts = {.tv_sec = 0, .tv_nsec = 100000};
            nanosleep(&ts, NULL);
        } else if (received < 0) {
            if (g_running) perror("recvmmsg");
        }
    }

cleanup:
    if (buffers) {
        for (int i = 0; i < batch; i++) free(buffers[i]);
    }
    if (cmsg_bufs) {
        for (int i = 0; i < batch; i++) free(cmsg_bufs[i]);
    }
    free(buffers);
    free(cmsg_bufs);
    free(msgs);
    free(iovecs);
    free(pcap_entries);

    if (sock >= 0) close(sock);
    return NULL;
}

/*============================================================================
 * Statistics Thread
 *============================================================================*/

static void *stats_thread(void *arg) {
    config_t *cfg = (config_t *)arg;

    if (!cfg->quiet) {
        printf("\n");
        printf("═══════════════════════════════════════════════════════════════════════════════════════════════════════════════\n");
        printf(" rxcap v%s - Traffic Capture\n", VERSION);
        printf(" Interface: %s | Batch: %d", cfg->interface, cfg->batch_size);
        if (cfg->filter_vlan) printf(" | VLAN: %d", cfg->vlan_id);
        if (cfg->filter_pcp) printf(" | PCP: %d", cfg->pcp);
        if (cfg->use_affinity) printf(" | CPU: %d", cfg->affinity_cpu >= 0 ? cfg->affinity_cpu : 0);
        printf("\n");
        printf(" Clock: CLOCK_MONOTONIC_RAW (same-machine latency only)\n");
        printf("═══════════════════════════════════════════════════════════════════════════════════════════════════════════════\n");

        if (cfg->show_pcp_stats) {
            printf(" %7s │ %12s │ %10s │ %10s │ %6s │ %7s %7s %7s %7s %7s %7s %7s %7s\n",
                   "Time", "Packets", "PPS", "Mbps", "Drops", "PCP0", "PCP1", "PCP2", "PCP3", "PCP4", "PCP5", "PCP6", "PCP7");
            printf("─────────┼──────────────┼────────────┼────────────┼────────┼───────────────────────────────────────────────────────────────────\n");
        } else {
            printf(" %7s │ %12s │ %10s │ %10s │ %6s │ %10s │ %10s\n",
                   "Time", "Packets", "PPS", "Mbps", "Drops", "VLAN", "Non-VLAN");
            printf("─────────┼──────────────┼────────────┼────────────┼────────┼────────────┼────────────\n");
        }
    }

    uint64_t last_packets = 0;
    uint64_t last_bytes = 0;
    uint64_t last_pcp[MAX_PCP] = {0};
    struct timespec last_time;
    clock_gettime(CLOCK_MONOTONIC, &last_time);

    while (g_running) {
        usleep(STATS_INTERVAL_US);

        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        double interval = (now.tv_sec - last_time.tv_sec) +
                         (now.tv_nsec - last_time.tv_nsec) / 1e9;
        double elapsed = (now.tv_sec - g_start_time.tv_sec) +
                        (now.tv_nsec - g_start_time.tv_nsec) / 1e9;

        uint64_t total_packets = atomic_load(&g_stats.total_packets);
        uint64_t total_bytes = atomic_load(&g_stats.total_bytes);
        uint64_t vlan_packets = atomic_load(&g_stats.vlan_packets);
        uint64_t non_vlan_packets = atomic_load(&g_stats.non_vlan_packets);
        uint64_t kernel_drops = atomic_load(&g_stats.kernel_drops);

        uint64_t delta_packets = total_packets - last_packets;
        uint64_t delta_bytes = total_bytes - last_bytes;

        double pps = delta_packets / interval;
        double mbps = (delta_bytes * 8.0) / (interval * 1e6);

        if (!cfg->quiet) {
            if (cfg->show_pcp_stats) {
                printf(" %6.1fs │ %12lu │ %10.0f │ %10.1f │ %6lu │",
                       elapsed, total_packets, pps, mbps, kernel_drops);
                for (int p = 0; p < MAX_PCP; p++) {
                    uint64_t pcp_pkts = atomic_load(&g_stats.pcp[p].packets);
                    uint64_t delta_pcp = pcp_pkts - last_pcp[p];
                    printf(" %7lu", delta_pcp);
                    last_pcp[p] = pcp_pkts;
                }
                printf("\n");
            } else {
                printf(" %6.1fs │ %12lu │ %10.0f │ %10.1f │ %6lu │ %10lu │ %10lu\n",
                       elapsed, total_packets, pps, mbps, kernel_drops, vlan_packets, non_vlan_packets);
            }
            fflush(stdout);
        }

        /* Write to CSV - standardized schema */
        if (g_csv_fp) {
            fprintf(g_csv_fp, "%.3f,%lu,%.0f,%.3f,%lu",
                    elapsed, total_packets, pps, mbps, kernel_drops);
            for (int p = 0; p < MAX_PCP; p++) {
                fprintf(g_csv_fp, ",%lu", atomic_load(&g_stats.pcp[p].packets));
            }

            /* Latency: -1 if not measured or no data */
            uint64_t lat_count = atomic_load(&g_stats.latency_count);
            if (cfg->measure_latency && lat_count > 0) {
                uint64_t lat_sum = atomic_load(&g_stats.latency_sum);
                double lat_avg = (double)lat_sum / lat_count;
                fprintf(g_csv_fp, ",%lu,%.0f,%lu",
                        atomic_load(&g_stats.latency_min), lat_avg,
                        atomic_load(&g_stats.latency_max));
            } else {
                fprintf(g_csv_fp, ",-1,-1,-1");
            }

            /* IAT: -1 if no data */
            uint64_t iat_count = atomic_load(&g_stats.iat_count);
            if (iat_count > 0) {
                uint64_t iat_sum = atomic_load(&g_stats.iat_sum);
                double iat_avg = (double)iat_sum / iat_count;
                fprintf(g_csv_fp, ",%lu,%.0f,%lu\n",
                        atomic_load(&g_stats.iat_min), iat_avg,
                        atomic_load(&g_stats.iat_max));
            } else {
                fprintf(g_csv_fp, ",-1,-1,-1\n");
            }
            fflush(g_csv_fp);
        }

        last_packets = total_packets;
        last_bytes = total_bytes;
        last_time = now;

        if (cfg->duration > 0 && elapsed >= cfg->duration) {
            g_running = 0;
            break;
        }
    }

    /* Final summary */
    struct timespec end_time;
    clock_gettime(CLOCK_MONOTONIC, &end_time);
    double total_time = (end_time.tv_sec - g_start_time.tv_sec) +
                       (end_time.tv_nsec - g_start_time.tv_nsec) / 1e9;

    uint64_t total_packets = atomic_load(&g_stats.total_packets);
    uint64_t total_bytes = atomic_load(&g_stats.total_bytes);
    uint64_t kernel_drops = atomic_load(&g_stats.kernel_drops);

    if (!cfg->quiet) {
        if (cfg->show_pcp_stats) {
            printf("─────────┴──────────────┴────────────┴────────────┴────────┴───────────────────────────────────────────────────────────────────\n\n");
        } else {
            printf("─────────┴──────────────┴────────────┴────────────┴────────┴────────────┴────────────\n\n");
        }

        printf("Summary:\n");
        printf("  Duration:       %.2f seconds\n", total_time);
        printf("  Total Packets:  %lu\n", total_packets);
        printf("  Total Data:     %.3f GB\n", total_bytes / (1024.0 * 1024.0 * 1024.0));
        printf("  Avg Rate:       %.0f pps\n", total_packets / total_time);
        printf("  Avg Throughput: %.3f Gbps\n", (total_bytes * 8.0) / (total_time * 1e9));
        printf("  Kernel Drops:   %lu (SO_RXQ_OVFL)\n", kernel_drops);

        /* VLAN/PCP breakdown */
        uint64_t vlan_pkts = atomic_load(&g_stats.vlan_packets);
        uint64_t nonvlan_pkts = atomic_load(&g_stats.non_vlan_packets);
        printf("\n  VLAN Packets:   %lu (%.1f%%)\n", vlan_pkts,
               total_packets > 0 ? 100.0 * vlan_pkts / total_packets : 0);
        printf("  Non-VLAN:       %lu (%.1f%%)\n", nonvlan_pkts,
               total_packets > 0 ? 100.0 * nonvlan_pkts / total_packets : 0);

        /* PCP distribution with per-PCP sequence tracking */
        if (vlan_pkts > 0) {
            printf("\n  PCP Distribution:\n");
            for (int p = 0; p < MAX_PCP; p++) {
                uint64_t pcp_pkts = atomic_load(&g_stats.pcp[p].packets);
                if (pcp_pkts > 0) {
                    uint64_t pcp_bytes = atomic_load(&g_stats.pcp[p].bytes);
                    uint64_t pcp_seq_err = atomic_load(&g_stats.pcp[p].seq_errors);
                    uint64_t pcp_seq_dup = atomic_load(&g_stats.pcp[p].seq_duplicates);
                    printf("    PCP %d: %lu pkts (%.1f%%), %.2f Mbps avg",
                           p, pcp_pkts,
                           100.0 * pcp_pkts / vlan_pkts,
                           (pcp_bytes * 8.0) / (total_time * 1e6));
                    if (cfg->check_seq && (pcp_seq_err > 0 || pcp_seq_dup > 0)) {
                        printf(" [seq_err:%lu dup:%lu]", pcp_seq_err, pcp_seq_dup);
                    }
                    printf("\n");
                }
            }
        }

        /* Global sequence analysis (for non-VLAN traffic) */
        if (cfg->check_seq && atomic_load(&g_stats.seq_started)) {
            uint64_t seq_errors = atomic_load(&g_stats.seq_errors);
            uint64_t seq_dups = atomic_load(&g_stats.seq_duplicates);
            uint32_t first = atomic_load(&g_stats.first_seq);
            uint32_t last = atomic_load(&g_stats.last_seq);
            uint32_t seq_range = last - first + 1;
            uint64_t received = nonvlan_pkts - seq_dups;

            printf("\n  Sequence Analysis (non-VLAN):\n");
            printf("    First seq:    %u\n", first);
            printf("    Last seq:     %u\n", last);
            printf("    Out-of-order: %lu\n", seq_errors);
            printf("    Duplicates:   %lu\n", seq_dups);

            /* Loss estimate: only meaningful for single-worker + contiguous seq
             * Skip if kernel_drops > 0 (receiver bottleneck makes estimate meaningless) */
            if (kernel_drops == 0 && seq_range > 0 && seq_range > received &&
                seq_range <= received * 2) {
                int64_t lost = (int64_t)seq_range - (int64_t)received;
                double loss_pct = lost * 100.0 / seq_range;
                printf("    Lost (est):   %ld (%.2f%%) - assumes contiguous seq\n", lost, loss_pct);
            }
        }

        /* Latency stats */
        uint64_t lat_cnt = atomic_load(&g_stats.latency_count);
        if (cfg->measure_latency && lat_cnt > 0) {
            uint64_t lat_sum = atomic_load(&g_stats.latency_sum);
            double avg_lat = (double)lat_sum / lat_cnt / 1000.0;
            printf("\n  Latency (us) [same-machine only]:\n");
            if (kernel_drops > 0) {
                printf("    ⚠ drops > 0, latency may be inflated\n");
            }
            printf("    Min: %.1f\n", atomic_load(&g_stats.latency_min) / 1000.0);
            printf("    Avg: %.1f\n", avg_lat);
            printf("    Max: %.1f\n", atomic_load(&g_stats.latency_max) / 1000.0);
        }

        /* Inter-arrival time */
        uint64_t iat_cnt = atomic_load(&g_stats.iat_count);
        if (iat_cnt > 0) {
            uint64_t iat_s = atomic_load(&g_stats.iat_sum);
            double avg_iat = (double)iat_s / iat_cnt / 1000.0;
            printf("\n  Inter-arrival Time (us):\n");
            printf("    Min: %.1f\n", atomic_load(&g_stats.iat_min) / 1000.0);
            printf("    Avg: %.1f\n", avg_iat);
            printf("    Max: %.1f\n", atomic_load(&g_stats.iat_max) / 1000.0);
        }

        printf("═══════════════════════════════════════════════════════════════════════════════════════════════════════════════\n");
    }

    return NULL;
}

/*============================================================================
 * Usage
 *============================================================================*/

static void print_usage(const char *prog) {
    printf("\n");
    printf("rxcap v%s - Traffic Capture\n", VERSION);
    printf("Companion tool for txgen - traffic capture & analysis\n");
    printf("\n");
    printf("Usage: %s [options] <interface>\n", prog);
    printf("\n");
    printf("Filter:\n");
    printf("  --vlan VID               Filter by VLAN ID\n");
    printf("  --pcp NUM                Filter by PCP (0-7)\n");
    printf("\n");
    printf("Capture:\n");
    printf("  --duration SEC           Capture duration (0=infinite)\n");
    printf("  --batch NUM              Batch size (default: 256)\n");
    printf("\n");
    printf("Analysis:\n");
    printf("  --seq                    Track sequence numbers\n");
    printf("  --seq-only               Only count packets with seq header (filter noise)\n");
    printf("  --latency                Measure latency (requires txgen --timestamp)\n");
    printf("  --pcp-stats              Show per-PCP statistics\n");
    printf("\n");
    printf("Performance:\n");
    printf("  --affinity[=CPU]         Pin RX thread to CPU core (default: 0)\n");
    printf("\n");
    printf("Output:\n");
    printf("  --csv FILE               Write CSV output (standardized schema)\n");
    printf("  --pcap FILE              Write pcap file (Wireshark compatible)\n");
    printf("  -q, --quiet              Quiet mode\n");
    printf("  -v, --verbose            Verbose output\n");
    printf("  -h, --help               Show help\n");
    printf("  --version                Show version\n");
    printf("\n");
    printf("Clock Policy:\n");
    printf("  - Uses CLOCK_MONOTONIC_RAW for latency measurement\n");
    printf("  - txgen must also use --timestamp for latency to work\n");
    printf("  - Both tools must run on the same machine for accurate latency\n");
    printf("\n");
    printf("Protocol Support:\n");
    printf("  - IPv4/IPv6 UDP packets with seq/timestamp parsing\n");
    printf("  - IPv6: UDP must follow IPv6 header directly (no extension headers)\n");
    printf("  - VLAN: 802.1Q (0x8100), QinQ (0x88a8), 802.1ad (0x9100)\n");
    printf("\n");
    printf("Drop Detection:\n");
    printf("  - Uses SO_RXQ_OVFL to detect kernel/socket drops\n");
    printf("  - Drops shown in real-time stats and summary\n");
    printf("  - Non-zero drops indicate receiver bottleneck\n");
    printf("\n");
    printf("CSV Schema:\n");
    printf("  time_s, total_pkts, total_pps, total_mbps, drops,\n");
    printf("  pcp0_pkts..pcp7_pkts,\n");
    printf("  latency_min_ns, latency_avg_ns, latency_max_ns,\n");
    printf("  iat_min_ns, iat_avg_ns, iat_max_ns\n");
    printf("\n");
    printf("Examples:\n");
    printf("  # Capture all traffic on eth0 for 60 seconds\n");
    printf("  sudo %s eth0 --duration 60\n", prog);
    printf("\n");
    printf("  # Capture VLAN 100 traffic with PCP stats and CPU pinning\n");
    printf("  sudo %s eth0 --vlan 100 --pcp-stats --affinity=2\n", prog);
    printf("\n");
    printf("  # Full analysis with txgen\n");
    printf("  # Terminal 1 (RX):  sudo %s eth1 --vlan 100 --seq --latency --pcp-stats --csv results.csv\n", prog);
    printf("  # Terminal 2 (TX):  sudo txgen eth0 -B IP -b MAC --multi-tc 0-7:100 --seq --timestamp\n");
    printf("\n");
}

/*============================================================================
 * Main
 *============================================================================*/

int main(int argc, char *argv[]) {
    /* Default configuration */
    memset(&g_config, 0, sizeof(g_config));
    g_config.batch_size = DEFAULT_BATCH_SIZE;

    static struct option long_options[] = {
        {"vlan",      required_argument, 0, 1001},
        {"pcp",       required_argument, 0, 1002},
        {"duration",  required_argument, 0, 1003},
        {"batch",     required_argument, 0, 1004},
        {"seq",       no_argument,       0, 1005},
        {"latency",   no_argument,       0, 1006},
        {"pcp-stats", no_argument,       0, 1007},
        {"csv",       required_argument, 0, 1008},
        {"pcap",      required_argument, 0, 1011},
        {"affinity",  optional_argument, 0, 1009},
        {"seq-only", no_argument,       0, 1010},
        {"quiet",     no_argument,       0, 'q'},
        {"verbose",   no_argument,       0, 'v'},
        {"help",      no_argument,       0, 'h'},
        {"version",   no_argument,       0, 1000},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "qvh", long_options, NULL)) != -1) {
        switch (opt) {
            case 1000: printf("rxcap v%s\n", VERSION); return 0;
            case 1010: g_config.seq_only = 1; break;
            case 1001:
                g_config.filter_vlan = 1;
                g_config.vlan_id = atoi(optarg) & 0xfff;
                break;
            case 1002:
                g_config.filter_pcp = 1;
                g_config.pcp = atoi(optarg) & 0x7;
                break;
            case 1003: g_config.duration = atoi(optarg); break;
            case 1004: g_config.batch_size = atoi(optarg); break;
            case 1005: g_config.check_seq = 1; break;
            case 1006: g_config.measure_latency = 1; break;
            case 1007: g_config.show_pcp_stats = 1; break;
            case 1008:
                strncpy(g_config.csv_file, optarg, sizeof(g_config.csv_file) - 1);
                break;
            case 1011:
                strncpy(g_config.pcap_file, optarg, sizeof(g_config.pcap_file) - 1);
                break;
            case 1009:
                g_config.use_affinity = 1;
                g_config.affinity_cpu = optarg ? atoi(optarg) : 0;
                break;
            case 'q': g_config.quiet = 1; break;
            case 'v': g_config.verbose = 1; break;
            case 'h': print_usage(argv[0]); return 0;
            default: print_usage(argv[0]); return 1;
        }
    }

    if (optind < argc) {
        strncpy(g_config.interface, argv[optind], IFNAMSIZ - 1);
    }

    /* Validation */
    if (strlen(g_config.interface) == 0) {
        fprintf(stderr, "Error: Interface required\n");
        return 1;
    }

    if (geteuid() != 0) {
        fprintf(stderr, "Error: Root privileges required\n");
        return 1;
    }

    /* Open CSV file - standardized schema */
    if (strlen(g_config.csv_file) > 0) {
        g_csv_fp = fopen(g_config.csv_file, "w");
        if (g_csv_fp) {
            fprintf(g_csv_fp, "time_s,total_pkts,total_pps,total_mbps,drops");
            for (int p = 0; p < MAX_PCP; p++) {
                fprintf(g_csv_fp, ",pcp%d_pkts", p);
            }
            fprintf(g_csv_fp, ",latency_min_ns,latency_avg_ns,latency_max_ns");
            fprintf(g_csv_fp, ",iat_min_ns,iat_avg_ns,iat_max_ns\n");
        }
    }

    /* Open pcap file */
    if (strlen(g_config.pcap_file) > 0) {
        if (pcap_open(g_config.pcap_file) < 0) {
            fprintf(stderr, "Failed to open pcap file: %s\n", g_config.pcap_file);
        } else {
            fprintf(stderr, "Warning: PCAP enabled - may cause drops at high rates (>5Gbps)\n");
        }
    }

    /* Initialize */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* Explicit atomic init (safe for re-run, library use, or unit tests) */
    atomic_store(&g_stats.total_packets, 0);
    atomic_store(&g_stats.total_bytes, 0);
    atomic_store(&g_stats.vlan_packets, 0);
    atomic_store(&g_stats.non_vlan_packets, 0);
    atomic_store(&g_stats.kernel_drops, 0);
    atomic_store(&g_stats.seq_errors, 0);
    atomic_store(&g_stats.seq_duplicates, 0);
    atomic_store(&g_stats.seq_started, 0);
    atomic_store(&g_stats.first_seq, 0);
    atomic_store(&g_stats.last_seq, 0);
    atomic_store(&g_stats.latency_sum, 0);
    atomic_store(&g_stats.latency_count, 0);
    atomic_store(&g_stats.latency_min, 0);
    atomic_store(&g_stats.latency_max, 0);
    atomic_store(&g_stats.iat_sum, 0);
    atomic_store(&g_stats.iat_count, 0);
    atomic_store(&g_stats.iat_min, 0);
    atomic_store(&g_stats.iat_max, 0);
    g_stats.last_arrival_ns = 0;
    for (int p = 0; p < MAX_PCP; p++) {
        atomic_store(&g_stats.pcp[p].packets, 0);
        atomic_store(&g_stats.pcp[p].bytes, 0);
        atomic_store(&g_stats.pcp[p].seq_errors, 0);
        atomic_store(&g_stats.pcp[p].seq_duplicates, 0);
        g_stats.pcp[p].last_seq = 0;
    }

    clock_gettime(CLOCK_MONOTONIC, &g_start_time);

    /* Start RX thread */
    if (pthread_create(&g_rx_thread, NULL, rx_thread, &g_config) != 0) {
        fprintf(stderr, "Failed to create RX thread\n");
        return 1;
    }

    /* Start stats thread */
    pthread_create(&g_stats_thread, NULL, stats_thread, &g_config);

    /* Wait for completion */
    pthread_join(g_stats_thread, NULL);
    pthread_join(g_rx_thread, NULL);

    if (g_csv_fp) fclose(g_csv_fp);
    if (g_pcap_fp) {
        fclose(g_pcap_fp);
        printf("  Pcap saved: %s\n", g_config.pcap_file);
    }

    return 0;
}
