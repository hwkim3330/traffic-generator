/*
 * tsnrecv - High-Performance TSN Traffic Receiver v1.3.0
 * Companion tool for tsngen - measures TSN traffic characteristics
 *
 * Copyright (C) 2025
 *
 * Features:
 * - recvmmsg() batch receive for high-speed capture
 * - Per-PCP/TC statistics for TSN analysis
 * - VLAN tag parsing (PCP, DEI, VID)
 * - Inter-arrival time measurement
 * - Sequence number tracking
 * - CSV export for analysis
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
 * TSN Payload Header (inline)
 *============================================================================*/
#define TSN_PAYLOAD_MAGIC       0x54534E31
#define TSN_PAYLOAD_VERSION     1
#define TSN_PAYLOAD_HDR_SIZE    24
#define TSN_LEGACY_HDR_SIZE     12
#define TSN_FLAG_SEQ            0x01
#define TSN_FLAG_TIMESTAMP      0x02
#define TSN_FLAG_FLOW_ID        0x04

#pragma pack(push, 1)
typedef struct {
    uint32_t magic;
    uint8_t  version;
    uint8_t  flags;
    uint8_t  flow_id;
    uint8_t  reserved;
    uint32_t seq_num;
    uint64_t timestamp;
    uint32_t payload_len;
} tsn_payload_hdr_t;
#pragma pack(pop)

#define TSN_HDR_HAS_SEQ(hdr)       ((hdr)->flags & TSN_FLAG_SEQ)
#define TSN_HDR_HAS_TIMESTAMP(hdr) ((hdr)->flags & TSN_FLAG_TIMESTAMP)
#define TSN_HDR_HAS_FLOW_ID(hdr)   ((hdr)->flags & TSN_FLAG_FLOW_ID)

static inline int tsn_is_new_format(const void *payload, size_t len) {
    if (len < sizeof(uint32_t)) return 0;
    uint32_t m;
    memcpy(&m, payload, sizeof(m));
    return (m == htonl(TSN_PAYLOAD_MAGIC));
}

/* SO_RXQ_OVFL for drop detection (if not defined) */
#ifndef SO_RXQ_OVFL
#define SO_RXQ_OVFL 40
#endif

/*============================================================================
 * Constants
 *============================================================================*/

#define VERSION "1.3.1"
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

    /* Options */
    int duration;
    int batch_size;
    int check_seq;
    int measure_latency;

    /* Output */
    char csv_file[256];
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

    /* Global sequence tracking (for single-TC mode) */
    atomic_uint_fast64_t seq_errors;
    atomic_uint_fast64_t seq_duplicates;
    uint32_t last_seq;

    /* Latency (if timestamp in packet) - uses CLOCK_MONOTONIC_RAW */
    uint64_t latency_sum;
    uint64_t latency_count;
    uint64_t latency_min;
    uint64_t latency_max;

    /* Inter-arrival time */
    uint64_t last_arrival_ns;
    uint64_t iat_sum;
    uint64_t iat_count;
    uint64_t iat_min;
    uint64_t iat_max;
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
 * - tsngen must also use CLOCK_MONOTONIC_RAW for accurate latency
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
 * TSN Payload Header formats:
 *
 * New format (v1, 24 bytes): Magic + version + flags + flow_id + seq + timestamp + len
 * Legacy format (12 bytes): seq (4) + timestamp (8)
 *
 * TSN payload header definitions are inlined above.
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

    /* TSN header fields */
    int new_format;         /* 1 = new 24-byte format, 0 = legacy */
    uint8_t flow_id;        /* Flow ID from new header (or derived from PCP) */
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

    /* Check for VLAN tags (single or QinQ) */
    while ((ethertype == 0x8100 || ethertype == 0x88a8) && offset + 4 <= len) {
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

    /* Try to extract TSN header from UDP payload */
    if (ethertype == 0x0800 && len >= offset + 20 + 8) {
        int ip_offset = offset;
        int ihl = (buf[ip_offset] & 0x0F) * 4;
        uint8_t ip_proto = buf[ip_offset + 9];

        if (ip_proto == 17 && len >= ip_offset + ihl + 8) {  /* UDP */
            int udp_offset = ip_offset + ihl;
            int payload_start = udp_offset + 8;
            int payload_len = len - payload_start;

            /* Check for new TSN header format (24 bytes, magic = "TSN1") */
            if (payload_len >= TSN_PAYLOAD_HDR_SIZE &&
                tsn_is_new_format(buf + payload_start, payload_len)) {

                const tsn_payload_hdr_t *hdr = (const tsn_payload_hdr_t *)(buf + payload_start);
                pkt->new_format = 1;

                if (TSN_HDR_HAS_FLOW_ID(hdr)) {
                    pkt->flow_id = hdr->flow_id;
                } else {
                    /* Default: use PCP as flow_id */
                    pkt->flow_id = pkt->has_vlan ? pkt->pcp : 0;
                }

                if (TSN_HDR_HAS_SEQ(hdr)) {
                    pkt->seq_num = ntohl(hdr->seq_num);
                    pkt->has_seq = 1;
                }

                if (TSN_HDR_HAS_TIMESTAMP(hdr)) {
                    pkt->timestamp = hdr->timestamp;
                    pkt->has_timestamp = 1;
                }
            }
            /* Legacy format (12 bytes): seq(4) + timestamp(8) */
            else if (payload_len >= TSN_LEGACY_HDR_SIZE) {
                pkt->new_format = 0;
                pkt->flow_id = pkt->has_vlan ? pkt->pcp : 0;

                /* First 4 bytes: sequence number (network order) */
                memcpy(&pkt->seq_num, buf + payload_start, 4);
                pkt->seq_num = ntohl(pkt->seq_num);
                pkt->has_seq = 1;

                /* Next 8 bytes: timestamp */
                memcpy(&pkt->timestamp, buf + payload_start + 4, 8);
                pkt->has_timestamp = 1;
            }
        }
    }

    return 0;
}

/*============================================================================
 * RX Thread
 *============================================================================*/

static void *rx_thread(void *arg) {
    config_t *cfg = (config_t *)arg;

    /* CPU affinity */
    if (cfg->use_affinity) {
        cpu_set_t cpuset;
        CPU_ZERO(&cpuset);
        int cpu = cfg->affinity_cpu >= 0 ? cfg->affinity_cpu : 0;
        CPU_SET(cpu % sysconf(_SC_NPROCESSORS_ONLN), &cpuset);
        pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset);
    }

    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        perror("socket");
        return NULL;
    }

    /* Increase receive buffer */
    int rcvbuf = 64 * 1024 * 1024;
    setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

    /* Enable SO_RXQ_OVFL to track kernel drops */
    int ovfl_enable = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_RXQ_OVFL, &ovfl_enable, sizeof(ovfl_enable)) < 0) {
        if (cfg->verbose) {
            fprintf(stderr, "Warning: SO_RXQ_OVFL not supported, drop counting disabled\n");
        }
    }

    int ifindex = get_if_index(cfg->interface);
    if (ifindex < 0) {
        fprintf(stderr, "Failed to get interface index for %s\n", cfg->interface);
        close(sock);
        return NULL;
    }

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);

    if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("bind");
        close(sock);
        return NULL;
    }

    /* Set promiscuous mode */
    struct packet_mreq mreq;
    memset(&mreq, 0, sizeof(mreq));
    mreq.mr_ifindex = ifindex;
    mreq.mr_type = PACKET_MR_PROMISC;
    setsockopt(sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq));

    /* Allocate batch receive buffers */
    int batch = cfg->batch_size;
    uint8_t **buffers = malloc(batch * sizeof(uint8_t *));
    struct mmsghdr *msgs = calloc(batch, sizeof(struct mmsghdr));
    struct iovec *iovecs = calloc(batch, sizeof(struct iovec));

    /* Control message buffer for SO_RXQ_OVFL */
    size_t cmsg_size = CMSG_SPACE(sizeof(uint32_t));
    uint8_t **cmsg_bufs = malloc(batch * sizeof(uint8_t *));

    for (int i = 0; i < batch; i++) {
        buffers[i] = aligned_alloc(64, MAX_PACKET_SIZE_ALIGNED);
        cmsg_bufs[i] = malloc(cmsg_size);
        iovecs[i].iov_base = buffers[i];
        iovecs[i].iov_len = MAX_PACKET_SIZE;
        msgs[i].msg_hdr.msg_iov = &iovecs[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
        msgs[i].msg_hdr.msg_control = cmsg_bufs[i];
        msgs[i].msg_hdr.msg_controllen = cmsg_size;
    }

    parsed_packet_t pkt;
    uint64_t local_packets = 0;
    uint64_t local_bytes = 0;
    uint64_t last_drop_count = 0;

    while (g_running) {
        /* Reset control message lengths */
        for (int i = 0; i < batch; i++) {
            msgs[i].msg_hdr.msg_controllen = cmsg_size;
        }

        int received = recvmmsg(sock, msgs, batch, MSG_DONTWAIT, NULL);

        if (received > 0) {
            uint64_t now_ns = get_time_ns();

            for (int i = 0; i < received; i++) {
                int len = msgs[i].msg_len;
                uint8_t *buf = buffers[i];

                /* Check for dropped packets from SO_RXQ_OVFL */
                struct cmsghdr *cmsg;
                for (cmsg = CMSG_FIRSTHDR(&msgs[i].msg_hdr); cmsg != NULL;
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

                /* Apply filters */
                if (cfg->filter_vlan && (!pkt.has_vlan || pkt.vlan_id != cfg->vlan_id)) {
                    continue;
                }
                if (cfg->filter_pcp && (!pkt.has_vlan || pkt.pcp != cfg->pcp)) {
                    continue;
                }

                local_packets++;
                local_bytes += len;

                /* Update PCP stats */
                if (pkt.has_vlan) {
                    atomic_fetch_add(&g_stats.vlan_packets, 1);
                    atomic_fetch_add(&g_stats.pcp[pkt.pcp].packets, 1);
                    atomic_fetch_add(&g_stats.pcp[pkt.pcp].bytes, len);

                    /* Per-PCP sequence tracking (for Multi-TC mode) */
                    if (cfg->check_seq && pkt.has_seq) {
                        pcp_stats_t *pcp_stat = &g_stats.pcp[pkt.pcp];
                        if (pcp_stat->last_seq != 0) {
                            if (pkt.seq_num == pcp_stat->last_seq) {
                                atomic_fetch_add(&pcp_stat->seq_duplicates, 1);
                            } else if (pkt.seq_num != pcp_stat->last_seq + 1) {
                                atomic_fetch_add(&pcp_stat->seq_errors, 1);
                            }
                        }
                        pcp_stat->last_seq = pkt.seq_num;
                    }
                } else {
                    atomic_fetch_add(&g_stats.non_vlan_packets, 1);

                    /* Global sequence tracking (for non-VLAN mode) */
                    if (cfg->check_seq && pkt.has_seq) {
                        if (g_stats.last_seq != 0) {
                            if (pkt.seq_num == g_stats.last_seq) {
                                atomic_fetch_add(&g_stats.seq_duplicates, 1);
                            } else if (pkt.seq_num != g_stats.last_seq + 1) {
                                atomic_fetch_add(&g_stats.seq_errors, 1);
                            }
                        }
                        g_stats.last_seq = pkt.seq_num;
                    }
                }

                /* Latency measurement (if timestamp present) */
                if (cfg->measure_latency && pkt.has_timestamp) {
                    uint64_t latency = now_ns - pkt.timestamp;
                    g_stats.latency_sum += latency;
                    g_stats.latency_count++;
                    if (latency < g_stats.latency_min || g_stats.latency_min == 0) {
                        g_stats.latency_min = latency;
                    }
                    if (latency > g_stats.latency_max) {
                        g_stats.latency_max = latency;
                    }
                }

                /* Inter-arrival time */
                if (g_stats.last_arrival_ns > 0) {
                    uint64_t iat = now_ns - g_stats.last_arrival_ns;
                    g_stats.iat_sum += iat;
                    g_stats.iat_count++;
                    if (iat < g_stats.iat_min || g_stats.iat_min == 0) {
                        g_stats.iat_min = iat;
                    }
                    if (iat > g_stats.iat_max) {
                        g_stats.iat_max = iat;
                    }
                }
                g_stats.last_arrival_ns = now_ns;
            }

            atomic_fetch_add(&g_stats.total_packets, local_packets);
            atomic_fetch_add(&g_stats.total_bytes, local_bytes);
            local_packets = 0;
            local_bytes = 0;
        } else if (received < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
            if (g_running) perror("recvmmsg");
        }
    }

    /* Cleanup */
    for (int i = 0; i < batch; i++) {
        free(buffers[i]);
        free(cmsg_bufs[i]);
    }
    free(buffers);
    free(cmsg_bufs);
    free(msgs);
    free(iovecs);
    close(sock);

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
        printf(" tsnrecv v%s - TSN Traffic Receiver\n", VERSION);
        printf(" Interface: %s | Batch: %d", cfg->interface, cfg->batch_size);
        if (cfg->filter_vlan) printf(" | VLAN: %d", cfg->vlan_id);
        if (cfg->filter_pcp) printf(" | PCP: %d", cfg->pcp);
        if (cfg->use_affinity) printf(" | CPU: %d", cfg->affinity_cpu >= 0 ? cfg->affinity_cpu : 0);
        printf("\n");
        printf(" Clock: CLOCK_MONOTONIC_RAW (for latency measurement)\n");
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
            if (cfg->measure_latency && g_stats.latency_count > 0) {
                double lat_avg = (double)g_stats.latency_sum / g_stats.latency_count;
                fprintf(g_csv_fp, ",%lu,%.0f,%lu",
                        g_stats.latency_min, lat_avg, g_stats.latency_max);
            } else {
                fprintf(g_csv_fp, ",-1,-1,-1");
            }

            /* IAT: -1 if no data */
            if (g_stats.iat_count > 0) {
                double iat_avg = (double)g_stats.iat_sum / g_stats.iat_count;
                fprintf(g_csv_fp, ",%lu,%.0f,%lu\n",
                        g_stats.iat_min, iat_avg, g_stats.iat_max);
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
        if (cfg->check_seq && nonvlan_pkts > 0) {
            uint64_t seq_errors = atomic_load(&g_stats.seq_errors);
            uint64_t seq_dups = atomic_load(&g_stats.seq_duplicates);
            printf("\n  Sequence Analysis (non-VLAN):\n");
            printf("    Out-of-order: %lu\n", seq_errors);
            printf("    Duplicates:   %lu\n", seq_dups);
        }

        /* Latency stats */
        if (cfg->measure_latency && g_stats.latency_count > 0) {
            double avg_lat = (double)g_stats.latency_sum / g_stats.latency_count / 1000.0;
            printf("\n  Latency (us) [CLOCK_MONOTONIC_RAW]:\n");
            if (kernel_drops > 0) {
                printf("    ⚠ WARNING: drops > 0, latency may be inflated by RX backlog\n");
            }
            printf("    Min: %.1f\n", g_stats.latency_min / 1000.0);
            printf("    Avg: %.1f\n", avg_lat);
            printf("    Max: %.1f\n", g_stats.latency_max / 1000.0);
        }

        /* Inter-arrival time */
        if (g_stats.iat_count > 0) {
            double avg_iat = (double)g_stats.iat_sum / g_stats.iat_count / 1000.0;
            printf("\n  Inter-arrival Time (us):\n");
            printf("    Min: %.1f\n", g_stats.iat_min / 1000.0);
            printf("    Avg: %.1f\n", avg_iat);
            printf("    Max: %.1f\n", g_stats.iat_max / 1000.0);
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
    printf("tsnrecv v%s - TSN Traffic Receiver\n", VERSION);
    printf("Companion tool for tsngen - measures TSN traffic characteristics\n");
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
    printf("  --seq                    Track sequence numbers (per-PCP for VLAN traffic)\n");
    printf("  --latency                Measure latency (requires tsngen --timestamp)\n");
    printf("  --pcp-stats              Show per-PCP statistics\n");
    printf("\n");
    printf("Performance:\n");
    printf("  --affinity[=CPU]         Pin RX thread to CPU core (default: 0)\n");
    printf("\n");
    printf("Output:\n");
    printf("  --csv FILE               Write CSV output (standardized schema)\n");
    printf("  -q, --quiet              Quiet mode\n");
    printf("  -v, --verbose            Verbose output\n");
    printf("  -h, --help               Show help\n");
    printf("  --version                Show version\n");
    printf("\n");
    printf("Clock Policy:\n");
    printf("  - Uses CLOCK_MONOTONIC_RAW for latency measurement\n");
    printf("  - tsngen must also use --timestamp for latency to work\n");
    printf("  - Both tools must run on the same machine for accurate latency\n");
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
    printf("  # Full TSN analysis with tsngen\n");
    printf("  # Terminal 1 (RX):  sudo %s eth1 --vlan 100 --seq --latency --pcp-stats --csv results.csv\n", prog);
    printf("  # Terminal 2 (TX):  sudo tsngen eth0 -B IP -b MAC --multi-tc 0-7:100 --seq --timestamp\n");
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
        {"affinity",  optional_argument, 0, 1009},
        {"quiet",     no_argument,       0, 'q'},
        {"verbose",   no_argument,       0, 'v'},
        {"help",      no_argument,       0, 'h'},
        {"version",   no_argument,       0, 1000},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "qvh", long_options, NULL)) != -1) {
        switch (opt) {
            case 1000: printf("tsnrecv v%s\n", VERSION); return 0;
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

    /* Initialize */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    memset(&g_stats, 0, sizeof(g_stats));
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

    return 0;
}
