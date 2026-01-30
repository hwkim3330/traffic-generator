/*
 * trafgen - High-Performance Traffic Generator v1.3.0
 * Based on Mausezahn concepts, enhanced with modern Linux networking features
 *
 * Copyright (C) 2025
 * Original Mausezahn Copyright (C) 2008-2010 Herbert Haas (GPLv2)
 *
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License version 2 as published by the
 * Free Software Foundation.
 *
 * Features:
 * - sendmmsg() batch transmission for 10Gbps+ throughput
 * - Multi-threaded architecture
 * - Precise rate limiting with token bucket
 * - VLAN/QinQ, DSCP, TCP/UDP/ICMP support
 * - Burst mode, random payload, sequence numbers
 * - Statistics export to file
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
#include <ctype.h>
#include <math.h>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <netpacket/packet.h>
#include <linux/if_ether.h>

/*============================================================================
 * Constants
 *============================================================================*/

#define VERSION "1.3.0"
#define MAX_PACKET_SIZE 9000
#define DEFAULT_PACKET_SIZE 1472
#define DEFAULT_BATCH_SIZE 512
#define MAX_WORKERS 64
#define MAX_PAYLOAD_SIZE 8192
#define MAX_FLOWS 256
#define STATS_INTERVAL_US 1000000
#define TOKEN_BUCKET_INTERVAL_NS 1000000  /* 1ms */

/*============================================================================
 * Data Structures
 *============================================================================*/

typedef enum {
    PKT_ETH_RAW = 0,
    PKT_ARP,
    PKT_IP,
    PKT_ICMP,
    PKT_UDP,
    PKT_TCP,
    PKT_DNS,
    PKT_RTP
} packet_type_t;

typedef enum {
    PATTERN_CONSTANT = 0,
    PATTERN_BURST,
    PATTERN_RAMP,
    PATTERN_RANDOM
} traffic_pattern_t;

typedef enum {
    PAYLOAD_ZERO = 0,
    PAYLOAD_RANDOM,
    PAYLOAD_INCREMENT,
    PAYLOAD_PATTERN,
    PAYLOAD_ASCII
} payload_type_t;

/* Global configuration */
typedef struct {
    char interface[IFNAMSIZ];

    /* Layer 2 */
    uint8_t eth_src[ETH_ALEN];
    uint8_t eth_dst[ETH_ALEN];
    uint16_t eth_type;
    int eth_src_rand;
    int eth_dst_rand;

    /* 802.1Q VLAN */
    int vlan_count;
    uint16_t vlan_id[8];
    uint8_t vlan_prio[8];   /* PCP: Priority Code Point (0-7) */
    uint8_t vlan_dei[8];    /* DEI: Drop Eligible Indicator (0-1) */

    /* Socket priority (for tc/qdisc integration) */
    int skb_priority;       /* SO_PRIORITY value */
    int use_skb_priority;

    /* Multi-TC mode */
    uint8_t multi_tc[8];    /* TC list to use */
    int multi_tc_count;     /* Number of TCs */
    uint16_t multi_tc_vlan; /* Base VLAN ID for multi-TC */

    /* Layer 3 */
    char src_ip[INET6_ADDRSTRLEN];
    char dst_ip[INET6_ADDRSTRLEN];
    uint32_t src_ip_start;
    uint32_t src_ip_end;
    uint32_t dst_ip_start;
    uint32_t dst_ip_end;
    int ip_src_rand;
    int ip_src_range;
    int ip_dst_range;
    uint8_t dscp;
    uint8_t ttl;
    int ipv6_mode;
    int df_flag;  /* Don't Fragment */

    /* Layer 4 */
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t src_port_start;
    uint16_t src_port_end;
    uint16_t dst_port_start;
    uint16_t dst_port_end;
    int src_port_range;
    int dst_port_range;
    uint8_t tcp_flags;
    uint32_t tcp_seq;
    uint32_t tcp_ack;
    uint16_t tcp_window;

    /* Packet */
    packet_type_t pkt_type;
    int packet_size;
    int packet_size_min;
    int packet_size_max;
    int packet_size_rand;
    uint8_t payload[MAX_PAYLOAD_SIZE];
    int payload_size;
    payload_type_t payload_type;
    char payload_pattern[256];

    /* Traffic control */
    uint64_t count;
    double rate_mbps;
    double rate_pps;      /* Packets per second */
    int duration;
    int num_workers;
    int batch_size;
    uint64_t delay_ns;    /* Inter-packet delay in nanoseconds */
    int delay_per_packet; /* Apply delay per packet (vs per batch) */

    /* Traffic pattern */
    traffic_pattern_t pattern;
    double burst_rate;    /* Mbps during burst */
    double burst_duration; /* seconds */
    double burst_interval; /* seconds between bursts */
    double ramp_start;    /* Mbps */
    double ramp_end;      /* Mbps */
    double ramp_step;     /* seconds per step */

    /* Multi-flow */
    int num_flows;

    /* Sequence & Timestamp */
    int add_seq_num;
    int add_timestamp;

    /* Statistics */
    char stats_file[256];
    int stats_interval;

    /* Flags */
    int verbose;
    int quiet;
    int simulation;

    /* Checksum */
    int calc_ip_csum;
    int calc_l4_csum;
} config_t;

/* Worker statistics */
typedef struct {
    atomic_uint_fast64_t packets_sent;
    atomic_uint_fast64_t bytes_sent;
    atomic_uint_fast64_t errors;
} worker_stats_t;

/* Token bucket for rate limiting */
typedef struct {
    double tokens;
    double max_tokens;
    double tokens_per_ns;
    struct timespec last_update;
    pthread_mutex_t lock;
} token_bucket_t;

/* Worker context */
typedef struct {
    int id;
    int socket_fd;
    config_t *cfg;
    worker_stats_t *stats;
    token_bucket_t *bucket;
    uint32_t seq_num;
    uint32_t flow_idx;
} worker_ctx_t;

/*============================================================================
 * Globals
 *============================================================================*/

static volatile sig_atomic_t g_running = 1;
static config_t g_config;
static worker_stats_t g_stats[MAX_WORKERS];
static pthread_t g_workers[MAX_WORKERS];
static pthread_t g_stats_thread;
static struct timespec g_start_time;
static token_bucket_t g_bucket;
static FILE *g_stats_fp = NULL;

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

static inline uint64_t get_time_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static int str2mac(const char *str, uint8_t *mac) {
    int values[6];
    if (sscanf(str, "%x:%x:%x:%x:%x:%x",
               &values[0], &values[1], &values[2],
               &values[3], &values[4], &values[5]) != 6) {
        return -1;
    }
    for (int i = 0; i < 6; i++) {
        mac[i] = (uint8_t)values[i];
    }
    return 0;
}

static int get_if_mac(const char *ifname, uint8_t *mac) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        close(fd);
        return -1;
    }

    memcpy(mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
    close(fd);
    return 0;
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

static int get_if_ip(const char *ifname, char *ip, size_t len) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    ifr.ifr_addr.sa_family = AF_INET;

    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
        close(fd);
        return -1;
    }

    struct sockaddr_in *addr = (struct sockaddr_in *)&ifr.ifr_addr;
    inet_ntop(AF_INET, &addr->sin_addr, ip, len);
    close(fd);
    return 0;
}

static uint16_t checksum(void *vdata, size_t length) {
    uint32_t sum = 0;
    uint16_t *data = (uint16_t *)vdata;

    while (length > 1) {
        sum += *data++;
        length -= 2;
    }

    if (length > 0) {
        sum += *(uint8_t *)data;
    }

    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    return ~sum;
}

/* TCP/UDP pseudo header checksum */
static uint16_t tcp_udp_checksum(uint32_t saddr, uint32_t daddr,
                                  uint8_t proto, void *data, size_t len) {
    uint32_t sum = 0;

    /* Pseudo header */
    sum += (saddr >> 16) & 0xFFFF;
    sum += saddr & 0xFFFF;
    sum += (daddr >> 16) & 0xFFFF;
    sum += daddr & 0xFFFF;
    sum += htons(proto);
    sum += htons(len);

    /* Data */
    uint16_t *ptr = (uint16_t *)data;
    while (len > 1) {
        sum += *ptr++;
        len -= 2;
    }
    if (len > 0) {
        sum += *(uint8_t *)ptr;
    }

    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    return ~sum;
}

static void rand_mac(uint8_t *mac) {
    for (int i = 0; i < 6; i++) {
        mac[i] = rand() & 0xff;
    }
    mac[0] &= 0xfe;
}

static uint32_t rand_ip_in_range(uint32_t start, uint32_t end) {
    if (start == end) return start;
    return start + (rand() % (end - start + 1));
}

static uint16_t rand_port_in_range(uint16_t start, uint16_t end) {
    if (start == end) return start;
    return start + (rand() % (end - start + 1));
}

/*============================================================================
 * Token Bucket Rate Limiter
 *============================================================================*/

static void token_bucket_init(token_bucket_t *tb, double rate_mbps, int batch_size, int pkt_size) {
    pthread_mutex_init(&tb->lock, NULL);

    if (rate_mbps <= 0) {
        tb->tokens_per_ns = 0;  /* Unlimited */
        tb->max_tokens = 1e18;
        tb->tokens = tb->max_tokens;
    } else {
        double bytes_per_sec = rate_mbps * 1000000.0 / 8.0;
        tb->tokens_per_ns = bytes_per_sec / 1e9;
        tb->max_tokens = (double)batch_size * pkt_size * 2;
        tb->tokens = tb->max_tokens;
    }

    clock_gettime(CLOCK_MONOTONIC, &tb->last_update);
}

static int token_bucket_consume(token_bucket_t *tb, size_t bytes) {
    if (tb->tokens_per_ns <= 0) return 1;  /* Unlimited */

    pthread_mutex_lock(&tb->lock);

    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);

    double elapsed_ns = (now.tv_sec - tb->last_update.tv_sec) * 1e9 +
                       (now.tv_nsec - tb->last_update.tv_nsec);

    tb->tokens += elapsed_ns * tb->tokens_per_ns;
    if (tb->tokens > tb->max_tokens) {
        tb->tokens = tb->max_tokens;
    }
    tb->last_update = now;

    if (tb->tokens >= (double)bytes) {
        tb->tokens -= (double)bytes;
        pthread_mutex_unlock(&tb->lock);
        return 1;
    }

    /* Calculate sleep time */
    double needed = (double)bytes - tb->tokens;
    double sleep_ns = needed / tb->tokens_per_ns;

    pthread_mutex_unlock(&tb->lock);

    if (sleep_ns > 100) {
        struct timespec ts = {
            .tv_sec = (time_t)(sleep_ns / 1e9),
            .tv_nsec = (long)((uint64_t)sleep_ns % (uint64_t)1e9)
        };
        nanosleep(&ts, NULL);
    }

    return 1;
}

/*============================================================================
 * Packet Building Functions
 *============================================================================*/

static int build_eth_header(uint8_t *buf, config_t *cfg) {
    int offset = 0;

    memcpy(buf + offset, cfg->eth_dst, ETH_ALEN);
    offset += ETH_ALEN;

    memcpy(buf + offset, cfg->eth_src, ETH_ALEN);
    offset += ETH_ALEN;

    /* VLAN tags (802.1Q) */
    for (int i = 0; i < cfg->vlan_count; i++) {
        buf[offset++] = 0x81;
        buf[offset++] = 0x00;
        /* TCI: PCP(3 bits) | DEI(1 bit) | VID(12 bits) */
        uint16_t tci = (cfg->vlan_prio[i] << 13) |
                       ((cfg->vlan_dei[i] & 0x1) << 12) |
                       (cfg->vlan_id[i] & 0xfff);
        buf[offset++] = (tci >> 8) & 0xff;
        buf[offset++] = tci & 0xff;
    }

    buf[offset++] = (cfg->eth_type >> 8) & 0xff;
    buf[offset++] = cfg->eth_type & 0xff;

    return offset;
}

static int build_ip_header(uint8_t *buf, config_t *cfg, int payload_len,
                           uint32_t saddr, uint32_t daddr) {
    struct iphdr *ip = (struct iphdr *)buf;

    ip->version = 4;
    ip->ihl = 5;
    ip->tos = cfg->dscp << 2;
    ip->tot_len = htons(sizeof(struct iphdr) + payload_len);
    ip->id = htons(rand() & 0xffff);
    ip->frag_off = cfg->df_flag ? htons(0x4000) : 0;
    ip->ttl = cfg->ttl;
    ip->protocol = (cfg->pkt_type == PKT_UDP) ? IPPROTO_UDP :
                   (cfg->pkt_type == PKT_TCP) ? IPPROTO_TCP :
                   (cfg->pkt_type == PKT_ICMP) ? IPPROTO_ICMP : 0;
    ip->check = 0;
    ip->saddr = saddr;
    ip->daddr = daddr;

    if (cfg->calc_ip_csum) {
        ip->check = checksum(ip, sizeof(struct iphdr));
    }

    return sizeof(struct iphdr);
}

static int build_udp_packet(uint8_t *buf, config_t *cfg, int payload_len,
                            uint16_t sport, uint16_t dport,
                            uint32_t saddr, uint32_t daddr) {
    struct udphdr *udp = (struct udphdr *)buf;

    udp->source = htons(sport);
    udp->dest = htons(dport);
    udp->len = htons(sizeof(struct udphdr) + payload_len);
    udp->check = 0;

    if (cfg->calc_l4_csum) {
        udp->check = tcp_udp_checksum(saddr, daddr, IPPROTO_UDP,
                                      udp, sizeof(struct udphdr) + payload_len);
    }

    return sizeof(struct udphdr);
}

static int build_tcp_packet(uint8_t *buf, config_t *cfg,
                            uint16_t sport, uint16_t dport,
                            uint32_t saddr, uint32_t daddr, uint32_t seq) {
    struct tcphdr *tcp = (struct tcphdr *)buf;

    memset(tcp, 0, sizeof(struct tcphdr));
    tcp->source = htons(sport);
    tcp->dest = htons(dport);
    tcp->seq = htonl(seq);
    tcp->ack_seq = htonl(cfg->tcp_ack);
    tcp->doff = 5;

    /* TCP flags */
    if (cfg->tcp_flags) {
        tcp->fin = (cfg->tcp_flags & 0x01) ? 1 : 0;
        tcp->syn = (cfg->tcp_flags & 0x02) ? 1 : 0;
        tcp->rst = (cfg->tcp_flags & 0x04) ? 1 : 0;
        tcp->psh = (cfg->tcp_flags & 0x08) ? 1 : 0;
        tcp->ack = (cfg->tcp_flags & 0x10) ? 1 : 0;
        tcp->urg = (cfg->tcp_flags & 0x20) ? 1 : 0;
    } else {
        tcp->syn = 1;
    }

    tcp->window = htons(cfg->tcp_window ? cfg->tcp_window : 65535);
    tcp->check = 0;
    tcp->urg_ptr = 0;

    if (cfg->calc_l4_csum) {
        tcp->check = tcp_udp_checksum(saddr, daddr, IPPROTO_TCP,
                                      tcp, sizeof(struct tcphdr));
    }

    return sizeof(struct tcphdr);
}

static void fill_payload(uint8_t *buf, int len, config_t *cfg, uint32_t seq) {
    switch (cfg->payload_type) {
        case PAYLOAD_ZERO:
            memset(buf, 0, len);
            break;
        case PAYLOAD_RANDOM:
            for (int i = 0; i < len; i++) {
                buf[i] = rand() & 0xff;
            }
            break;
        case PAYLOAD_INCREMENT:
            for (int i = 0; i < len; i++) {
                buf[i] = (uint8_t)(i & 0xff);
            }
            break;
        case PAYLOAD_PATTERN:
            {
                int plen = strlen(cfg->payload_pattern);
                if (plen > 0) {
                    for (int i = 0; i < len; i++) {
                        buf[i] = cfg->payload_pattern[i % plen];
                    }
                }
            }
            break;
        case PAYLOAD_ASCII:
            if (cfg->payload_size > 0) {
                int copy_len = (len < cfg->payload_size) ? len : cfg->payload_size;
                memcpy(buf, cfg->payload, copy_len);
                if (len > copy_len) {
                    memset(buf + copy_len, 0, len - copy_len);
                }
            }
            break;
    }

    /* Add sequence number at start if requested */
    if (cfg->add_seq_num && len >= 4) {
        uint32_t net_seq = htonl(seq);
        memcpy(buf, &net_seq, 4);
    }

    /* Add timestamp if requested */
    if (cfg->add_timestamp && len >= 12) {
        uint64_t ts = get_time_ns();
        memcpy(buf + 4, &ts, 8);
    }
}

static int build_packet(uint8_t *buf, config_t *cfg, worker_ctx_t *ctx) {
    int offset = 0;
    int pkt_size = cfg->packet_size;

    /* Random packet size if enabled */
    if (cfg->packet_size_rand && cfg->packet_size_min > 0 && cfg->packet_size_max > 0) {
        pkt_size = cfg->packet_size_min +
                   (rand() % (cfg->packet_size_max - cfg->packet_size_min + 1));
    }

    /* Randomize MAC if needed */
    if (cfg->eth_src_rand) rand_mac(cfg->eth_src);
    if (cfg->eth_dst_rand) rand_mac(cfg->eth_dst);

    /* Ethernet header */
    offset = build_eth_header(buf, cfg);

    if (cfg->pkt_type == PKT_ETH_RAW) {
        int payload_len = pkt_size - offset;
        if (payload_len > 0) {
            fill_payload(buf + offset, payload_len, cfg, ctx->seq_num++);
            offset += payload_len;
        }
    } else {
        /* Calculate addresses */
        uint32_t saddr, daddr;
        uint16_t sport, dport;

        if (cfg->ip_src_range) {
            saddr = htonl(rand_ip_in_range(cfg->src_ip_start, cfg->src_ip_end));
        } else if (cfg->ip_src_rand) {
            saddr = htonl(rand());
        } else {
            saddr = inet_addr(cfg->src_ip);
        }

        if (cfg->ip_dst_range) {
            daddr = htonl(rand_ip_in_range(cfg->dst_ip_start, cfg->dst_ip_end));
        } else {
            daddr = inet_addr(cfg->dst_ip);
        }

        if (cfg->src_port_range) {
            sport = rand_port_in_range(cfg->src_port_start, cfg->src_port_end);
        } else {
            sport = cfg->src_port + (ctx->id * 100) + (ctx->flow_idx % 100);
        }

        if (cfg->dst_port_range) {
            dport = rand_port_in_range(cfg->dst_port_start, cfg->dst_port_end);
        } else {
            dport = cfg->dst_port;
        }

        /* Header sizes */
        int ip_hdr_size = sizeof(struct iphdr);
        int l4_hdr_size = (cfg->pkt_type == PKT_UDP) ? sizeof(struct udphdr) :
                          (cfg->pkt_type == PKT_TCP) ? sizeof(struct tcphdr) : 0;
        int header_total = offset + ip_hdr_size + l4_hdr_size;
        int payload_len = pkt_size - header_total;
        if (payload_len < 0) payload_len = 0;

        /* IP header */
        int l4_total = l4_hdr_size + payload_len;
        offset += build_ip_header(buf + offset, cfg, l4_total, saddr, daddr);

        /* Transport layer */
        if (cfg->pkt_type == PKT_UDP) {
            offset += build_udp_packet(buf + offset, cfg, payload_len,
                                       sport, dport, saddr, daddr);
        } else if (cfg->pkt_type == PKT_TCP) {
            offset += build_tcp_packet(buf + offset, cfg, sport, dport,
                                       saddr, daddr, ctx->seq_num++);
        }

        /* Payload */
        if (payload_len > 0) {
            fill_payload(buf + offset, payload_len, cfg, ctx->seq_num);
            offset += payload_len;
        }
    }

    /* Ensure minimum frame size */
    if (offset < 60) {
        memset(buf + offset, 0, 60 - offset);
        offset = 60;
    }

    ctx->flow_idx++;
    return offset;
}

/*============================================================================
 * Worker Thread
 *============================================================================*/

static void *worker_thread(void *arg) {
    worker_ctx_t *ctx = (worker_ctx_t *)arg;
    config_t *cfg = ctx->cfg;
    worker_stats_t *stats = ctx->stats;

    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        perror("socket");
        return NULL;
    }

    int sndbuf = 64 * 1024 * 1024;
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));

    /* Set socket priority for tc/qdisc integration */
    if (cfg->use_skb_priority) {
        if (setsockopt(sock, SOL_SOCKET, SO_PRIORITY, &cfg->skb_priority, sizeof(cfg->skb_priority)) < 0) {
            perror("SO_PRIORITY");
        }
    }

    int ifindex = get_if_index(cfg->interface);
    if (ifindex < 0) {
        fprintf(stderr, "Failed to get interface index\n");
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

    ctx->socket_fd = sock;

    /* Pre-allocate packets */
    int batch = cfg->batch_size;
    uint8_t **packets = malloc(batch * sizeof(uint8_t *));
    int *pkt_sizes = malloc(batch * sizeof(int));

    for (int i = 0; i < batch; i++) {
        packets[i] = aligned_alloc(64, MAX_PACKET_SIZE);
        memset(packets[i], 0, MAX_PACKET_SIZE);
    }

    struct mmsghdr *msgs = calloc(batch, sizeof(struct mmsghdr));
    struct iovec *iovecs = calloc(batch, sizeof(struct iovec));

    uint64_t local_packets = 0;
    uint64_t local_bytes = 0;
    uint64_t local_errors = 0;
    struct timespec last_update;
    clock_gettime(CLOCK_MONOTONIC, &last_update);

    while (g_running) {
        /* Build batch of packets */
        size_t batch_bytes = 0;
        for (int i = 0; i < batch; i++) {
            pkt_sizes[i] = build_packet(packets[i], cfg, ctx);
            iovecs[i].iov_base = packets[i];
            iovecs[i].iov_len = pkt_sizes[i];
            msgs[i].msg_hdr.msg_iov = &iovecs[i];
            msgs[i].msg_hdr.msg_iovlen = 1;
            batch_bytes += pkt_sizes[i];
        }

        /* Rate limiting */
        token_bucket_consume(ctx->bucket, batch_bytes);

        /* Send with optional inter-packet delay */
        if (cfg->delay_ns > 0 && cfg->delay_per_packet) {
            /* Per-packet delay mode: send one at a time */
            struct timespec delay_ts = {
                .tv_sec = (time_t)(cfg->delay_ns / 1000000000ULL),
                .tv_nsec = (long)(cfg->delay_ns % 1000000000ULL)
            };
            for (int i = 0; i < batch && g_running; i++) {
                ssize_t ret = sendto(sock, packets[i], pkt_sizes[i], 0, NULL, 0);
                if (ret > 0) {
                    local_packets++;
                    local_bytes += pkt_sizes[i];
                } else if (ret < 0 && errno != EAGAIN) {
                    local_errors++;
                }
                nanosleep(&delay_ts, NULL);
            }
        } else {
            /* Batch mode */
            int sent = sendmmsg(sock, msgs, batch, 0);

            if (sent > 0) {
                for (int i = 0; i < sent; i++) {
                    local_packets++;
                    local_bytes += pkt_sizes[i];
                }
            } else if (sent < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                local_errors++;
            }

            /* Per-batch delay */
            if (cfg->delay_ns > 0) {
                struct timespec delay_ts = {
                    .tv_sec = (time_t)(cfg->delay_ns / 1000000000ULL),
                    .tv_nsec = (long)(cfg->delay_ns % 1000000000ULL)
                };
                nanosleep(&delay_ts, NULL);
            }
        }

        /* Periodic stats update */
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        double ms = (now.tv_sec - last_update.tv_sec) * 1000.0 +
                   (now.tv_nsec - last_update.tv_nsec) / 1e6;

        if (ms >= 100) {
            atomic_fetch_add(&stats->packets_sent, local_packets);
            atomic_fetch_add(&stats->bytes_sent, local_bytes);
            atomic_fetch_add(&stats->errors, local_errors);
            local_packets = 0;
            local_bytes = 0;
            local_errors = 0;
            last_update = now;
        }
    }

    /* Final stats */
    atomic_fetch_add(&stats->packets_sent, local_packets);
    atomic_fetch_add(&stats->bytes_sent, local_bytes);
    atomic_fetch_add(&stats->errors, local_errors);

    /* Cleanup */
    for (int i = 0; i < batch; i++) {
        free(packets[i]);
    }
    free(packets);
    free(pkt_sizes);
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
        printf("════════════════════════════════════════════════════════════════════════════════\n");
        printf(" trafgen v%s - High-Performance Traffic Generator\n", VERSION);
        printf(" %d workers, %d byte packets, batch %d, rate: %s\n",
               cfg->num_workers, cfg->packet_size, cfg->batch_size,
               cfg->rate_mbps > 0 ? "" : "unlimited");
        if (cfg->rate_mbps > 0) printf("%.0f Mbps\n", cfg->rate_mbps);
        printf("════════════════════════════════════════════════════════════════════════════════\n");
        printf(" %8s │ %14s │ %12s │ %15s │ %10s\n",
               "Time", "Packets", "Rate (pps)", "Throughput", "Errors");
        printf("──────────┼────────────────┼──────────────┼─────────────────┼────────────\n");
    }

    uint64_t last_packets = 0;
    uint64_t last_bytes = 0;
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

        uint64_t total_packets = 0;
        uint64_t total_bytes = 0;
        uint64_t total_errors = 0;

        for (int i = 0; i < cfg->num_workers; i++) {
            total_packets += atomic_load(&g_stats[i].packets_sent);
            total_bytes += atomic_load(&g_stats[i].bytes_sent);
            total_errors += atomic_load(&g_stats[i].errors);
        }

        uint64_t delta_packets = total_packets - last_packets;
        uint64_t delta_bytes = total_bytes - last_bytes;

        double pps = delta_packets / interval;
        double throughput_mbps = (delta_bytes * 8.0) / (interval * 1e6);
        double throughput_gbps = throughput_mbps / 1000.0;

        if (!cfg->quiet) {
            char tp_str[32];
            if (throughput_gbps >= 1.0) {
                snprintf(tp_str, sizeof(tp_str), "%.2f Gbps", throughput_gbps);
            } else {
                snprintf(tp_str, sizeof(tp_str), "%.1f Mbps", throughput_mbps);
            }

            printf(" %7.1fs │ %14lu │ %12.0f │ %15s │ %10lu\n",
                   elapsed, total_packets, pps, tp_str, total_errors);
            fflush(stdout);
        }

        /* Write to stats file if configured */
        if (g_stats_fp) {
            fprintf(g_stats_fp, "%.1f,%lu,%lu,%.0f,%.2f,%lu\n",
                    elapsed, total_packets, total_bytes, pps, throughput_mbps, total_errors);
            fflush(g_stats_fp);
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

    uint64_t total_packets = 0;
    uint64_t total_bytes = 0;
    uint64_t total_errors = 0;

    for (int i = 0; i < cfg->num_workers; i++) {
        total_packets += atomic_load(&g_stats[i].packets_sent);
        total_bytes += atomic_load(&g_stats[i].bytes_sent);
        total_errors += atomic_load(&g_stats[i].errors);
    }

    if (!cfg->quiet) {
        printf("──────────┴────────────────┴──────────────┴─────────────────┴────────────\n\n");
        printf("Summary:\n");
        printf("  Duration:       %.2f seconds\n", total_time);
        printf("  Total Packets:  %lu\n", total_packets);
        printf("  Total Data:     %.3f GB\n", total_bytes / (1024.0 * 1024.0 * 1024.0));
        printf("  Avg Rate:       %.0f pps\n", total_packets / total_time);
        printf("  Avg Throughput: %.3f Gbps\n", (total_bytes * 8.0) / (total_time * 1e9));
        printf("  Errors:         %lu\n", total_errors);
        printf("════════════════════════════════════════════════════════════════════════════════\n");
    }

    return NULL;
}

/*============================================================================
 * Usage
 *============================================================================*/

static void print_usage(const char *prog) {
    printf("\n");
    printf("trafgen v%s - High-Performance Traffic Generator\n", VERSION);
    printf("\n");
    printf("Usage: %s [options] <interface>\n", prog);
    printf("\n");
    printf("Required:\n");
    printf("  <interface>              Network interface\n");
    printf("  -B, --dst-ip IP          Destination IP address\n");
    printf("  -b, --dst-mac MAC        Destination MAC address\n");
    printf("\n");
    printf("Layer 2:\n");
    printf("  -a, --src-mac MAC|rand   Source MAC\n");
    printf("  -Q, --vlan [PCP[.DEI]:]VLAN  VLAN tag with priority (multiple allowed)\n");
    printf("                           PCP: Priority Code Point (0-7)\n");
    printf("                           DEI: Drop Eligible Indicator (0-1)\n");
    printf("                           Examples: 100, 5:100, 5.1:100\n");
    printf("\n");
    printf("Layer 3:\n");
    printf("  -A, --src-ip IP|rand|IP-IP  Source IP (single, random, or range)\n");
    printf("  -D, --dscp VALUE         DSCP 0-63\n");
    printf("  -T, --ttl VALUE          TTL (default: 64)\n");
    printf("  --df                     Set Don't Fragment flag\n");
    printf("\n");
    printf("Layer 4:\n");
    printf("  -t, --type TYPE          udp, tcp, icmp, raw (default: udp)\n");
    printf("  -p, --port PORT|PORT-PORT  Destination port (single or range)\n");
    printf("  -P, --src-port PORT|PORT-PORT  Source port\n");
    printf("  --tcp-flags FLAGS        TCP flags: S=SYN,A=ACK,F=FIN,R=RST,P=PSH,U=URG\n");
    printf("  --tcp-seq NUM            TCP sequence number\n");
    printf("  --tcp-ack NUM            TCP acknowledgment number\n");
    printf("  --tcp-win NUM            TCP window size\n");
    printf("\n");
    printf("Traffic Control:\n");
    printf("  -c, --count NUM          Packet count (0=infinite)\n");
    printf("  -r, --rate MBPS          Rate limit in Mbps\n");
    printf("  --pps NUM                Rate limit in packets/sec\n");
    printf("  --duration SEC           Duration in seconds\n");
    printf("  -w, --workers NUM        Worker threads (default: CPU count)\n");
    printf("  --batch NUM              Batch size (default: 512)\n");
    printf("  -d, --delay DELAY        Inter-packet delay (e.g., 100ns, 10us, 1ms)\n");
    printf("  --delay-per-pkt          Apply delay per packet (default: per batch)\n");
    printf("  --skb-priority NUM       Socket priority (SO_PRIORITY for tc/qdisc)\n");
    printf("                           Maps to tc filter prio or pfifo_fast bands\n");
    printf("  --multi-tc TC_SPEC[:VLAN]  Send to multiple TCs simultaneously\n");
    printf("                           TC_SPEC: 0-7, 0,2,4,6, or 0-3,6-7\n");
    printf("                           Example: --multi-tc 0-7:100\n");
    printf("\n");
    printf("Packet:\n");
    printf("  -l, --length SIZE|MIN-MAX  Packet size (fixed or random range)\n");
    printf("  --payload-type TYPE      zero, random, increment, pattern, ascii\n");
    printf("  --payload-pattern STR    Pattern string for payload\n");
    printf("  --payload-ascii TEXT     ASCII payload\n");
    printf("  --seq                    Add sequence number to payload\n");
    printf("  --timestamp              Add timestamp to payload\n");
    printf("\n");
    printf("Checksum:\n");
    printf("  --ip-csum                Calculate IP checksum\n");
    printf("  --l4-csum                Calculate TCP/UDP checksum\n");
    printf("\n");
    printf("Output:\n");
    printf("  --stats-file FILE        Write stats to CSV file\n");
    printf("  -q, --quiet              Quiet mode\n");
    printf("  -v, --verbose            Verbose output\n");
    printf("  -S, --simulation         Don't send packets\n");
    printf("  -h, --help               Show help\n");
    printf("  --version                Show version\n");
    printf("\n");
    printf("Examples:\n");
    printf("  # UDP flood at line rate\n");
    printf("  sudo %s eth0 -B 192.168.1.100 -b 00:11:22:33:44:55\n", prog);
    printf("\n");
    printf("  # 1 Gbps, VLAN 100, DSCP EF\n");
    printf("  sudo %s eth0 -B 192.168.1.100 -b 00:11:22:33:44:55 -r 1000 -Q 5:100 -D 46\n", prog);
    printf("\n");
    printf("  # TCP SYN to port range 80-443\n");
    printf("  sudo %s eth0 -B 192.168.1.100 -b 00:11:22:33:44:55 -t tcp -p 80-443\n", prog);
    printf("\n");
    printf("  # Random source IP, sequence numbers, stats to file\n");
    printf("  sudo %s eth0 -B 192.168.1.100 -b 00:11:22:33:44:55 -A rand --seq --stats-file stats.csv\n", prog);
    printf("\n");
    printf("  # TSN/tc integration: VLAN PCP 6, SKB priority 6\n");
    printf("  sudo %s eth0 -B 192.168.1.100 -b 00:11:22:33:44:55 -Q 6:100 --skb-priority 6\n", prog);
    printf("\n");
    printf("  # CBS test: PCP 2 and PCP 6 traffic\n");
    printf("  sudo %s eth0 -B 192.168.1.100 -b 00:11:22:33:44:55 -Q 2:100 --skb-priority 2 -r 1500\n", prog);
    printf("\n");
}

/*============================================================================
 * Argument Parsing
 *============================================================================*/

static int parse_port_range(const char *str, uint16_t *start, uint16_t *end) {
    char *dash = strchr(str, '-');
    if (dash) {
        *start = atoi(str);
        *end = atoi(dash + 1);
        return 1;  /* range */
    } else {
        *start = *end = atoi(str);
        return 0;  /* single */
    }
}

static int parse_ip_range(const char *str, uint32_t *start, uint32_t *end) {
    char *dash = strchr(str, '-');
    if (dash) {
        char tmp[INET_ADDRSTRLEN];
        strncpy(tmp, str, dash - str);
        tmp[dash - str] = '\0';
        *start = ntohl(inet_addr(tmp));
        *end = ntohl(inet_addr(dash + 1));
        return 1;
    }
    return 0;
}

static int parse_size_range(const char *str, int *min, int *max) {
    char *dash = strchr(str, '-');
    if (dash) {
        *min = atoi(str);
        *max = atoi(dash + 1);
        return 1;
    }
    return 0;
}

static int parse_tcp_flags(const char *str) {
    int flags = 0;
    for (const char *p = str; *p; p++) {
        switch (toupper(*p)) {
            case 'F': flags |= 0x01; break;  /* FIN */
            case 'S': flags |= 0x02; break;  /* SYN */
            case 'R': flags |= 0x04; break;  /* RST */
            case 'P': flags |= 0x08; break;  /* PSH */
            case 'A': flags |= 0x10; break;  /* ACK */
            case 'U': flags |= 0x20; break;  /* URG */
        }
    }
    return flags;
}

/* Parse multi-TC specification: "0-7", "0,2,4,6", "0-3,6-7" */
static int parse_multi_tc(const char *str, config_t *cfg) {
    cfg->multi_tc_count = 0;
    char buf[64];
    strncpy(buf, str, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    char *token = strtok(buf, ",");
    while (token && cfg->multi_tc_count < 8) {
        char *dash = strchr(token, '-');
        if (dash) {
            int start = atoi(token);
            int end = atoi(dash + 1);
            for (int tc = start; tc <= end && cfg->multi_tc_count < 8; tc++) {
                if (tc >= 0 && tc <= 7) {
                    cfg->multi_tc[cfg->multi_tc_count++] = (uint8_t)tc;
                }
            }
        } else {
            int tc = atoi(token);
            if (tc >= 0 && tc <= 7) {
                cfg->multi_tc[cfg->multi_tc_count++] = (uint8_t)tc;
            }
        }
        token = strtok(NULL, ",");
    }
    return cfg->multi_tc_count;
}

static int parse_vlan(const char *str, config_t *cfg) {
    if (cfg->vlan_count >= 8) return -1;

    /* Format: [PCP[.DEI]:]VLAN
     * Examples: 100, 5:100, 5.1:100 */
    int idx = cfg->vlan_count;
    cfg->vlan_prio[idx] = 0;
    cfg->vlan_dei[idx] = 0;
    cfg->vlan_id[idx] = 0;

    char *colon = strchr(str, ':');
    if (colon) {
        /* Has priority part */
        char *dot = memchr(str, '.', colon - str);
        if (dot) {
            /* PCP.DEI:VLAN format */
            cfg->vlan_prio[idx] = atoi(str) & 0x7;
            cfg->vlan_dei[idx] = atoi(dot + 1) & 0x1;
        } else {
            /* PCP:VLAN format */
            cfg->vlan_prio[idx] = atoi(str) & 0x7;
        }
        cfg->vlan_id[idx] = atoi(colon + 1) & 0xfff;
    } else {
        /* Just VLAN ID */
        cfg->vlan_id[idx] = atoi(str) & 0xfff;
    }

    cfg->vlan_count++;
    return 0;
}

/*============================================================================
 * Main
 *============================================================================*/

int main(int argc, char *argv[]) {
    /* Default configuration */
    memset(&g_config, 0, sizeof(g_config));
    g_config.eth_type = ETH_P_IP;
    g_config.ttl = 64;
    g_config.src_port = 10000 + (rand() % 50000);
    g_config.dst_port = 5001;
    g_config.pkt_type = PKT_UDP;
    g_config.packet_size = DEFAULT_PACKET_SIZE;
    g_config.batch_size = DEFAULT_BATCH_SIZE;
    g_config.num_workers = sysconf(_SC_NPROCESSORS_ONLN);
    g_config.payload_type = PAYLOAD_INCREMENT;
    g_config.calc_ip_csum = 1;

    static struct option long_options[] = {
        {"src-mac",       required_argument, 0, 'a'},
        {"dst-mac",       required_argument, 0, 'b'},
        {"src-ip",        required_argument, 0, 'A'},
        {"dst-ip",        required_argument, 0, 'B'},
        {"count",         required_argument, 0, 'c'},
        {"length",        required_argument, 0, 'l'},
        {"port",          required_argument, 0, 'p'},
        {"src-port",      required_argument, 0, 'P'},
        {"vlan",          required_argument, 0, 'Q'},
        {"rate",          required_argument, 0, 'r'},
        {"type",          required_argument, 0, 't'},
        {"dscp",          required_argument, 0, 'D'},
        {"ttl",           required_argument, 0, 'T'},
        {"workers",       required_argument, 0, 'w'},
        {"duration",      required_argument, 0, 1001},
        {"batch",         required_argument, 0, 1002},
        {"pps",           required_argument, 0, 1003},
        {"delay",         required_argument, 0, 'd'},
        {"delay-per-pkt", no_argument,       0, 1016},
        {"payload-type",  required_argument, 0, 1004},
        {"payload-pattern", required_argument, 0, 1005},
        {"payload-ascii", required_argument, 0, 1006},
        {"stats-file",    required_argument, 0, 1007},
        {"tcp-flags",     required_argument, 0, 1008},
        {"tcp-seq",       required_argument, 0, 1009},
        {"tcp-ack",       required_argument, 0, 1010},
        {"tcp-win",       required_argument, 0, 1011},
        {"skb-priority",  required_argument, 0, 1015},
        {"multi-tc",      required_argument, 0, 1017},
        {"df",            no_argument,       0, 1020},
        {"seq",           no_argument,       0, 1021},
        {"timestamp",     no_argument,       0, 1022},
        {"ip-csum",       no_argument,       0, 1023},
        {"l4-csum",       no_argument,       0, 1024},
        {"quiet",         no_argument,       0, 'q'},
        {"verbose",       no_argument,       0, 'v'},
        {"simulation",    no_argument,       0, 'S'},
        {"help",          no_argument,       0, 'h'},
        {"version",       no_argument,       0, 1000},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "a:b:A:B:c:d:l:p:P:Q:r:t:D:T:w:qvSh",
                              long_options, NULL)) != -1) {
        switch (opt) {
            case 'a':
                if (strcmp(optarg, "rand") == 0) {
                    g_config.eth_src_rand = 1;
                } else if (str2mac(optarg, g_config.eth_src) < 0) {
                    fprintf(stderr, "Invalid source MAC: %s\n", optarg);
                    return 1;
                }
                break;
            case 'b':
                if (strcmp(optarg, "rand") == 0) {
                    g_config.eth_dst_rand = 1;
                } else if (str2mac(optarg, g_config.eth_dst) < 0) {
                    fprintf(stderr, "Invalid destination MAC: %s\n", optarg);
                    return 1;
                }
                break;
            case 'A':
                if (strcmp(optarg, "rand") == 0) {
                    g_config.ip_src_rand = 1;
                } else if (parse_ip_range(optarg, &g_config.src_ip_start, &g_config.src_ip_end)) {
                    g_config.ip_src_range = 1;
                } else {
                    strncpy(g_config.src_ip, optarg, sizeof(g_config.src_ip) - 1);
                }
                break;
            case 'B':
                if (parse_ip_range(optarg, &g_config.dst_ip_start, &g_config.dst_ip_end)) {
                    g_config.ip_dst_range = 1;
                } else {
                    strncpy(g_config.dst_ip, optarg, sizeof(g_config.dst_ip) - 1);
                }
                break;
            case 'c':
                g_config.count = strtoull(optarg, NULL, 10);
                break;
            case 'd':
                /* Parse delay: 100ns, 10us, 1ms, 1s */
                {
                    char *endptr;
                    double val = strtod(optarg, &endptr);
                    if (*endptr == 'n' || strstr(endptr, "ns")) {
                        g_config.delay_ns = (uint64_t)val;
                    } else if (*endptr == 'u' || strstr(endptr, "us")) {
                        g_config.delay_ns = (uint64_t)(val * 1000);
                    } else if (*endptr == 'm' || strstr(endptr, "ms")) {
                        g_config.delay_ns = (uint64_t)(val * 1000000);
                    } else if (*endptr == 's') {
                        g_config.delay_ns = (uint64_t)(val * 1000000000);
                    } else {
                        /* Default: microseconds */
                        g_config.delay_ns = (uint64_t)(val * 1000);
                    }
                }
                break;
            case 'l':
                if (parse_size_range(optarg, &g_config.packet_size_min, &g_config.packet_size_max)) {
                    g_config.packet_size_rand = 1;
                    g_config.packet_size = g_config.packet_size_max;
                } else {
                    g_config.packet_size = atoi(optarg);
                }
                break;
            case 'p':
                if (parse_port_range(optarg, &g_config.dst_port_start, &g_config.dst_port_end)) {
                    g_config.dst_port_range = 1;
                    g_config.dst_port = g_config.dst_port_start;
                } else {
                    g_config.dst_port = atoi(optarg);
                }
                break;
            case 'P':
                if (parse_port_range(optarg, &g_config.src_port_start, &g_config.src_port_end)) {
                    g_config.src_port_range = 1;
                    g_config.src_port = g_config.src_port_start;
                } else {
                    g_config.src_port = atoi(optarg);
                }
                break;
            case 'Q':
                if (parse_vlan(optarg, &g_config) < 0) {
                    fprintf(stderr, "Error: Maximum 8 VLAN tags\n");
                    return 1;
                }
                break;
            case 'r':
                g_config.rate_mbps = atof(optarg);
                break;
            case 't':
                if (strcmp(optarg, "udp") == 0) g_config.pkt_type = PKT_UDP;
                else if (strcmp(optarg, "tcp") == 0) g_config.pkt_type = PKT_TCP;
                else if (strcmp(optarg, "icmp") == 0) g_config.pkt_type = PKT_ICMP;
                else if (strcmp(optarg, "raw") == 0) g_config.pkt_type = PKT_ETH_RAW;
                else {
                    fprintf(stderr, "Unknown type: %s\n", optarg);
                    return 1;
                }
                break;
            case 'D':
                g_config.dscp = atoi(optarg) & 0x3f;
                break;
            case 'T':
                g_config.ttl = atoi(optarg);
                break;
            case 'w':
                g_config.num_workers = atoi(optarg);
                if (g_config.num_workers < 1) g_config.num_workers = 1;
                if (g_config.num_workers > MAX_WORKERS) g_config.num_workers = MAX_WORKERS;
                break;
            case 1001: g_config.duration = atoi(optarg); break;
            case 1002: g_config.batch_size = atoi(optarg); break;
            case 1003: g_config.rate_pps = atof(optarg); break;
            case 1004:
                if (strcmp(optarg, "zero") == 0) g_config.payload_type = PAYLOAD_ZERO;
                else if (strcmp(optarg, "random") == 0) g_config.payload_type = PAYLOAD_RANDOM;
                else if (strcmp(optarg, "increment") == 0) g_config.payload_type = PAYLOAD_INCREMENT;
                else if (strcmp(optarg, "pattern") == 0) g_config.payload_type = PAYLOAD_PATTERN;
                else if (strcmp(optarg, "ascii") == 0) g_config.payload_type = PAYLOAD_ASCII;
                break;
            case 1005:
                strncpy(g_config.payload_pattern, optarg, sizeof(g_config.payload_pattern) - 1);
                g_config.payload_type = PAYLOAD_PATTERN;
                break;
            case 1006:
                strncpy((char*)g_config.payload, optarg, MAX_PAYLOAD_SIZE - 1);
                g_config.payload_size = strlen(optarg);
                g_config.payload_type = PAYLOAD_ASCII;
                break;
            case 1007:
                strncpy(g_config.stats_file, optarg, sizeof(g_config.stats_file) - 1);
                break;
            case 1008: g_config.tcp_flags = parse_tcp_flags(optarg); break;
            case 1009: g_config.tcp_seq = strtoul(optarg, NULL, 10); break;
            case 1010: g_config.tcp_ack = strtoul(optarg, NULL, 10); break;
            case 1011: g_config.tcp_window = atoi(optarg); break;
            case 1015:
                g_config.skb_priority = atoi(optarg);
                g_config.use_skb_priority = 1;
                break;
            case 1016: g_config.delay_per_packet = 1; break;
            case 1017:
                {
                    /* Format: TC_SPEC[:VLAN] e.g., "0-7:100" or "0,2,4,6:100" */
                    char *colon = strchr(optarg, ':');
                    if (colon) {
                        g_config.multi_tc_vlan = atoi(colon + 1) & 0xfff;
                        *colon = '\0';
                    }
                    parse_multi_tc(optarg, &g_config);
                }
                break;
            case 1020: g_config.df_flag = 1; break;
            case 1021: g_config.add_seq_num = 1; break;
            case 1022: g_config.add_timestamp = 1; break;
            case 1023: g_config.calc_ip_csum = 1; break;
            case 1024: g_config.calc_l4_csum = 1; break;
            case 'q': g_config.quiet = 1; break;
            case 'v': g_config.verbose = 1; break;
            case 'S': g_config.simulation = 1; break;
            case 'h': print_usage(argv[0]); return 0;
            case 1000: printf("trafgen v%s\n", VERSION); return 0;
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

    if (strlen(g_config.dst_ip) == 0 && !g_config.ip_dst_range && g_config.pkt_type != PKT_ETH_RAW) {
        fprintf(stderr, "Error: Destination IP required (-B)\n");
        return 1;
    }

    if (geteuid() != 0) {
        fprintf(stderr, "Error: Root privileges required\n");
        return 1;
    }

    /* Get interface info */
    if (!g_config.eth_src_rand && memcmp(g_config.eth_src, "\x00\x00\x00\x00\x00\x00", 6) == 0) {
        get_if_mac(g_config.interface, g_config.eth_src);
    }

    if (strlen(g_config.src_ip) == 0 && !g_config.ip_src_rand && !g_config.ip_src_range) {
        get_if_ip(g_config.interface, g_config.src_ip, sizeof(g_config.src_ip));
        if (strlen(g_config.src_ip) == 0) strcpy(g_config.src_ip, "192.168.1.1");
    }

    if (!g_config.eth_dst_rand && memcmp(g_config.eth_dst, "\x00\x00\x00\x00\x00\x00", 6) == 0) {
        fprintf(stderr, "Error: Destination MAC required (-b)\n");
        return 1;
    }

    /* Print config (skip if multi-TC mode, handled separately) */
    if (!g_config.quiet && g_config.multi_tc_count <= 1) {
        printf("\nConfiguration:\n");
        printf("  Interface:    %s (%02x:%02x:%02x:%02x:%02x:%02x)\n",
               g_config.interface,
               g_config.eth_src[0], g_config.eth_src[1], g_config.eth_src[2],
               g_config.eth_src[3], g_config.eth_src[4], g_config.eth_src[5]);
        printf("  Destination:  %s (%02x:%02x:%02x:%02x:%02x:%02x)\n",
               g_config.dst_ip,
               g_config.eth_dst[0], g_config.eth_dst[1], g_config.eth_dst[2],
               g_config.eth_dst[3], g_config.eth_dst[4], g_config.eth_dst[5]);
        printf("  Source IP:    %s%s\n", g_config.src_ip,
               g_config.ip_src_rand ? " (random)" : g_config.ip_src_range ? " (range)" : "");
        printf("  Ports:        %d%s -> %d%s\n",
               g_config.src_port, g_config.src_port_range ? " (range)" : "",
               g_config.dst_port, g_config.dst_port_range ? " (range)" : "");
        printf("  Packet Size:  %d bytes%s\n", g_config.packet_size,
               g_config.packet_size_rand ? " (random)" : "");
        printf("  Rate:         %s\n", g_config.rate_mbps > 0 ? "" : "Line rate");
        if (g_config.rate_mbps > 0) printf("                %.0f Mbps\n", g_config.rate_mbps);
        printf("  Duration:     %s\n", g_config.duration > 0 ? "" : "Infinite");
        if (g_config.duration > 0) printf("                %d seconds\n", g_config.duration);
        printf("  Workers:      %d, Batch: %d\n", g_config.num_workers, g_config.batch_size);
        if (g_config.delay_ns > 0) {
            if (g_config.delay_ns >= 1000000000ULL)
                printf("  Delay:        %.3f s %s\n", g_config.delay_ns / 1e9,
                       g_config.delay_per_packet ? "(per-pkt)" : "(per-batch)");
            else if (g_config.delay_ns >= 1000000ULL)
                printf("  Delay:        %.3f ms %s\n", g_config.delay_ns / 1e6,
                       g_config.delay_per_packet ? "(per-pkt)" : "(per-batch)");
            else if (g_config.delay_ns >= 1000ULL)
                printf("  Delay:        %.3f us %s\n", g_config.delay_ns / 1e3,
                       g_config.delay_per_packet ? "(per-pkt)" : "(per-batch)");
            else
                printf("  Delay:        %lu ns %s\n", g_config.delay_ns,
                       g_config.delay_per_packet ? "(per-pkt)" : "(per-batch)");
        }
        for (int i = 0; i < g_config.vlan_count; i++) {
            printf("  VLAN %d:       %d (PCP: %d, DEI: %d)\n",
                   i+1, g_config.vlan_id[i], g_config.vlan_prio[i], g_config.vlan_dei[i]);
        }
        if (g_config.dscp > 0) printf("  DSCP:         %d\n", g_config.dscp);
        if (g_config.use_skb_priority) printf("  SKB Priority: %d\n", g_config.skb_priority);
        if (g_config.add_seq_num) printf("  Sequence:     Enabled\n");
        if (g_config.add_timestamp) printf("  Timestamp:    Enabled\n");
    }

    if (g_config.simulation) {
        printf("\n*** SIMULATION MODE ***\n");
        return 0;
    }

    /* Open stats file */
    if (strlen(g_config.stats_file) > 0) {
        g_stats_fp = fopen(g_config.stats_file, "w");
        if (g_stats_fp) {
            fprintf(g_stats_fp, "time,packets,bytes,pps,mbps,errors\n");
        }
    }

    /* Initialize */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    memset(g_stats, 0, sizeof(g_stats));

    /* Multi-TC mode: fork process for each TC */
    if (g_config.multi_tc_count > 1) {
        pid_t pids[8];
        int num_tc = g_config.multi_tc_count;
        int is_parent = 1;

        if (!g_config.quiet) {
            printf("\n══════════════════════════════════════════════════════════════════════════════\n");
            printf(" Multi-TC Mode: %d Traffic Classes (PCP 0-%d)\n", num_tc, num_tc - 1);
            printf(" VLAN: %d | Rate: %.0f Mbps/TC | Duration: %d sec\n",
                   g_config.multi_tc_vlan,
                   g_config.rate_mbps > 0 ? g_config.rate_mbps : 0,
                   g_config.duration);
            printf("══════════════════════════════════════════════════════════════════════════════\n");
            fflush(stdout);
        }

        for (int i = 0; i < num_tc; i++) {
            pids[i] = fork();
            if (pids[i] == 0) {
                /* Child process: configure for this TC */
                is_parent = 0;
                uint8_t tc = g_config.multi_tc[i];

                /* Set VLAN with PCP = TC */
                g_config.vlan_count = 1;
                g_config.vlan_id[0] = g_config.multi_tc_vlan;
                g_config.vlan_prio[0] = tc;
                g_config.vlan_dei[0] = 0;

                /* Set SKB priority */
                g_config.skb_priority = tc;
                g_config.use_skb_priority = 1;

                /* Clear multi-TC to prevent recursion */
                g_config.multi_tc_count = 0;

                /* Quiet mode for children */
                g_config.quiet = 1;

                /* Continue to normal execution */
                break;
            } else if (pids[i] < 0) {
                perror("fork");
                return 1;
            }
        }

        /* Parent: wait for all children */
        if (is_parent) {
            for (int i = 0; i < num_tc; i++) {
                int status;
                waitpid(pids[i], &status, 0);
            }
            printf("\nAll %d TCs completed.\n", num_tc);
            return 0;
        }
    }

    token_bucket_init(&g_bucket, g_config.rate_mbps, g_config.batch_size, g_config.packet_size);
    clock_gettime(CLOCK_MONOTONIC, &g_start_time);

    /* Start workers */
    worker_ctx_t *contexts = calloc(g_config.num_workers, sizeof(worker_ctx_t));

    for (int i = 0; i < g_config.num_workers; i++) {
        contexts[i].id = i;
        contexts[i].cfg = &g_config;
        contexts[i].stats = &g_stats[i];
        contexts[i].bucket = &g_bucket;
        contexts[i].seq_num = i * 1000000;

        if (pthread_create(&g_workers[i], NULL, worker_thread, &contexts[i]) != 0) {
            fprintf(stderr, "Failed to create worker %d\n", i);
            g_running = 0;
            break;
        }
    }

    pthread_create(&g_stats_thread, NULL, stats_thread, &g_config);
    pthread_join(g_stats_thread, NULL);

    for (int i = 0; i < g_config.num_workers; i++) {
        pthread_join(g_workers[i], NULL);
    }

    if (g_stats_fp) fclose(g_stats_fp);
    free(contexts);

    return 0;
}
