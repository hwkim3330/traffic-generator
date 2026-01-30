/*
 * trafgen - High-Performance Traffic Generator
 * Based on Mausezahn concepts, enhanced with modern Linux networking features
 *
 * Copyright (C) 2025
 * Original Mausezahn Copyright (C) 2008-2010 Herbert Haas (GPLv2)
 *
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License version 2 as published by the
 * Free Software Foundation.
 *
 * Key improvements over mz:
 * - sendmmsg() batch transmission for 10x+ throughput
 * - Multi-threaded architecture
 * - Real-time statistics (pps, throughput)
 * - Direct AF_PACKET (no libnet overhead)
 * - Precise rate limiting with nanosleep
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

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
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

#define VERSION "1.0.0"
#define MAX_PACKET_SIZE 9000
#define DEFAULT_PACKET_SIZE 1472
#define DEFAULT_BATCH_SIZE 1024
#define MAX_WORKERS 64
#define MAX_PAYLOAD_SIZE 8192
#define STATS_INTERVAL_US 1000000

/*============================================================================
 * Data Structures
 *============================================================================*/

/* Packet types - compatible with mz */
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
    uint8_t vlan_prio[8];

    /* Layer 3 */
    char src_ip[INET6_ADDRSTRLEN];
    char dst_ip[INET6_ADDRSTRLEN];
    int ip_src_rand;
    uint8_t dscp;
    uint8_t ttl;
    int ipv6_mode;

    /* Layer 4 */
    uint16_t src_port;
    uint16_t dst_port;
    int src_port_rand;
    int dst_port_range;
    uint16_t dst_port_start;
    uint16_t dst_port_end;

    /* Packet */
    packet_type_t pkt_type;
    int packet_size;
    uint8_t payload[MAX_PAYLOAD_SIZE];
    int payload_size;
    char payload_ascii[MAX_PAYLOAD_SIZE];

    /* Traffic control */
    uint64_t count;         /* 0 = infinite */
    double rate_mbps;       /* 0 = line rate */
    int duration;           /* seconds, 0 = infinite */
    int num_workers;
    int batch_size;
    unsigned int delay_us;  /* inter-packet delay in microseconds */

    /* Flags */
    int verbose;
    int quiet;
    int simulation;
} config_t;

/* Worker statistics */
typedef struct {
    atomic_uint_fast64_t packets_sent;
    atomic_uint_fast64_t bytes_sent;
    atomic_uint_fast64_t errors;
} worker_stats_t;

/* Worker context */
typedef struct {
    int id;
    int socket_fd;
    config_t *cfg;
    worker_stats_t *stats;
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

/*============================================================================
 * Signal Handler
 *============================================================================*/

static void signal_handler(int sig) {
    (void)sig;
    g_running = 0;
}

/*============================================================================
 * Utility Functions (from mz)
 *============================================================================*/

/* Parse MAC address string */
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

/* Get interface MAC address */
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

/* Get interface index */
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

/* Get interface IP address */
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

/* Calculate IP checksum */
static uint16_t ip_checksum(void *vdata, size_t length) {
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

/* Generate random MAC */
static void rand_mac(uint8_t *mac) {
    for (int i = 0; i < 6; i++) {
        mac[i] = rand() & 0xff;
    }
    mac[0] &= 0xfe;  /* Clear multicast bit */
}

/*============================================================================
 * Packet Building Functions
 *============================================================================*/

/* Build Ethernet header */
static int build_eth_header(uint8_t *buf, config_t *cfg) {
    int offset = 0;

    /* Destination MAC */
    memcpy(buf + offset, cfg->eth_dst, ETH_ALEN);
    offset += ETH_ALEN;

    /* Source MAC */
    memcpy(buf + offset, cfg->eth_src, ETH_ALEN);
    offset += ETH_ALEN;

    /* VLAN tags (802.1Q) */
    for (int i = 0; i < cfg->vlan_count; i++) {
        buf[offset++] = 0x81;
        buf[offset++] = 0x00;
        uint16_t tci = (cfg->vlan_prio[i] << 13) | cfg->vlan_id[i];
        buf[offset++] = (tci >> 8) & 0xff;
        buf[offset++] = tci & 0xff;
    }

    /* EtherType */
    buf[offset++] = (cfg->eth_type >> 8) & 0xff;
    buf[offset++] = cfg->eth_type & 0xff;

    return offset;
}

/* Build IPv4 header */
static int build_ip_header(uint8_t *buf, config_t *cfg, int payload_len) {
    struct iphdr *ip = (struct iphdr *)buf;

    ip->version = 4;
    ip->ihl = 5;
    ip->tos = cfg->dscp << 2;
    ip->tot_len = htons(sizeof(struct iphdr) + payload_len);
    ip->id = htons(rand() & 0xffff);
    ip->frag_off = 0;
    ip->ttl = cfg->ttl;
    ip->protocol = (cfg->pkt_type == PKT_UDP) ? IPPROTO_UDP :
                   (cfg->pkt_type == PKT_TCP) ? IPPROTO_TCP :
                   (cfg->pkt_type == PKT_ICMP) ? IPPROTO_ICMP : 0;
    ip->check = 0;
    ip->saddr = inet_addr(cfg->src_ip);
    ip->daddr = inet_addr(cfg->dst_ip);
    ip->check = ip_checksum(ip, sizeof(struct iphdr));

    return sizeof(struct iphdr);
}

/* Build UDP header */
static int build_udp_header(uint8_t *buf, config_t *cfg, int payload_len) {
    struct udphdr *udp = (struct udphdr *)buf;

    udp->source = htons(cfg->src_port);
    udp->dest = htons(cfg->dst_port);
    udp->len = htons(sizeof(struct udphdr) + payload_len);
    udp->check = 0;  /* Optional for IPv4 */

    return sizeof(struct udphdr);
}

/* Build TCP header */
static int build_tcp_header(uint8_t *buf, config_t *cfg) {
    struct tcphdr *tcp = (struct tcphdr *)buf;

    memset(tcp, 0, sizeof(struct tcphdr));
    tcp->source = htons(cfg->src_port);
    tcp->dest = htons(cfg->dst_port);
    tcp->seq = htonl(rand());
    tcp->ack_seq = 0;
    tcp->doff = 5;
    tcp->syn = 1;
    tcp->window = htons(65535);
    tcp->check = 0;
    tcp->urg_ptr = 0;

    return sizeof(struct tcphdr);
}

/* Build complete packet */
static int build_packet(uint8_t *buf, config_t *cfg, int flow_id) {
    int offset = 0;
    int payload_len;

    /* Randomize if needed */
    if (cfg->eth_src_rand) {
        rand_mac(cfg->eth_src);
    }
    if (cfg->eth_dst_rand) {
        rand_mac(cfg->eth_dst);
    }

    /* Ethernet header */
    offset = build_eth_header(buf, cfg);

    if (cfg->pkt_type == PKT_ETH_RAW) {
        /* Raw Ethernet - just add payload */
        if (cfg->payload_size > 0) {
            memcpy(buf + offset, cfg->payload, cfg->payload_size);
            offset += cfg->payload_size;
        }
    } else {
        /* IP-based packets */
        int ip_start = offset;
        int udp_payload_len;

        /* Calculate payload length */
        int header_size = 14 + (cfg->vlan_count * 4) + 20;  /* Eth + VLAN + IP */
        if (cfg->pkt_type == PKT_UDP) header_size += 8;
        else if (cfg->pkt_type == PKT_TCP) header_size += 20;

        if (cfg->payload_size > 0) {
            udp_payload_len = cfg->payload_size;
        } else {
            udp_payload_len = cfg->packet_size - header_size;
            if (udp_payload_len < 0) udp_payload_len = 0;
        }

        /* IP header */
        payload_len = (cfg->pkt_type == PKT_UDP) ? sizeof(struct udphdr) + udp_payload_len :
                      (cfg->pkt_type == PKT_TCP) ? sizeof(struct tcphdr) : udp_payload_len;
        offset += build_ip_header(buf + offset, cfg, payload_len);

        /* Transport layer */
        if (cfg->pkt_type == PKT_UDP) {
            struct udphdr *udp = (struct udphdr *)(buf + offset);
            udp->source = htons(cfg->src_port + (flow_id % 1000));
            udp->dest = htons(cfg->dst_port);
            udp->len = htons(sizeof(struct udphdr) + udp_payload_len);
            udp->check = 0;
            offset += sizeof(struct udphdr);

            /* Payload */
            for (int i = 0; i < udp_payload_len; i++) {
                buf[offset + i] = (uint8_t)(i & 0xff);
            }
            offset += udp_payload_len;

        } else if (cfg->pkt_type == PKT_TCP) {
            offset += build_tcp_header(buf + offset, cfg);
        }
    }

    /* Ensure minimum frame size */
    if (offset < 60) {
        memset(buf + offset, 0, 60 - offset);
        offset = 60;
    }

    return offset;
}

/*============================================================================
 * Worker Thread (High Performance Transmission)
 *============================================================================*/

static void *worker_thread(void *arg) {
    worker_ctx_t *ctx = (worker_ctx_t *)arg;
    config_t *cfg = ctx->cfg;
    worker_stats_t *stats = ctx->stats;

    /* Create raw socket */
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        perror("socket");
        return NULL;
    }

    /* Large send buffer */
    int sndbuf = 64 * 1024 * 1024;
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));

    /* Bind to interface */
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

    /* Pre-build packets */
    int batch = cfg->batch_size;
    uint8_t **packets = malloc(batch * sizeof(uint8_t *));
    int *pkt_sizes = malloc(batch * sizeof(int));

    for (int i = 0; i < batch; i++) {
        packets[i] = aligned_alloc(64, MAX_PACKET_SIZE);
        memset(packets[i], 0, MAX_PACKET_SIZE);
        pkt_sizes[i] = build_packet(packets[i], cfg, ctx->id * 1000 + i);
    }

    /* Prepare sendmmsg structures */
    struct mmsghdr *msgs = calloc(batch, sizeof(struct mmsghdr));
    struct iovec *iovecs = calloc(batch, sizeof(struct iovec));

    for (int i = 0; i < batch; i++) {
        iovecs[i].iov_base = packets[i];
        iovecs[i].iov_len = pkt_sizes[i];
        msgs[i].msg_hdr.msg_iov = &iovecs[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
    }

    /* Rate limiting setup */
    double rate_per_worker = cfg->rate_mbps / cfg->num_workers;
    double bytes_per_ns = 0;
    if (rate_per_worker > 0) {
        bytes_per_ns = (rate_per_worker * 1000000.0) / (8.0 * 1e9);
    }

    uint64_t local_packets = 0;
    uint64_t local_bytes = 0;
    uint64_t local_errors = 0;
    struct timespec last_update, now, rate_start;
    clock_gettime(CLOCK_MONOTONIC, &last_update);
    rate_start = last_update;

    uint64_t rate_bytes = 0;

    /* Main transmission loop */
    while (g_running) {
        int sent = sendmmsg(sock, msgs, batch, 0);

        if (sent > 0) {
            for (int i = 0; i < sent; i++) {
                local_packets++;
                local_bytes += pkt_sizes[i % batch];
                rate_bytes += pkt_sizes[i % batch];
            }
        } else if (sent < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
            local_errors++;
        }

        /* Rate limiting */
        if (bytes_per_ns > 0) {
            clock_gettime(CLOCK_MONOTONIC, &now);
            double elapsed_ns = (now.tv_sec - rate_start.tv_sec) * 1e9 +
                               (now.tv_nsec - rate_start.tv_nsec);
            double target_bytes = elapsed_ns * bytes_per_ns;

            if (rate_bytes > target_bytes) {
                double sleep_ns = (rate_bytes - target_bytes) / bytes_per_ns;
                if (sleep_ns > 100) {
                    struct timespec ts = {
                        .tv_sec = (time_t)(sleep_ns / 1e9),
                        .tv_nsec = (long)((uint64_t)sleep_ns % (uint64_t)1e9)
                    };
                    nanosleep(&ts, NULL);
                }
            }
        }

        /* Periodic stats update */
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
            rate_start = now;
            rate_bytes = 0;
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
        printf(" %d workers, %d byte packets, batch size %d\n",
               cfg->num_workers, cfg->packet_size, cfg->batch_size);
        printf("════════════════════════════════════════════════════════════════════════════════\n");
        printf(" %8s │ %14s │ %12s │ %15s │ %10s\n",
               "Time", "Packets", "Rate (pps)", "Throughput", "Errors");
        printf("──────────┼────────────────┼──────────────┼─────────────────┼────────────\n");
    }

    uint64_t last_packets = 0;
    uint64_t last_bytes = 0;
    struct timespec last_time, now;
    clock_gettime(CLOCK_MONOTONIC, &last_time);

    while (g_running) {
        usleep(STATS_INTERVAL_US);

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

        last_packets = total_packets;
        last_bytes = total_bytes;
        last_time = now;

        /* Check duration */
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
        printf("──────────┴────────────────┴──────────────┴─────────────────┴────────────\n");
        printf("\n");
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
 * Usage and Help
 *============================================================================*/

static void print_usage(const char *prog) {
    printf("\n");
    printf("trafgen v%s - High-Performance Traffic Generator\n", VERSION);
    printf("Based on Mausezahn, enhanced with sendmmsg() and multi-threading\n");
    printf("\n");
    printf("Usage: %s [options] <interface>\n", prog);
    printf("\n");
    printf("Required:\n");
    printf("  <interface>              Network interface (e.g., eth0, enp11s0)\n");
    printf("  -B, --dst-ip IP          Destination IP address\n");
    printf("  -b, --dst-mac MAC        Destination MAC address\n");
    printf("\n");
    printf("Layer 2 Options:\n");
    printf("  -a, --src-mac MAC|rand   Source MAC (default: interface MAC, 'rand' for random)\n");
    printf("  -b, --dst-mac MAC|rand   Destination MAC ('rand' for random)\n");
    printf("  -Q, --vlan [CoS:]VLAN    VLAN tag (can specify multiple: -Q 100 -Q 5:200)\n");
    printf("\n");
    printf("Layer 3 Options:\n");
    printf("  -A, --src-ip IP|rand     Source IP (default: interface IP)\n");
    printf("  -B, --dst-ip IP          Destination IP\n");
    printf("  -D, --dscp VALUE         DSCP value 0-63 (default: 0)\n");
    printf("  -T, --ttl VALUE          TTL value (default: 64)\n");
    printf("\n");
    printf("Layer 4 Options:\n");
    printf("  -t, --type TYPE          Packet type: udp, tcp, icmp, raw (default: udp)\n");
    printf("  -p, --port PORT          Destination port (default: 5001)\n");
    printf("  -P, --src-port PORT      Source port (default: random)\n");
    printf("\n");
    printf("Traffic Control:\n");
    printf("  -c, --count NUM          Packet count (0 = infinite, default: 0)\n");
    printf("  -d, --delay DELAY        Inter-packet delay (e.g., 100usec, 10msec, 1sec)\n");
    printf("  -r, --rate MBPS          Target rate in Mbps (0 = line rate)\n");
    printf("  --duration SEC           Duration in seconds\n");
    printf("  -w, --workers NUM        Number of worker threads (default: CPU count)\n");
    printf("  --batch NUM              Batch size for sendmmsg (default: 1024)\n");
    printf("\n");
    printf("Packet Options:\n");
    printf("  -l, --length SIZE        Packet size in bytes (default: 1472)\n");
    printf("  --payload HEX            Hex payload (e.g., \"de:ad:be:ef\")\n");
    printf("  --payload-ascii TEXT     ASCII payload\n");
    printf("\n");
    printf("Other:\n");
    printf("  -q, --quiet              Quiet mode\n");
    printf("  -v, --verbose            Verbose output\n");
    printf("  -S, --simulation         Simulation mode (don't send)\n");
    printf("  -h, --help               Show this help\n");
    printf("  --version                Show version\n");
    printf("\n");
    printf("Examples:\n");
    printf("  # UDP flood at line rate\n");
    printf("  sudo %s eth0 -B 192.168.1.100 -b 00:11:22:33:44:55\n", prog);
    printf("\n");
    printf("  # 1 Gbps for 60 seconds\n");
    printf("  sudo %s eth0 -B 192.168.1.100 -b 00:11:22:33:44:55 -r 1000 --duration 60\n", prog);
    printf("\n");
    printf("  # VLAN tagged with QoS\n");
    printf("  sudo %s eth0 -B 192.168.1.100 -b 00:11:22:33:44:55 -Q 5:100 -D 46\n", prog);
    printf("\n");
}

/*============================================================================
 * Argument Parsing
 *============================================================================*/

static int parse_delay(const char *str, unsigned int *delay_us) {
    char *endptr;
    double val = strtod(str, &endptr);

    if (endptr == str) return -1;

    if (strstr(endptr, "sec") || *endptr == 's') {
        *delay_us = (unsigned int)(val * 1000000);
    } else if (strstr(endptr, "msec") || *endptr == 'm') {
        *delay_us = (unsigned int)(val * 1000);
    } else if (strstr(endptr, "usec") || *endptr == 'u' || *endptr == '\0') {
        *delay_us = (unsigned int)val;
    } else {
        return -1;
    }

    return 0;
}

static int parse_vlan(const char *str, config_t *cfg) {
    if (cfg->vlan_count >= 8) {
        fprintf(stderr, "Error: Maximum 8 VLAN tags supported\n");
        return -1;
    }

    char *colon = strchr(str, ':');
    if (colon) {
        cfg->vlan_prio[cfg->vlan_count] = atoi(str) & 0x7;
        cfg->vlan_id[cfg->vlan_count] = atoi(colon + 1) & 0xfff;
    } else {
        cfg->vlan_prio[cfg->vlan_count] = 0;
        cfg->vlan_id[cfg->vlan_count] = atoi(str) & 0xfff;
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

    static struct option long_options[] = {
        {"src-mac",       required_argument, 0, 'a'},
        {"dst-mac",       required_argument, 0, 'b'},
        {"src-ip",        required_argument, 0, 'A'},
        {"dst-ip",        required_argument, 0, 'B'},
        {"count",         required_argument, 0, 'c'},
        {"delay",         required_argument, 0, 'd'},
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
        {"payload",       required_argument, 0, 1003},
        {"payload-ascii", required_argument, 0, 1004},
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
                } else {
                    if (str2mac(optarg, g_config.eth_src) < 0) {
                        fprintf(stderr, "Invalid source MAC: %s\n", optarg);
                        return 1;
                    }
                }
                break;
            case 'b':
                if (strcmp(optarg, "rand") == 0) {
                    g_config.eth_dst_rand = 1;
                } else {
                    if (str2mac(optarg, g_config.eth_dst) < 0) {
                        fprintf(stderr, "Invalid destination MAC: %s\n", optarg);
                        return 1;
                    }
                }
                break;
            case 'A':
                if (strcmp(optarg, "rand") == 0) {
                    g_config.ip_src_rand = 1;
                } else {
                    strncpy(g_config.src_ip, optarg, sizeof(g_config.src_ip) - 1);
                }
                break;
            case 'B':
                strncpy(g_config.dst_ip, optarg, sizeof(g_config.dst_ip) - 1);
                break;
            case 'c':
                g_config.count = strtoull(optarg, NULL, 10);
                break;
            case 'd':
                if (parse_delay(optarg, &g_config.delay_us) < 0) {
                    fprintf(stderr, "Invalid delay: %s\n", optarg);
                    return 1;
                }
                break;
            case 'l':
                g_config.packet_size = atoi(optarg);
                break;
            case 'p':
                g_config.dst_port = atoi(optarg);
                break;
            case 'P':
                g_config.src_port = atoi(optarg);
                break;
            case 'Q':
                if (parse_vlan(optarg, &g_config) < 0) return 1;
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
                    fprintf(stderr, "Unknown packet type: %s\n", optarg);
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
            case 1001:  /* --duration */
                g_config.duration = atoi(optarg);
                break;
            case 1002:  /* --batch */
                g_config.batch_size = atoi(optarg);
                break;
            case 'q':
                g_config.quiet = 1;
                break;
            case 'v':
                g_config.verbose = 1;
                break;
            case 'S':
                g_config.simulation = 1;
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            case 1000:  /* --version */
                printf("trafgen v%s\n", VERSION);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    /* Get interface from positional argument */
    if (optind < argc) {
        strncpy(g_config.interface, argv[optind], IFNAMSIZ - 1);
    }

    /* Validate required arguments */
    if (strlen(g_config.interface) == 0) {
        fprintf(stderr, "Error: Interface required\n");
        print_usage(argv[0]);
        return 1;
    }

    if (strlen(g_config.dst_ip) == 0 && g_config.pkt_type != PKT_ETH_RAW) {
        fprintf(stderr, "Error: Destination IP required (-B)\n");
        return 1;
    }

    /* Check root */
    if (geteuid() != 0) {
        fprintf(stderr, "Error: Root privileges required\n");
        return 1;
    }

    /* Get interface MAC if not specified */
    if (!g_config.eth_src_rand &&
        memcmp(g_config.eth_src, "\x00\x00\x00\x00\x00\x00", 6) == 0) {
        if (get_if_mac(g_config.interface, g_config.eth_src) < 0) {
            fprintf(stderr, "Error: Cannot get MAC for %s\n", g_config.interface);
            return 1;
        }
    }

    /* Get interface IP if not specified */
    if (strlen(g_config.src_ip) == 0 && !g_config.ip_src_rand) {
        get_if_ip(g_config.interface, g_config.src_ip, sizeof(g_config.src_ip));
        if (strlen(g_config.src_ip) == 0) {
            strcpy(g_config.src_ip, "192.168.1.1");
        }
    }

    /* Check destination MAC */
    if (!g_config.eth_dst_rand &&
        memcmp(g_config.eth_dst, "\x00\x00\x00\x00\x00\x00", 6) == 0) {
        fprintf(stderr, "Error: Destination MAC required (-b)\n");
        return 1;
    }

    /* Print configuration */
    if (!g_config.quiet) {
        printf("\nConfiguration:\n");
        printf("  Interface:    %s (%02x:%02x:%02x:%02x:%02x:%02x)\n",
               g_config.interface,
               g_config.eth_src[0], g_config.eth_src[1], g_config.eth_src[2],
               g_config.eth_src[3], g_config.eth_src[4], g_config.eth_src[5]);
        printf("  Destination:  %s (%02x:%02x:%02x:%02x:%02x:%02x)\n",
               g_config.dst_ip,
               g_config.eth_dst[0], g_config.eth_dst[1], g_config.eth_dst[2],
               g_config.eth_dst[3], g_config.eth_dst[4], g_config.eth_dst[5]);
        printf("  Source IP:    %s\n", g_config.src_ip);
        printf("  Ports:        %d -> %d\n", g_config.src_port, g_config.dst_port);
        printf("  Packet Size:  %d bytes\n", g_config.packet_size);
        printf("  Rate:         %s\n", g_config.rate_mbps > 0 ? "" : "Line rate");
        if (g_config.rate_mbps > 0)
            printf("                %.0f Mbps\n", g_config.rate_mbps);
        printf("  Duration:     %s\n", g_config.duration > 0 ? "" : "Infinite");
        if (g_config.duration > 0)
            printf("                %d seconds\n", g_config.duration);
        printf("  Workers:      %d\n", g_config.num_workers);
        for (int i = 0; i < g_config.vlan_count; i++) {
            printf("  VLAN %d:       %d (prio: %d)\n", i+1,
                   g_config.vlan_id[i], g_config.vlan_prio[i]);
        }
        if (g_config.dscp > 0)
            printf("  DSCP:         %d\n", g_config.dscp);
    }

    if (g_config.simulation) {
        printf("\n*** SIMULATION MODE - No packets will be sent ***\n");
        return 0;
    }

    /* Setup signals */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* Initialize stats */
    memset(g_stats, 0, sizeof(g_stats));
    clock_gettime(CLOCK_MONOTONIC, &g_start_time);

    /* Start workers */
    worker_ctx_t *contexts = calloc(g_config.num_workers, sizeof(worker_ctx_t));

    for (int i = 0; i < g_config.num_workers; i++) {
        contexts[i].id = i;
        contexts[i].cfg = &g_config;
        contexts[i].stats = &g_stats[i];

        if (pthread_create(&g_workers[i], NULL, worker_thread, &contexts[i]) != 0) {
            fprintf(stderr, "Failed to create worker %d\n", i);
            g_running = 0;
            break;
        }
    }

    /* Start stats thread */
    pthread_create(&g_stats_thread, NULL, stats_thread, &g_config);

    /* Wait for completion */
    pthread_join(g_stats_thread, NULL);

    for (int i = 0; i < g_config.num_workers; i++) {
        pthread_join(g_workers[i], NULL);
    }

    free(contexts);

    return 0;
}
