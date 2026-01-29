/*
 * High-Performance Traffic Generator
 * Capable of 10Gbps+ line-rate traffic generation
 *
 * Features:
 * - Raw socket with sendmmsg() for batch transmission
 * - Multi-threaded architecture
 * - VLAN tagging support
 * - DSCP/QoS marking
 * - Real-time statistics
 *
 * Build: gcc -O3 -march=native -o traffic_gen traffic_generator.c -lpthread
 * Usage: sudo ./traffic_gen -i eth0 -d 192.168.1.100 -m 00:11:22:33:44:55
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

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netpacket/packet.h>
#include <linux/if_ether.h>

#define MAX_PACKET_SIZE 9000
#define DEFAULT_PACKET_SIZE 1472
#define BATCH_SIZE 1024
#define MAX_WORKERS 64
#define STATS_INTERVAL_MS 1000

/* Global running flag */
static volatile sig_atomic_t running = 1;

/* Statistics */
typedef struct {
    atomic_uint_fast64_t packets_sent;
    atomic_uint_fast64_t bytes_sent;
    atomic_uint_fast64_t errors;
} worker_stats_t;

/* Configuration */
typedef struct {
    char interface[IFNAMSIZ];
    char dst_ip[INET_ADDRSTRLEN];
    char src_ip[INET_ADDRSTRLEN];
    uint8_t dst_mac[ETH_ALEN];
    uint8_t src_mac[ETH_ALEN];
    uint16_t dst_port;
    uint16_t src_port;
    int packet_size;
    double rate_mbps;        /* 0 = line rate */
    int duration;            /* 0 = infinite */
    int num_workers;
    int vlan_id;             /* 0 = no VLAN */
    int vlan_priority;
    int dscp;
    int batch_size;
} config_t;

/* Worker context */
typedef struct {
    int worker_id;
    config_t *config;
    worker_stats_t *stats;
    int socket_fd;
} worker_ctx_t;

static config_t g_config;
static worker_stats_t g_stats[MAX_WORKERS];
static pthread_t g_workers[MAX_WORKERS];
static pthread_t g_stats_thread;
static struct timespec g_start_time;

/* Signal handler */
static void signal_handler(int sig) {
    (void)sig;
    running = 0;
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

/* Parse MAC address string */
static int parse_mac(const char *str, uint8_t *mac) {
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
static int get_interface_mac(const char *ifname, uint8_t *mac) {
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
static int get_interface_index(const char *ifname) {
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

/* Build packet */
static int build_packet(config_t *cfg, uint8_t *buffer, int flow_id) {
    int offset = 0;

    /* Ethernet header */
    struct ethhdr *eth = (struct ethhdr *)buffer;
    memcpy(eth->h_dest, cfg->dst_mac, ETH_ALEN);
    memcpy(eth->h_source, cfg->src_mac, ETH_ALEN);

    if (cfg->vlan_id > 0) {
        /* 802.1Q VLAN tag */
        eth->h_proto = htons(ETH_P_8021Q);
        uint16_t *vlan = (uint16_t *)(buffer + ETH_HLEN);
        *vlan = htons((cfg->vlan_priority << 13) | cfg->vlan_id);
        *(vlan + 1) = htons(ETH_P_IP);
        offset = ETH_HLEN + 4;
    } else {
        eth->h_proto = htons(ETH_P_IP);
        offset = ETH_HLEN;
    }

    /* Calculate sizes */
    int ip_payload_size = cfg->packet_size - offset - sizeof(struct iphdr);
    int udp_payload_size = ip_payload_size - sizeof(struct udphdr);

    if (udp_payload_size < 0) udp_payload_size = 0;

    /* IP header */
    struct iphdr *ip = (struct iphdr *)(buffer + offset);
    ip->version = 4;
    ip->ihl = 5;
    ip->tos = cfg->dscp << 2;
    ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + udp_payload_size);
    ip->id = htons(flow_id & 0xFFFF);
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = IPPROTO_UDP;
    ip->check = 0;
    ip->saddr = inet_addr(cfg->src_ip);
    ip->daddr = inet_addr(cfg->dst_ip);
    ip->check = ip_checksum(ip, sizeof(struct iphdr));

    /* UDP header */
    struct udphdr *udp = (struct udphdr *)(buffer + offset + sizeof(struct iphdr));
    udp->source = htons(cfg->src_port + (flow_id % 1000));
    udp->dest = htons(cfg->dst_port);
    udp->len = htons(sizeof(struct udphdr) + udp_payload_size);
    udp->check = 0;  /* Optional for IPv4 */

    /* Payload - fill with pattern */
    uint8_t *payload = buffer + offset + sizeof(struct iphdr) + sizeof(struct udphdr);
    for (int i = 0; i < udp_payload_size; i++) {
        payload[i] = (uint8_t)(i & 0xFF);
    }

    return cfg->packet_size;
}

/* Worker thread */
static void *worker_thread(void *arg) {
    worker_ctx_t *ctx = (worker_ctx_t *)arg;
    config_t *cfg = ctx->config;
    worker_stats_t *stats = ctx->stats;

    /* Create raw socket */
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        perror("socket");
        return NULL;
    }

    /* Increase socket buffer */
    int sndbuf = 64 * 1024 * 1024;
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));

    /* Bind to interface */
    int ifindex = get_interface_index(cfg->interface);
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
    uint8_t **packets = malloc(cfg->batch_size * sizeof(uint8_t *));
    int *packet_sizes = malloc(cfg->batch_size * sizeof(int));

    for (int i = 0; i < cfg->batch_size; i++) {
        packets[i] = aligned_alloc(64, MAX_PACKET_SIZE);
        memset(packets[i], 0, MAX_PACKET_SIZE);
        packet_sizes[i] = build_packet(cfg, packets[i], ctx->worker_id * 1000 + i);
    }

    /* Prepare sendmmsg structures */
    struct mmsghdr *msgs = calloc(cfg->batch_size, sizeof(struct mmsghdr));
    struct iovec *iovecs = calloc(cfg->batch_size, sizeof(struct iovec));

    for (int i = 0; i < cfg->batch_size; i++) {
        iovecs[i].iov_base = packets[i];
        iovecs[i].iov_len = packet_sizes[i];
        msgs[i].msg_hdr.msg_iov = &iovecs[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
    }

    /* Rate limiting */
    double rate_per_worker = cfg->rate_mbps / cfg->num_workers;
    double bytes_per_ns = 0;
    if (rate_per_worker > 0) {
        bytes_per_ns = (rate_per_worker * 1000000.0) / (8.0 * 1e9);
    }

    uint64_t local_packets = 0;
    uint64_t local_bytes = 0;
    uint64_t local_errors = 0;
    struct timespec last_update, now, send_time;
    clock_gettime(CLOCK_MONOTONIC, &last_update);
    send_time = last_update;

    int pkt_idx = 0;

    while (running) {
        /* Send batch of packets */
        int batch = cfg->batch_size;
        int sent = sendmmsg(sock, msgs, batch, 0);

        if (sent > 0) {
            for (int i = 0; i < sent; i++) {
                local_packets++;
                local_bytes += packet_sizes[(pkt_idx + i) % cfg->batch_size];
            }
            pkt_idx = (pkt_idx + sent) % cfg->batch_size;
        } else if (sent < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
            local_errors++;
        }

        /* Rate limiting */
        if (bytes_per_ns > 0) {
            clock_gettime(CLOCK_MONOTONIC, &now);
            double elapsed_ns = (now.tv_sec - send_time.tv_sec) * 1e9 +
                               (now.tv_nsec - send_time.tv_nsec);
            double target_bytes = elapsed_ns * bytes_per_ns;

            if (local_bytes > target_bytes) {
                double sleep_ns = (local_bytes - target_bytes) / bytes_per_ns;
                struct timespec sleep_time = {
                    .tv_sec = (time_t)(sleep_ns / 1e9),
                    .tv_nsec = (long)((uint64_t)sleep_ns % (uint64_t)1e9)
                };
                nanosleep(&sleep_time, NULL);
            }
        }

        /* Update global stats periodically */
        clock_gettime(CLOCK_MONOTONIC, &now);
        double ms_elapsed = (now.tv_sec - last_update.tv_sec) * 1000.0 +
                           (now.tv_nsec - last_update.tv_nsec) / 1e6;

        if (ms_elapsed >= 100) {
            atomic_fetch_add(&stats->packets_sent, local_packets);
            atomic_fetch_add(&stats->bytes_sent, local_bytes);
            atomic_fetch_add(&stats->errors, local_errors);
            local_packets = 0;
            local_bytes = 0;
            local_errors = 0;
            last_update = now;
            send_time = now;
        }
    }

    /* Final stats update */
    atomic_fetch_add(&stats->packets_sent, local_packets);
    atomic_fetch_add(&stats->bytes_sent, local_bytes);
    atomic_fetch_add(&stats->errors, local_errors);

    /* Cleanup */
    for (int i = 0; i < cfg->batch_size; i++) {
        free(packets[i]);
    }
    free(packets);
    free(packet_sizes);
    free(msgs);
    free(iovecs);
    close(sock);

    return NULL;
}

/* Statistics thread */
static void *stats_thread(void *arg) {
    config_t *cfg = (config_t *)arg;

    printf("\n");
    printf("================================================================================\n");
    printf("Traffic Generator - %d workers, %d byte packets\n", cfg->num_workers, cfg->packet_size);
    printf("================================================================================\n");
    printf("%8s | %14s | %12s | %15s | %10s\n",
           "Time", "Packets", "Rate (pps)", "Throughput", "Errors");
    printf("--------------------------------------------------------------------------------\n");

    uint64_t last_packets = 0;
    uint64_t last_bytes = 0;
    struct timespec last_time, now;
    clock_gettime(CLOCK_MONOTONIC, &last_time);

    while (running) {
        usleep(STATS_INTERVAL_MS * 1000);

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

        char throughput_str[32];
        if (throughput_gbps >= 1.0) {
            snprintf(throughput_str, sizeof(throughput_str), "%.2f Gbps", throughput_gbps);
        } else {
            snprintf(throughput_str, sizeof(throughput_str), "%.1f Mbps", throughput_mbps);
        }

        printf("%7.1fs | %14lu | %12.0f | %15s | %10lu\n",
               elapsed, total_packets, pps, throughput_str, total_errors);
        fflush(stdout);

        last_packets = total_packets;
        last_bytes = total_bytes;
        last_time = now;

        /* Check duration */
        if (cfg->duration > 0 && elapsed >= cfg->duration) {
            running = 0;
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

    printf("--------------------------------------------------------------------------------\n");
    printf("\nFinal Summary:\n");
    printf("  Duration:       %.2f seconds\n", total_time);
    printf("  Total Packets:  %lu\n", total_packets);
    printf("  Total Data:     %.3f GB\n", total_bytes / (1024.0 * 1024.0 * 1024.0));
    printf("  Avg Rate:       %.0f pps\n", total_packets / total_time);
    printf("  Avg Throughput: %.3f Gbps\n", (total_bytes * 8.0) / (total_time * 1e9));
    printf("  Errors:         %lu\n", total_errors);
    printf("================================================================================\n");

    return NULL;
}

static void print_usage(const char *prog) {
    printf("High-Performance Traffic Generator\n\n");
    printf("Usage: %s [options]\n\n", prog);
    printf("Required options:\n");
    printf("  -i, --interface IFACE    Network interface (e.g., enp11s0)\n");
    printf("  -d, --dst-ip IP          Destination IP address\n");
    printf("  -m, --dst-mac MAC        Destination MAC address (e.g., 00:11:22:33:44:55)\n");
    printf("\nOptional:\n");
    printf("  -s, --src-ip IP          Source IP (default: 192.168.1.1)\n");
    printf("  -p, --dst-port PORT      Destination UDP port (default: 5001)\n");
    printf("  -P, --src-port PORT      Source UDP port base (default: 10000)\n");
    printf("  -l, --length SIZE        Packet size in bytes (default: 1472)\n");
    printf("  -r, --rate MBPS          Target rate in Mbps (0 = line rate)\n");
    printf("  -t, --duration SEC       Duration in seconds (0 = infinite)\n");
    printf("  -w, --workers N          Number of worker threads (default: CPU cores)\n");
    printf("  -b, --batch SIZE         Batch size for sendmmsg (default: 1024)\n");
    printf("  -v, --vlan ID            VLAN ID (1-4094)\n");
    printf("  -q, --vlan-prio PRI      VLAN priority (0-7)\n");
    printf("  -D, --dscp VALUE         DSCP value (0-63)\n");
    printf("  -h, --help               Show this help\n");
    printf("\nExamples:\n");
    printf("  # Maximum rate traffic\n");
    printf("  sudo %s -i enp11s0 -d 192.168.1.100 -m 00:11:22:33:44:55\n\n", prog);
    printf("  # 1 Gbps with 1024-byte packets\n");
    printf("  sudo %s -i enp11s0 -d 192.168.1.100 -m 00:11:22:33:44:55 -r 1000 -l 1024\n\n", prog);
    printf("  # 10 seconds test with VLAN tagging\n");
    printf("  sudo %s -i enp11s0 -d 192.168.1.100 -m 00:11:22:33:44:55 -t 10 -v 100 -q 5\n", prog);
}

int main(int argc, char *argv[]) {
    /* Default configuration */
    memset(&g_config, 0, sizeof(g_config));
    strcpy(g_config.src_ip, "192.168.1.1");
    g_config.dst_port = 5001;
    g_config.src_port = 10000;
    g_config.packet_size = DEFAULT_PACKET_SIZE;
    g_config.rate_mbps = 0;
    g_config.duration = 0;
    g_config.num_workers = sysconf(_SC_NPROCESSORS_ONLN);
    g_config.batch_size = BATCH_SIZE;
    g_config.vlan_id = 0;
    g_config.vlan_priority = 0;
    g_config.dscp = 0;

    static struct option long_options[] = {
        {"interface", required_argument, 0, 'i'},
        {"dst-ip",    required_argument, 0, 'd'},
        {"dst-mac",   required_argument, 0, 'm'},
        {"src-ip",    required_argument, 0, 's'},
        {"dst-port",  required_argument, 0, 'p'},
        {"src-port",  required_argument, 0, 'P'},
        {"length",    required_argument, 0, 'l'},
        {"rate",      required_argument, 0, 'r'},
        {"duration",  required_argument, 0, 't'},
        {"workers",   required_argument, 0, 'w'},
        {"batch",     required_argument, 0, 'b'},
        {"vlan",      required_argument, 0, 'v'},
        {"vlan-prio", required_argument, 0, 'q'},
        {"dscp",      required_argument, 0, 'D'},
        {"help",      no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    int has_interface = 0, has_dst_ip = 0, has_dst_mac = 0;

    while ((opt = getopt_long(argc, argv, "i:d:m:s:p:P:l:r:t:w:b:v:q:D:h",
                              long_options, NULL)) != -1) {
        switch (opt) {
            case 'i':
                strncpy(g_config.interface, optarg, IFNAMSIZ - 1);
                has_interface = 1;
                break;
            case 'd':
                strncpy(g_config.dst_ip, optarg, INET_ADDRSTRLEN - 1);
                has_dst_ip = 1;
                break;
            case 'm':
                if (parse_mac(optarg, g_config.dst_mac) < 0) {
                    fprintf(stderr, "Invalid MAC address: %s\n", optarg);
                    return 1;
                }
                has_dst_mac = 1;
                break;
            case 's':
                strncpy(g_config.src_ip, optarg, INET_ADDRSTRLEN - 1);
                break;
            case 'p':
                g_config.dst_port = atoi(optarg);
                break;
            case 'P':
                g_config.src_port = atoi(optarg);
                break;
            case 'l':
                g_config.packet_size = atoi(optarg);
                if (g_config.packet_size < 64 || g_config.packet_size > MAX_PACKET_SIZE) {
                    fprintf(stderr, "Packet size must be 64-%d bytes\n", MAX_PACKET_SIZE);
                    return 1;
                }
                break;
            case 'r':
                g_config.rate_mbps = atof(optarg);
                break;
            case 't':
                g_config.duration = atoi(optarg);
                break;
            case 'w':
                g_config.num_workers = atoi(optarg);
                if (g_config.num_workers < 1 || g_config.num_workers > MAX_WORKERS) {
                    fprintf(stderr, "Workers must be 1-%d\n", MAX_WORKERS);
                    return 1;
                }
                break;
            case 'b':
                g_config.batch_size = atoi(optarg);
                break;
            case 'v':
                g_config.vlan_id = atoi(optarg);
                if (g_config.vlan_id < 1 || g_config.vlan_id > 4094) {
                    fprintf(stderr, "VLAN ID must be 1-4094\n");
                    return 1;
                }
                break;
            case 'q':
                g_config.vlan_priority = atoi(optarg);
                if (g_config.vlan_priority < 0 || g_config.vlan_priority > 7) {
                    fprintf(stderr, "VLAN priority must be 0-7\n");
                    return 1;
                }
                break;
            case 'D':
                g_config.dscp = atoi(optarg);
                if (g_config.dscp < 0 || g_config.dscp > 63) {
                    fprintf(stderr, "DSCP must be 0-63\n");
                    return 1;
                }
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    /* Check required arguments */
    if (!has_interface || !has_dst_ip || !has_dst_mac) {
        fprintf(stderr, "Error: Missing required arguments\n\n");
        print_usage(argv[0]);
        return 1;
    }

    /* Check root */
    if (geteuid() != 0) {
        fprintf(stderr, "Error: Root privileges required. Run with sudo.\n");
        return 1;
    }

    /* Get source MAC */
    if (get_interface_mac(g_config.interface, g_config.src_mac) < 0) {
        fprintf(stderr, "Error: Cannot get MAC for interface %s\n", g_config.interface);
        return 1;
    }

    /* Print configuration */
    printf("\nConfiguration:\n");
    printf("  Interface:    %s (%02x:%02x:%02x:%02x:%02x:%02x)\n",
           g_config.interface,
           g_config.src_mac[0], g_config.src_mac[1], g_config.src_mac[2],
           g_config.src_mac[3], g_config.src_mac[4], g_config.src_mac[5]);
    printf("  Destination:  %s (%02x:%02x:%02x:%02x:%02x:%02x)\n",
           g_config.dst_ip,
           g_config.dst_mac[0], g_config.dst_mac[1], g_config.dst_mac[2],
           g_config.dst_mac[3], g_config.dst_mac[4], g_config.dst_mac[5]);
    printf("  Source IP:    %s\n", g_config.src_ip);
    printf("  Ports:        %d -> %d\n", g_config.src_port, g_config.dst_port);
    printf("  Packet Size:  %d bytes\n", g_config.packet_size);
    printf("  Target Rate:  %s\n", g_config.rate_mbps > 0 ?
           "" : "Line Rate (maximum)");
    if (g_config.rate_mbps > 0) {
        printf("                %.0f Mbps (%.2f Gbps)\n",
               g_config.rate_mbps, g_config.rate_mbps / 1000.0);
    }
    printf("  Duration:     %s\n", g_config.duration > 0 ? "" : "Infinite");
    if (g_config.duration > 0) {
        printf("                %d seconds\n", g_config.duration);
    }
    printf("  Workers:      %d threads\n", g_config.num_workers);
    printf("  Batch Size:   %d packets\n", g_config.batch_size);
    if (g_config.vlan_id > 0) {
        printf("  VLAN:         %d (priority: %d)\n", g_config.vlan_id, g_config.vlan_priority);
    }
    if (g_config.dscp > 0) {
        printf("  DSCP:         %d\n", g_config.dscp);
    }

    /* Setup signal handlers */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* Initialize stats */
    memset(g_stats, 0, sizeof(g_stats));

    /* Record start time */
    clock_gettime(CLOCK_MONOTONIC, &g_start_time);

    /* Create worker contexts and start threads */
    worker_ctx_t *contexts = calloc(g_config.num_workers, sizeof(worker_ctx_t));

    for (int i = 0; i < g_config.num_workers; i++) {
        contexts[i].worker_id = i;
        contexts[i].config = &g_config;
        contexts[i].stats = &g_stats[i];

        if (pthread_create(&g_workers[i], NULL, worker_thread, &contexts[i]) != 0) {
            fprintf(stderr, "Failed to create worker thread %d\n", i);
            running = 0;
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
