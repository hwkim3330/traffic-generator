#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define APP_NAME "tgd"
#define APP_VERSION "0.1.0"
#define DEFAULT_PORT 8080
#define LISTEN_BACKLOG 64
#define REQ_BUF_SIZE 8192
#define SMALL_BUF 256
#define MED_BUF 1024
#define PATH_BUF 512
#define LARGE_BUF 65536

typedef struct {
    int running;
    pid_t tx_pid;
    pid_t rx_pid;
    time_t started_at;
    char session_dir[PATH_BUF];
    char rx_csv[PATH_BUF];
    char tx_log[PATH_BUF];
    char rx_log[PATH_BUF];
    char live_csv[PATH_BUF];
    int configured_vlan;
} run_state_t;

typedef struct {
    int fd;
    char web_root[PATH_BUF];
    char txgen_path[PATH_BUF];
    char rxcap_path[PATH_BUF];
} client_arg_t;

typedef struct {
    double time_s;
    uint64_t total_pkts;
    double total_pps;
    double total_mbps;
    uint64_t drops;
    uint64_t pcp_pkts[8];
    uint64_t vlan_pkts;
    uint64_t non_vlan_pkts;
    double lat_avg_ns;
    double iat_avg_ns;
    uint64_t seq_missing;
    uint64_t txgen_pkts;
    double jitter_avg_ns;
    int valid;
} metrics_t;

static volatile sig_atomic_t g_stop = 0;
static pthread_mutex_t g_state_mu = PTHREAD_MUTEX_INITIALIZER;
static run_state_t g_state = {0};

static void sig_handler(int sig) {
    (void)sig;
    g_stop = 1;
}

static void now_iso8601(char *out, size_t n) {
    time_t t = time(NULL);
    struct tm tmv;
    localtime_r(&t, &tmv);
    strftime(out, n, "%Y-%m-%d %H:%M:%S", &tmv);
}

static int read_small_text(const char *path, char *out, size_t out_sz) {
    FILE *fp = fopen(path, "r");
    if (!fp) return -1;
    if (!fgets(out, (int)out_sz, fp)) {
        fclose(fp);
        return -1;
    }
    fclose(fp);
    size_t l = strlen(out);
    while (l > 0 && (out[l - 1] == '\n' || out[l - 1] == '\r' || out[l - 1] == ' ' || out[l - 1] == '\t')) {
        out[--l] = 0;
    }
    return 0;
}

static int iface_is_physical(const char *ifname) {
    char p[PATH_BUF];
    snprintf(p, sizeof(p), "/sys/class/net/%s/device", ifname);
    return access(p, F_OK) == 0 ? 1 : 0;
}

static int iface_carrier(const char *ifname) {
    char p[PATH_BUF], b[32];
    snprintf(p, sizeof(p), "/sys/class/net/%s/carrier", ifname);
    if (read_small_text(p, b, sizeof(b)) != 0) return -1;
    return atoi(b);
}

static int get_iface_ipv4(const char *ifname, char *ip_out, size_t ip_out_sz) {
    struct ifaddrs *ifaddr = NULL, *ifa = NULL;
    ip_out[0] = 0;
    if (getifaddrs(&ifaddr) != 0) return -1;
    for (ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_name || !ifa->ifa_addr) continue;
        if (strcmp(ifa->ifa_name, ifname) != 0) continue;
        if (ifa->ifa_addr->sa_family != AF_INET) continue;
        void *addr = &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
        inet_ntop(AF_INET, addr, ip_out, (socklen_t)ip_out_sz);
        freeifaddrs(ifaddr);
        return 0;
    }
    freeifaddrs(ifaddr);
    return -1;
}

static int get_iface_mac(const char *ifname, char *mac_out, size_t mac_out_sz) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return -1;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", ifname);
    if (ioctl(s, SIOCGIFHWADDR, &ifr) != 0) {
        close(s);
        return -1;
    }
    close(s);
    unsigned char *m = (unsigned char*)ifr.ifr_hwaddr.sa_data;
    snprintf(mac_out, mac_out_sz, "%02x:%02x:%02x:%02x:%02x:%02x",
             m[0], m[1], m[2], m[3], m[4], m[5]);
    return 0;
}

static int ensure_dir(const char *p) {
    struct stat st;
    if (stat(p, &st) == 0) return S_ISDIR(st.st_mode) ? 0 : -1;
    return mkdir(p, 0755);
}

static int join_path(char *out, size_t out_sz, const char *a, const char *b) {
    if (!out || !a || !b) return -1;
    size_t la = strlen(a), lb = strlen(b);
    if (la + 1 + lb + 1 > out_sz) return -1;
    memcpy(out, a, la);
    out[la] = '/';
    memcpy(out + la + 1, b, lb);
    out[la + 1 + lb] = 0;
    return 0;
}

static bool is_safe_path_component(const char *s) {
    if (!s || !*s) return false;
    for (const char *p = s; *p; p++) {
        if (!( (*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
               (*p >= '0' && *p <= '9') || *p == '_' || *p == '-' || *p == '.')) {
            return false;
        }
    }
    return true;
}

static int is_valid_tc_spec(const char *s) {
    if (!s || !*s) return 0;
    for (const char *p = s; *p; p++) {
        if (!((*p >= '0' && *p <= '9') || *p == ',' || *p == '-' || *p == ':')) {
            return 0;
        }
    }
    return 1;
}

static void url_decode(char *dst, size_t dst_sz, const char *src) {
    size_t di = 0;
    for (size_t i = 0; src[i] && di + 1 < dst_sz; i++) {
        if (src[i] == '%' && src[i + 1] && src[i + 2]) {
            char hex[3] = {src[i + 1], src[i + 2], 0};
            dst[di++] = (char)strtol(hex, NULL, 16);
            i += 2;
        } else if (src[i] == '+') {
            dst[di++] = ' ';
        } else {
            dst[di++] = src[i];
        }
    }
    dst[di] = 0;
}

static int q_get(const char *query, const char *key, char *out, size_t out_sz) {
    if (!query || !key || !out || out_sz == 0) return -1;
    size_t key_len = strlen(key);
    const char *p = query;
    while (p && *p) {
        const char *amp = strchr(p, '&');
        size_t len = amp ? (size_t)(amp - p) : strlen(p);
        const char *eq = memchr(p, '=', len);
        if (eq) {
            size_t klen = (size_t)(eq - p);
            if (klen == key_len && strncmp(p, key, key_len) == 0) {
                char tmp[SMALL_BUF];
                size_t vlen = len - klen - 1;
                if (vlen >= sizeof(tmp)) vlen = sizeof(tmp) - 1;
                memcpy(tmp, eq + 1, vlen);
                tmp[vlen] = 0;
                url_decode(out, out_sz, tmp);
                return 0;
            }
        }
        p = amp ? amp + 1 : NULL;
    }
    return -1;
}

static int send_all(int fd, const char *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = send(fd, buf + off, len - off, 0);
        if (n <= 0) return -1;
        off += (size_t)n;
    }
    return 0;
}

static void send_json(int fd, int code, const char *body) {
    char hdr[MED_BUF];
    int n = snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 %d OK\r\n"
        "Content-Type: application/json; charset=utf-8\r\n"
        "Cache-Control: no-cache\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Content-Length: %zu\r\n\r\n",
        code, strlen(body));
    if (n > 0) {
        send_all(fd, hdr, (size_t)n);
        send_all(fd, body, strlen(body));
    }
}

static void send_text(int fd, int code, const char *body) {
    char hdr[MED_BUF];
    int n = snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 %d OK\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        "Cache-Control: no-cache\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Content-Length: %zu\r\n\r\n",
        code, strlen(body));
    if (n > 0) {
        send_all(fd, hdr, (size_t)n);
        send_all(fd, body, strlen(body));
    }
}

static void send_404(int fd) {
    send_text(fd, 404, "Not Found\n");
}

static int read_file(const char *path, char **buf_out, size_t *len_out) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return -1;
    if (fseek(fp, 0, SEEK_END) != 0) { fclose(fp); return -1; }
    long sz = ftell(fp);
    if (sz < 0) { fclose(fp); return -1; }
    rewind(fp);
    char *b = (char*)malloc((size_t)sz + 1);
    if (!b) { fclose(fp); return -1; }
    size_t n = fread(b, 1, (size_t)sz, fp);
    fclose(fp);
    b[n] = 0;
    *buf_out = b;
    *len_out = n;
    return 0;
}

static const char* mime_from_path(const char *path) {
    const char *ext = strrchr(path, '.');
    if (!ext) return "application/octet-stream";
    if (strcmp(ext, ".html") == 0) return "text/html; charset=utf-8";
    if (strcmp(ext, ".js") == 0) return "application/javascript; charset=utf-8";
    if (strcmp(ext, ".css") == 0) return "text/css; charset=utf-8";
    if (strcmp(ext, ".json") == 0) return "application/json; charset=utf-8";
    return "application/octet-stream";
}

static void serve_static(int fd, const char *web_root, const char *uri_path) {
    char rel[SMALL_BUF];
    if (strcmp(uri_path, "/") == 0) snprintf(rel, sizeof(rel), "index.html");
    else {
        if (strstr(uri_path, "..")) { send_404(fd); return; }
        snprintf(rel, sizeof(rel), "%s", uri_path + 1);
    }

    char full[MED_BUF];
    snprintf(full, sizeof(full), "%s/%s", web_root, rel);
    char *body = NULL;
    size_t blen = 0;
    if (read_file(full, &body, &blen) != 0) {
        send_404(fd);
        return;
    }
    char hdr[MED_BUF];
    int n = snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: %s\r\n"
        "Cache-Control: no-cache\r\n"
        "Content-Length: %zu\r\n\r\n",
        mime_from_path(full), blen);
    if (n > 0) {
        send_all(fd, hdr, (size_t)n);
        send_all(fd, body, blen);
    }
    free(body);
}

static void update_child_state_locked(void) {
    int st = 0;
    if (g_state.rx_pid > 0) {
        pid_t r = waitpid(g_state.rx_pid, &st, WNOHANG);
        if (r == g_state.rx_pid) g_state.rx_pid = 0;
    }
    if (g_state.tx_pid > 0) {
        pid_t r = waitpid(g_state.tx_pid, &st, WNOHANG);
        if (r == g_state.tx_pid) g_state.tx_pid = 0;
    }
    g_state.running = (g_state.rx_pid > 0 || g_state.tx_pid > 0) ? 1 : 0;
}

static void stop_children_locked(void) {
    if (g_state.tx_pid > 0) kill(g_state.tx_pid, SIGTERM);
    if (g_state.rx_pid > 0) kill(g_state.rx_pid, SIGTERM);
    usleep(200000);
    if (g_state.tx_pid > 0) kill(g_state.tx_pid, SIGKILL);
    if (g_state.rx_pid > 0) kill(g_state.rx_pid, SIGKILL);
    if (g_state.tx_pid > 0) waitpid(g_state.tx_pid, NULL, 0);
    if (g_state.rx_pid > 0) waitpid(g_state.rx_pid, NULL, 0);
    g_state.tx_pid = 0;
    g_state.rx_pid = 0;
    g_state.running = 0;
}

static int parse_last_metrics(const char *csv_path, metrics_t *m) {
    memset(m, 0, sizeof(*m));
    FILE *fp = fopen(csv_path, "r");
    if (!fp) return -1;
    char line[LARGE_BUF];
    char last[LARGE_BUF];
    last[0] = 0;
    while (fgets(line, sizeof(line), fp)) {
        if (line[0] == '\n' || strncmp(line, "time_s", 6) == 0) continue;
        strncpy(last, line, sizeof(last) - 1);
        last[sizeof(last) - 1] = 0;
    }
    fclose(fp);
    if (last[0] == 0) return -1;

    int idx = 0;
    char *save = NULL;
    char *tok = strtok_r(last, ",\n\r", &save);
    while (tok) {
        switch (idx) {
            case 0: m->time_s = atof(tok); break;
            case 1: m->total_pkts = strtoull(tok, NULL, 10); break;
            case 2: m->total_pps = atof(tok); break;
            case 3: m->total_mbps = atof(tok); break;
            case 4: m->drops = strtoull(tok, NULL, 10); break;
            case 5: m->pcp_pkts[0] = strtoull(tok, NULL, 10); break;
            case 6: m->pcp_pkts[1] = strtoull(tok, NULL, 10); break;
            case 7: m->pcp_pkts[2] = strtoull(tok, NULL, 10); break;
            case 8: m->pcp_pkts[3] = strtoull(tok, NULL, 10); break;
            case 9: m->pcp_pkts[4] = strtoull(tok, NULL, 10); break;
            case 10: m->pcp_pkts[5] = strtoull(tok, NULL, 10); break;
            case 11: m->pcp_pkts[6] = strtoull(tok, NULL, 10); break;
            case 12: m->pcp_pkts[7] = strtoull(tok, NULL, 10); break;
            case 13: m->vlan_pkts = strtoull(tok, NULL, 10); break;
            case 14: m->non_vlan_pkts = strtoull(tok, NULL, 10); break;
            case 18: m->lat_avg_ns = atof(tok); break;
            case 21: m->iat_avg_ns = atof(tok); break;
            case 24: m->seq_missing = strtoull(tok, NULL, 10); break;
            case 26: m->txgen_pkts = strtoull(tok, NULL, 10); break;
            case 28: m->jitter_avg_ns = atof(tok); break;
            default: break;
        }
        idx++;
        tok = strtok_r(NULL, ",\n\r", &save);
    }
    m->valid = (idx >= 29);
    return m->valid ? 0 : -1;
}

static int parse_live_csv_line(const char *line, int configured_vlan, char *json, size_t json_sz) {
    /* schema: t,len,src,dst,vlan,pcp,ip.src,ip.dst,sport,dport */
    char buf[MED_BUF];
    snprintf(buf, sizeof(buf), "%s", line);
    char *cols[10] = {0};
    int n = 0;
    char *save = NULL;
    char *tok = strtok_r(buf, ",\r\n", &save);
    while (tok && n < 10) {
        cols[n++] = tok;
        tok = strtok_r(NULL, ",\r\n", &save);
    }
    if (n < 10) return -1;
    long vlan = strtol(cols[4], NULL, 10);
    int vlan_derived = 0;
    if (vlan < 0 && configured_vlan > 0) {
        vlan = configured_vlan;
        vlan_derived = 1;
    }
    snprintf(json, json_sz,
        "{\"t\":%s,\"len\":%s,\"src\":\"%s\",\"dst\":\"%s\","
        "\"vlan\":%ld,\"vlan_derived\":%d,\"pcp\":%s,\"ip_src\":\"%s\",\"ip_dst\":\"%s\","
        "\"sport\":%s,\"dport\":%s}",
        cols[0], cols[1], cols[2], cols[3],
        vlan, vlan_derived, cols[5], cols[6], cols[7], cols[8], cols[9]);
    return 0;
}

static pid_t spawn_to_log(char *const argv[], const char *log_file) {
    pid_t p = fork();
    if (p < 0) return -1;
    if (p == 0) {
        int fd = open(log_file, O_CREAT | O_WRONLY | O_TRUNC, 0644);
        if (fd >= 0) {
            dup2(fd, STDOUT_FILENO);
            dup2(fd, STDERR_FILENO);
            close(fd);
        }
        execvp(argv[0], argv);
        fprintf(stderr, "execvp failed: %s (%s)\n", argv[0], strerror(errno));
        _exit(127);
    }
    return p;
}

static int start_run(const char *txgen_path, const char *rxcap_path, const char *query, char *err, size_t err_sz) {
    if (geteuid() != 0) {
        snprintf(err, err_sz, "root privileges required for raw sockets");
        return -1;
    }
    if (access(txgen_path, X_OK) != 0) {
        snprintf(err, err_sz, "txgen not executable: %s", txgen_path);
        return -1;
    }
    if (access(rxcap_path, X_OK) != 0) {
        snprintf(err, err_sz, "rxcap not executable: %s", rxcap_path);
        return -1;
    }
    char tx_if[64] = {0}, rx_if[64] = {0}, dst_ip[64] = {0}, dst_mac[64] = {0};
    char tc_mode[16] = "multi", tc_spec[64] = "0-7";
    char rate[32] = "100", dur[32] = "10", vlan[32] = "100";
    (void)q_get(query, "tx_if", tx_if, sizeof(tx_if));
    (void)q_get(query, "rx_if", rx_if, sizeof(rx_if));
    (void)q_get(query, "dst_ip", dst_ip, sizeof(dst_ip));
    (void)q_get(query, "dst_mac", dst_mac, sizeof(dst_mac));
    (void)q_get(query, "rate_mbps", rate, sizeof(rate));
    (void)q_get(query, "duration_sec", dur, sizeof(dur));
    (void)q_get(query, "vlan", vlan, sizeof(vlan));
    (void)q_get(query, "tc_mode", tc_mode, sizeof(tc_mode));
    (void)q_get(query, "tc_spec", tc_spec, sizeof(tc_spec));
    if (!is_safe_path_component(tx_if) || !is_safe_path_component(rx_if)) {
        snprintf(err, err_sz, "invalid interface");
        return -1;
    }
    if (strcmp(tx_if, rx_if) == 0) {
        snprintf(err, err_sz, "tx_if and rx_if should be different on same-machine tests");
        return -1;
    }
    if (if_nametoindex(tx_if) == 0 || if_nametoindex(rx_if) == 0) {
        snprintf(err, err_sz, "interface not found");
        return -1;
    }
    if (dst_mac[0] == 0) {
        if (get_iface_mac(rx_if, dst_mac, sizeof(dst_mac)) != 0 || dst_mac[0] == 0) {
            snprintf(err, err_sz, "dst_mac missing and auto-detect failed");
            return -1;
        }
    }
    if (dst_ip[0] == 0) {
        if (get_iface_ipv4(rx_if, dst_ip, sizeof(dst_ip)) != 0 || dst_ip[0] == 0) {
            snprintf(dst_ip, sizeof(dst_ip), "192.168.10.2");
        }
    }
    if (!is_valid_tc_spec(tc_spec)) {
        snprintf(err, err_sz, "invalid tc_spec");
        return -1;
    }
    int single_mode = (strcmp(tc_mode, "single") == 0);

    if (ensure_dir("sessions") != 0) {
        snprintf(err, err_sz, "failed to create sessions dir");
        return -1;
    }

    time_t now = time(NULL);
    struct tm tmv;
    localtime_r(&now, &tmv);
    char sid[64];
    strftime(sid, sizeof(sid), "run_%Y%m%d_%H%M%S", &tmv);
    char sdir[PATH_BUF];
    snprintf(sdir, sizeof(sdir), "sessions/%s", sid);
    if (ensure_dir(sdir) != 0) {
        snprintf(err, err_sz, "failed to create session dir");
        return -1;
    }
    char rx_csv[PATH_BUF], tx_log[PATH_BUF], rx_log[PATH_BUF], live_csv[PATH_BUF];
    if (join_path(rx_csv, sizeof(rx_csv), sdir, "rx.csv") != 0 ||
        join_path(tx_log, sizeof(tx_log), sdir, "tx.log") != 0 ||
        join_path(rx_log, sizeof(rx_log), sdir, "rx.log") != 0 ||
        join_path(live_csv, sizeof(live_csv), sdir, "live.csv") != 0) {
        snprintf(err, err_sz, "session path too long");
        return -1;
    }

    char multi_tc_vlan[64];
    if (strchr(tc_spec, ':')) snprintf(multi_tc_vlan, sizeof(multi_tc_vlan), "%s", tc_spec);
    else snprintf(multi_tc_vlan, sizeof(multi_tc_vlan), "%s:%s", tc_spec, vlan);
    char single_vlan[32];
    const char *tc_base = tc_spec;
    char *colon = strchr(tc_spec, ':');
    if (colon) {
        size_t n = (size_t)(colon - tc_spec);
        if (n >= sizeof(single_vlan)) n = sizeof(single_vlan) - 1;
        memcpy(single_vlan, tc_spec, n);
        single_vlan[n] = 0;
        tc_base = single_vlan;
    }
    char pcp_vlan[64];
    snprintf(pcp_vlan, sizeof(pcp_vlan), "%s:%s", tc_base, vlan);

    char *rx_argv[] = {
        (char*)rxcap_path, (char*)rx_if,
        (char*)"--seq", (char*)"--latency", (char*)"--seq-only",
        (char*)"--txgen-only", (char*)"--pcp-stats",
        (char*)"--live-file", live_csv, (char*)"--live-rate-ms", (char*)"100",
        (char*)"--csv", rx_csv, (char*)"--duration", dur, NULL
    };
    char *tx_argv_multi[] = {
        (char*)txgen_path, (char*)tx_if,
        (char*)"-B", (char*)dst_ip, (char*)"-b", (char*)dst_mac,
        (char*)"--seq", (char*)"--timestamp",
        (char*)"--multi-tc", multi_tc_vlan, (char*)"--rate-per-tc",
        (char*)"-r", (char*)rate, (char*)"--duration", (char*)dur, NULL
    };
    char *tx_argv_single[] = {
        (char*)txgen_path, (char*)tx_if,
        (char*)"-B", (char*)dst_ip, (char*)"-b", (char*)dst_mac,
        (char*)"--seq", (char*)"--timestamp",
        (char*)"-Q", pcp_vlan,
        (char*)"-r", (char*)rate, (char*)"--duration", (char*)dur, NULL
    };

    pthread_mutex_lock(&g_state_mu);
    stop_children_locked();
    pthread_mutex_unlock(&g_state_mu);

    pid_t rxp = spawn_to_log(rx_argv, rx_log);
    if (rxp <= 0) {
        snprintf(err, err_sz, "failed to start rxcap");
        return -1;
    }
    usleep(250000);
    int st = 0;
    pid_t w = waitpid(rxp, &st, WNOHANG);
    if (w == rxp) {
        snprintf(err, err_sz, "rxcap exited immediately (check session rx.log)");
        return -1;
    }

    pid_t txp = spawn_to_log(single_mode ? tx_argv_single : tx_argv_multi, tx_log);
    if (txp <= 0) {
        kill(rxp, SIGTERM);
        waitpid(rxp, NULL, 0);
        snprintf(err, err_sz, "failed to start txgen");
        return -1;
    }
    usleep(250000);
    w = waitpid(txp, &st, WNOHANG);
    if (w == txp) {
        kill(rxp, SIGTERM);
        waitpid(rxp, NULL, 0);
        snprintf(err, err_sz, "txgen exited immediately (check session tx.log)");
        return -1;
    }

    pthread_mutex_lock(&g_state_mu);
    g_state.running = 1;
    g_state.rx_pid = rxp;
    g_state.tx_pid = txp;
    g_state.started_at = now;
    snprintf(g_state.session_dir, sizeof(g_state.session_dir), "%s", sdir);
    snprintf(g_state.rx_csv, sizeof(g_state.rx_csv), "%s", rx_csv);
    snprintf(g_state.tx_log, sizeof(g_state.tx_log), "%s", tx_log);
    snprintf(g_state.rx_log, sizeof(g_state.rx_log), "%s", rx_log);
    snprintf(g_state.live_csv, sizeof(g_state.live_csv), "%s", live_csv);
    g_state.configured_vlan = atoi(vlan);
    pthread_mutex_unlock(&g_state_mu);
    return 0;
}

static void api_interfaces(int fd) {
    char json[LARGE_BUF];
    size_t off = 0;
    off += snprintf(json + off, sizeof(json) - off, "{\"ok\":true,\"interfaces\":[");

    struct if_nameindex *ifs = if_nameindex();
    if (!ifs) {
        send_json(fd, 500, "{\"ok\":false,\"error\":\"if_nameindex failed\"}");
        return;
    }

    int first = 1;
    for (struct if_nameindex *it = ifs; it && it->if_name; it++) {
        const char *ifname = it->if_name;
        if (strcmp(ifname, "lo") == 0) continue;
        if (!iface_is_physical(ifname)) continue;

        char ip[64] = "";
        (void)get_iface_ipv4(ifname, ip, sizeof(ip));

        int s = socket(AF_INET, SOCK_DGRAM, 0);
        if (s < 0) continue;
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        snprintf(ifr.ifr_name, IFNAMSIZ, "%s", ifname);
        if (ioctl(s, SIOCGIFFLAGS, &ifr) != 0) { close(s); continue; }
        int up = (ifr.ifr_flags & IFF_UP) ? 1 : 0;
        int running = (ifr.ifr_flags & IFF_RUNNING) ? 1 : 0;
        int carrier = iface_carrier(ifname);

        char mac[32] = "";
        if (ioctl(s, SIOCGIFHWADDR, &ifr) == 0) {
            unsigned char *m = (unsigned char*)ifr.ifr_hwaddr.sa_data;
            snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x",
                     m[0], m[1], m[2], m[3], m[4], m[5]);
        }
        close(s);

        if (!first) off += snprintf(json + off, sizeof(json) - off, ",");
        first = 0;
        off += snprintf(json + off, sizeof(json) - off,
            "{\"name\":\"%s\",\"ip\":\"%s\",\"mac\":\"%s\",\"up\":%d,\"running\":%d,\"carrier\":%d}",
            ifname, ip, mac, up, running, carrier);
        if (off + 128 >= sizeof(json)) break;
    }
    if_freenameindex(ifs);
    off += snprintf(json + off, sizeof(json) - off, "]}");
    send_json(fd, 200, json);
}

static void api_status(int fd) {
    pthread_mutex_lock(&g_state_mu);
    update_child_state_locked();
    run_state_t st = g_state;
    pthread_mutex_unlock(&g_state_mu);

    metrics_t m;
    int has_metrics = (st.rx_csv[0] && parse_last_metrics(st.rx_csv, &m) == 0);

    char started[64] = "";
    if (st.started_at > 0) {
        struct tm tmv;
        localtime_r(&st.started_at, &tmv);
        strftime(started, sizeof(started), "%Y-%m-%d %H:%M:%S", &tmv);
    }

    char body[LARGE_BUF];
    snprintf(body, sizeof(body),
        "{\"ok\":true,\"running\":%s,\"tx_pid\":%d,\"rx_pid\":%d,"
        "\"started_at\":\"%s\",\"session_dir\":\"%s\","
        "\"metrics\":{\"valid\":%s,\"time_s\":%.3f,\"pps\":%.0f,\"mbps\":%.3f,"
        "\"drops\":%llu,\"vlan_pkts\":%llu,\"non_vlan_pkts\":%llu,"
        "\"pcp\":[%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu],"
        "\"lat_avg_ns\":%.0f,\"iat_avg_ns\":%.0f,"
        "\"seq_missing\":%llu,\"txgen_pkts\":%llu,\"jitter_avg_ns\":%.0f}}",
        st.running ? "true" : "false", (int)st.tx_pid, (int)st.rx_pid,
        started, st.session_dir,
        has_metrics ? "true" : "false",
        has_metrics ? m.time_s : 0.0,
        has_metrics ? m.total_pps : 0.0,
        has_metrics ? m.total_mbps : 0.0,
        (unsigned long long)(has_metrics ? m.drops : 0ULL),
        (unsigned long long)(has_metrics ? m.vlan_pkts : 0ULL),
        (unsigned long long)(has_metrics ? m.non_vlan_pkts : 0ULL),
        (unsigned long long)(has_metrics ? m.pcp_pkts[0] : 0ULL),
        (unsigned long long)(has_metrics ? m.pcp_pkts[1] : 0ULL),
        (unsigned long long)(has_metrics ? m.pcp_pkts[2] : 0ULL),
        (unsigned long long)(has_metrics ? m.pcp_pkts[3] : 0ULL),
        (unsigned long long)(has_metrics ? m.pcp_pkts[4] : 0ULL),
        (unsigned long long)(has_metrics ? m.pcp_pkts[5] : 0ULL),
        (unsigned long long)(has_metrics ? m.pcp_pkts[6] : 0ULL),
        (unsigned long long)(has_metrics ? m.pcp_pkts[7] : 0ULL),
        has_metrics ? m.lat_avg_ns : 0.0,
        has_metrics ? m.iat_avg_ns : 0.0,
        (unsigned long long)(has_metrics ? m.seq_missing : 0ULL),
        (unsigned long long)(has_metrics ? m.txgen_pkts : 0ULL),
        has_metrics ? m.jitter_avg_ns : 0.0);

    send_json(fd, 200, body);
}

static void api_stop(int fd) {
    pthread_mutex_lock(&g_state_mu);
    stop_children_locked();
    pthread_mutex_unlock(&g_state_mu);
    send_json(fd, 200, "{\"ok\":true,\"stopped\":true}");
}

static void api_start(int fd, const char *txgen_path, const char *rxcap_path, const char *query) {
    char err[SMALL_BUF];
    if (start_run(txgen_path, rxcap_path, query, err, sizeof(err)) != 0) {
        char body[MED_BUF];
        snprintf(body, sizeof(body), "{\"ok\":false,\"error\":\"%s\"}", err);
        send_json(fd, 400, body);
        return;
    }
    send_json(fd, 200, "{\"ok\":true}");
}

static void api_stream(int fd) {
    const char *hdr =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/event-stream\r\n"
        "Cache-Control: no-cache\r\n"
        "Connection: keep-alive\r\n"
        "Access-Control-Allow-Origin: *\r\n\r\n";
    if (send_all(fd, hdr, strlen(hdr)) != 0) return;

    char stream_session[PATH_BUF] = "";
    FILE *live_fp = NULL;
    long live_pos = 0;

    while (!g_stop) {
        pthread_mutex_lock(&g_state_mu);
        update_child_state_locked();
        run_state_t st = g_state;
        pthread_mutex_unlock(&g_state_mu);

        metrics_t m;
        int has_metrics = 0;
        if (st.running && st.rx_csv[0]) {
            has_metrics = (parse_last_metrics(st.rx_csv, &m) == 0);
        }

        char msg[MED_BUF];
        int n = snprintf(msg, sizeof(msg),
            "data: {\"running\":%s,\"session\":\"%s\",\"metrics\":{\"valid\":%s,"
            "\"time_s\":%.3f,\"pps\":%.0f,\"mbps\":%.3f,\"drops\":%llu,"
            "\"vlan_pkts\":%llu,\"non_vlan_pkts\":%llu,"
            "\"pcp\":[%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu],"
            "\"lat_avg_ns\":%.0f,\"jitter_avg_ns\":%.0f,\"seq_missing\":%llu}}\n\n",
            st.running ? "true" : "false",
            st.session_dir,
            has_metrics ? "true" : "false",
            has_metrics ? m.time_s : 0.0,
            has_metrics ? m.total_pps : 0.0,
            has_metrics ? m.total_mbps : 0.0,
            (unsigned long long)(has_metrics ? m.drops : 0ULL),
            (unsigned long long)(has_metrics ? m.vlan_pkts : 0ULL),
            (unsigned long long)(has_metrics ? m.non_vlan_pkts : 0ULL),
            (unsigned long long)(has_metrics ? m.pcp_pkts[0] : 0ULL),
            (unsigned long long)(has_metrics ? m.pcp_pkts[1] : 0ULL),
            (unsigned long long)(has_metrics ? m.pcp_pkts[2] : 0ULL),
            (unsigned long long)(has_metrics ? m.pcp_pkts[3] : 0ULL),
            (unsigned long long)(has_metrics ? m.pcp_pkts[4] : 0ULL),
            (unsigned long long)(has_metrics ? m.pcp_pkts[5] : 0ULL),
            (unsigned long long)(has_metrics ? m.pcp_pkts[6] : 0ULL),
            (unsigned long long)(has_metrics ? m.pcp_pkts[7] : 0ULL),
            has_metrics ? m.lat_avg_ns : 0.0,
            has_metrics ? m.jitter_avg_ns : 0.0,
            (unsigned long long)(has_metrics ? m.seq_missing : 0ULL));
        if (n <= 0 || send_all(fd, msg, (size_t)n) != 0) break;

        /* Incremental packet stream for UI table */
        if (st.running && st.live_csv[0]) {
            if (strcmp(stream_session, st.session_dir) != 0) {
                if (live_fp) fclose(live_fp);
                live_fp = fopen(st.live_csv, "r");
                live_pos = 0;
                snprintf(stream_session, sizeof(stream_session), "%s", st.session_dir);
            }
            if (live_fp) {
                if (fseek(live_fp, live_pos, SEEK_SET) == 0) {
                    char line[MED_BUF];
                    while (fgets(line, sizeof(line), live_fp)) {
                        if (strncmp(line, "t,", 2) == 0) continue;
                        char pj[MED_BUF];
                        if (parse_live_csv_line(line, st.configured_vlan, pj, sizeof(pj)) == 0) {
                            char ev[MED_BUF + 64];
                            int en = snprintf(ev, sizeof(ev), "event: packet\ndata: %s\n\n", pj);
                            if (en > 0 && send_all(fd, ev, (size_t)en) != 0) goto done;
                        }
                    }
                    live_pos = ftell(live_fp);
                }
            }
        }
        sleep(1);
    }
done:
    if (live_fp) fclose(live_fp);
}

static void* client_thread(void *arg) {
    client_arg_t *c = (client_arg_t*)arg;
    int fd = c->fd;
    char web_root[PATH_BUF], txgen_path[PATH_BUF], rxcap_path[PATH_BUF];
    snprintf(web_root, sizeof(web_root), "%s", c->web_root);
    snprintf(txgen_path, sizeof(txgen_path), "%s", c->txgen_path);
    snprintf(rxcap_path, sizeof(rxcap_path), "%s", c->rxcap_path);
    free(c);

    char req[REQ_BUF_SIZE];
    ssize_t r = recv(fd, req, sizeof(req) - 1, 0);
    if (r <= 0) { close(fd); return NULL; }
    req[r] = 0;

    char method[16] = {0}, uri[SMALL_BUF] = {0}, proto[16] = {0};
    if (sscanf(req, "%15s %255s %15s", method, uri, proto) != 3) {
        close(fd); return NULL;
    }

    char path[SMALL_BUF], query[MED_BUF];
    path[0] = 0; query[0] = 0;
    char *qm = strchr(uri, '?');
    if (qm) {
        size_t plen = (size_t)(qm - uri);
        if (plen >= sizeof(path)) plen = sizeof(path) - 1;
        memcpy(path, uri, plen);
        path[plen] = 0;
        snprintf(query, sizeof(query), "%s", qm + 1);
    } else {
        snprintf(path, sizeof(path), "%s", uri);
    }

    if (strcmp(path, "/api/interfaces") == 0) {
        api_interfaces(fd);
    } else if (strcmp(path, "/api/status") == 0) {
        api_status(fd);
    } else if (strcmp(path, "/api/start") == 0 && strcmp(method, "POST") == 0) {
        api_start(fd, txgen_path, rxcap_path, query);
    } else if (strcmp(path, "/api/stop") == 0 && strcmp(method, "POST") == 0) {
        api_stop(fd);
    } else if (strcmp(path, "/api/stream") == 0) {
        api_stream(fd);
    } else {
        serve_static(fd, web_root, path);
    }

    close(fd);
    return NULL;
}

static void usage(const char *p) {
    printf("%s v%s\n", APP_NAME, APP_VERSION);
    printf("Usage: %s [--port N] [--web-root DIR] [--txgen PATH] [--rxcap PATH]\n", p);
}

int main(int argc, char **argv) {
    int port = DEFAULT_PORT;
    char web_root[PATH_BUF] = "web";
    char txgen_path[PATH_BUF] = "./txgen";
    char rxcap_path[PATH_BUF] = "./rxcap";

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--web-root") == 0 && i + 1 < argc) {
            snprintf(web_root, sizeof(web_root), "%s", argv[++i]);
        } else if (strcmp(argv[i], "--txgen") == 0 && i + 1 < argc) {
            snprintf(txgen_path, sizeof(txgen_path), "%s", argv[++i]);
        } else if (strcmp(argv[i], "--rxcap") == 0 && i + 1 < argc) {
            snprintf(rxcap_path, sizeof(rxcap_path), "%s", argv[++i]);
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        }
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    int sfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sfd < 0) {
        perror("socket");
        return 1;
    }
    int yes = 1;
    setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons((uint16_t)port);

    if (bind(sfd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        perror("bind");
        close(sfd);
        return 1;
    }
    if (listen(sfd, LISTEN_BACKLOG) != 0) {
        perror("listen");
        close(sfd);
        return 1;
    }

    char ts[64];
    now_iso8601(ts, sizeof(ts));
    printf("[%s] %s listening on 0.0.0.0:%d\n", ts, APP_NAME, port);
    printf("[%s] web_root=%s txgen=%s rxcap=%s\n", ts, web_root, txgen_path, rxcap_path);

    while (!g_stop) {
        struct sockaddr_in cli;
        socklen_t cl = sizeof(cli);
        int cfd = accept(sfd, (struct sockaddr*)&cli, &cl);
        if (cfd < 0) {
            if (errno == EINTR) continue;
            perror("accept");
            break;
        }

        client_arg_t *ca = (client_arg_t*)calloc(1, sizeof(client_arg_t));
        if (!ca) { close(cfd); continue; }
        ca->fd = cfd;
        snprintf(ca->web_root, sizeof(ca->web_root), "%s", web_root);
        snprintf(ca->txgen_path, sizeof(ca->txgen_path), "%s", txgen_path);
        snprintf(ca->rxcap_path, sizeof(ca->rxcap_path), "%s", rxcap_path);

        pthread_t th;
        if (pthread_create(&th, NULL, client_thread, ca) == 0) {
            pthread_detach(th);
        } else {
            free(ca);
            close(cfd);
        }
    }

    pthread_mutex_lock(&g_state_mu);
    stop_children_locked();
    pthread_mutex_unlock(&g_state_mu);
    close(sfd);
    return 0;
}
