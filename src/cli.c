// project/cgctl.c

// Usage (as root):
//   ./cgctl congestion
//   ./cgctl buckets
//   ./cgctl stats
//   ./cgctl set_weight <cg_id> <weight>

#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#include <bpf/bpf.h>

#define PIN_CONGESTION "/sys/fs/bpf/netcong/congestion_map"
#define PIN_BUCKETS    "/sys/fs/bpf/netcong/cg_buckets"
#define PIN_STATS      "/sys/fs/bpf/netcong/cg_stats"

// Default parameters must match enforce.c
#define DEFAULT_RATE_BYTES_PER_S  1250000ULL   // ~10 Mbit/s
#define DEFAULT_BURST_BYTES       65536U       // 64 KB

struct congestion_state {
    uint64_t active;
    uint64_t expiry_ns;
    uint64_t last_drop_ns;
};

struct cg_bucket {
    uint64_t last_ts_ns;
    int64_t  tokens;
    uint64_t rate_bytes_per_s;
    uint32_t burst_bytes;
    uint32_t pad;
};

struct cg_stats {
    uint64_t bytes_passed;
    uint64_t bytes_dropped;
    uint64_t pkts_passed;
    uint64_t pkts_dropped;
};

static void die(const char *msg)
{
    perror(msg);
    exit(EXIT_FAILURE);
}

static uint64_t get_time_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static void show_congestion(void)
{
    int fd = bpf_obj_get(PIN_CONGESTION);
    if (fd < 0)
        die("bpf_obj_get(congestion_map)");

    struct congestion_state st;
    uint32_t key = 0;
    if (bpf_map_lookup_elem(fd, &key, &st)) {
        fprintf(stderr, "lookup congestion_map failed: %s\n", strerror(errno));
        close(fd);
        return;
    }

    printf("== congestion_map ==\n");
    printf("  active      : %llu\n", (unsigned long long)st.active);
    printf("  expiry_ns   : %llu\n", (unsigned long long)st.expiry_ns);
    close(fd);
}

static void show_buckets(void)
{
    int fd = bpf_obj_get(PIN_BUCKETS);
    if (fd < 0)
        die("bpf_obj_get(cg_buckets)");

    uint64_t key = 0, next_key;
    struct cg_bucket b;
    int first = 1;

    printf("== cg_buckets (per-cgroup token buckets) ==\n");
    printf("%16s  %14s  %11s  %14s  %18s\n",
           "CGID", "rate_bytes/s", "burst_bytes", "tokens", "last_ts_ns");

    while (bpf_map_get_next_key(fd, first ? NULL : &key, &next_key) == 0) {
        if (bpf_map_lookup_elem(fd, &next_key, &b) == 0) {
            printf("%16llu  %14llu  %11u  %14lld  %18llu\n",
                   (unsigned long long)next_key,
                   (unsigned long long)b.rate_bytes_per_s,
                   b.burst_bytes,
                   (long long)b.tokens,
                   (unsigned long long)b.last_ts_ns);
        }
        key = next_key;
        first = 0;
    }
    close(fd);
}

static void show_stats(void)
{
    int fd = bpf_obj_get(PIN_STATS);
    if (fd < 0)
        die("bpf_obj_get(cg_stats)");

    uint64_t key = 0, next_key;
    struct cg_stats st;
    int first = 1;

    printf("== cg_stats_map ==\n");
    printf("%16s  %12s  %13s  %12s  %13s\n", "CGID", "pkts_pass", "bytes_pass", "pkts_drop", "bytes_drop");

    while (bpf_map_get_next_key(fd, first ? NULL : &key, &next_key) == 0) {
        if (bpf_map_lookup_elem(fd, &next_key, &st) == 0) {
            printf("%16llu  %12llu  %13llu  %12llu  %13llu\n",
                   (unsigned long long)next_key,
                   (unsigned long long)st.pkts_passed,
                   (unsigned long long)st.bytes_passed,
                   (unsigned long long)st.pkts_dropped,
                   (unsigned long long)st.bytes_dropped);
        }
        key = next_key;
        first = 0;
    }
    close(fd);
}

static void set_weight(const char *cg_id_str, const char *weight_str)
{
    int fd = bpf_obj_get(PIN_BUCKETS);
    if (fd < 0)
        die("bpf_obj_get(cg_buckets)");

    uint64_t cg_id = strtoull(cg_id_str, NULL, 10);
    double weight = strtod(weight_str, NULL);

    if (weight <= 0.0) {
        fprintf(stderr, "Error: Weight must be positive.\n");
        close(fd);
        exit(EXIT_FAILURE);
    }

    struct cg_bucket b;
    int exists = (bpf_map_lookup_elem(fd, &cg_id, &b) == 0);

    // Calculate new rate based on default * weight
    uint64_t new_rate = (uint64_t)(DEFAULT_RATE_BYTES_PER_S * weight);
    uint32_t new_burst = DEFAULT_BURST_BYTES; 
    // new_burst = (uint32_t)(DEFAULT_BURST_BYTES * weight);

    if (exists) {
        // UPDATE EXISTING: Preserve tokens and timestamp
        printf("[*] Updating CGroup %llu: Rate %llu -> %llu (Weight %.1f)\n", 
               (unsigned long long)cg_id, 
               (unsigned long long)b.rate_bytes_per_s, 
               (unsigned long long)new_rate, weight);
        
        b.rate_bytes_per_s = new_rate;
        b.burst_bytes = new_burst;
        
        // Cap tokens to new burst if necessary
        if (b.tokens > new_burst) b.tokens = new_burst;

    } else {
        // CREATE NEW: Initialize Fresh
        printf("[*] Creating CGroup %llu: Rate %llu (Weight %.1f)\n", 
               (unsigned long long)cg_id, (unsigned long long)new_rate, weight);

        memset(&b, 0, sizeof(b));
        b.last_ts_ns = get_time_ns();
        b.tokens = new_burst; // Start full
        b.rate_bytes_per_s = new_rate;
        b.burst_bytes = new_burst;
    }

    if (bpf_map_update_elem(fd, &cg_id, &b, BPF_ANY) != 0) {
        perror("bpf_map_update_elem");
    } else {
        printf("[+] Success.\n");
    }

    close(fd);
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr,
                "Usage: %s {congestion|buckets|stats|set_weight <cgid> <val>}\n",
                argv[0]);
        return EXIT_FAILURE;
    }

    if (strcmp(argv[1], "congestion") == 0) {
        show_congestion();
    } else if (strcmp(argv[1], "buckets") == 0) {
        show_buckets();
    } else if (strcmp(argv[1], "stats") == 0) {
        show_stats();
    } else if (strcmp(argv[1], "set_weight") == 0) {
        if (argc != 4) {
            fprintf(stderr, "Usage: %s set_weight <cgroup_id> <weight_multiplier>\n", argv[0]);
            return EXIT_FAILURE;
        }
        set_weight(argv[2], argv[3]);
    } else {
        fprintf(stderr, "Unknown command '%s'\n", argv[1]);
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}