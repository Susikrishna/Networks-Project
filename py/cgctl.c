// project/cgctl.c
//
// C replacement for cgctl.py
// Inspect pinned maps:
//   /sys/fs/bpf/netcong/congestion_map
//   /sys/fs/bpf/netcong/cg_buckets
//   /sys/fs/bpf/netcong/cg_stats
//
// Build:
//   gcc -O2 -Wall cgctl.c -o cgctl -lbpf
//
// Usage (as root):
//   ./cgctl congestion
//   ./cgctl buckets
//   ./cgctl stats

#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

#include <bpf/bpf.h>

#define PIN_CONGESTION "/sys/fs/bpf/netcong/congestion_map"
#define PIN_BUCKETS    "/sys/fs/bpf/netcong/cg_buckets"
#define PIN_STATS      "/sys/fs/bpf/netcong/cg_stats"

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

static void show_congestion(void)
{
    int fd = bpf_obj_get(PIN_CONGESTION);
    if (fd < 0)
        die("bpf_obj_get(congestion_map)");

    struct congestion_state st;
    uint32_t key = 0;
    int err = bpf_map_lookup_elem(fd, &key, &st);
    if (err) {
        fprintf(stderr, "lookup congestion_map failed: %s\n", strerror(errno));
        close(fd);
        return;
    }

    printf("== congestion_map ==\n");
    printf("  active      : %llu\n", (unsigned long long)st.active);
    printf("  expiry_ns   : %llu\n", (unsigned long long)st.expiry_ns);
    printf("  last_drop_ns: %llu\n", (unsigned long long)st.last_drop_ns);

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

    // iterate keys
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

    printf("== cg_stats_map (per-cgroup stats) ==\n");
    printf("%16s  %12s  %13s  %12s  %13s\n",
           "CGID",
           "pkts_passed", "bytes_passed",
           "pkts_dropped", "bytes_dropped");

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

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr,
                "Usage: %s {congestion|buckets|stats}\n",
                argv[0]);
        return EXIT_FAILURE;
    }

    if (strcmp(argv[1], "congestion") == 0) {
        show_congestion();
    } else if (strcmp(argv[1], "buckets") == 0) {
        show_buckets();
    } else if (strcmp(argv[1], "stats") == 0) {
        show_stats();
    } else {
        fprintf(stderr, "Unknown command '%s'\n", argv[1]);
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
