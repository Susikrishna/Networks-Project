// src/monitor.c
//
// Renamed from stats.c
// Live view of cg_stats_map every 1s.
//
// Build:
//   gcc -O2 -Wall src/monitor.c -o bin/monitor -lbpf
//
// Run (as root):
//   sudo ./bin/monitor

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include <bpf/bpf.h>

#define PIN_STATS "/sys/fs/bpf/netcong/cg_stats"

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

static void print_header(void)
{
    printf("== cg_stats_map (live view) ==\n");
    printf("%16s  %12s  %13s  %12s  %13s\n",
           "CGID",
           "pkts_passed", "bytes_passed",
           "pkts_dropped", "bytes_dropped");
    printf("-------------------------------------------------------------------------\n");
}

int main(void)
{
    int fd = bpf_obj_get(PIN_STATS);
    if (fd < 0)
        die("bpf_obj_get(cg_stats)");

    for (;;) {
        // clear screen
        printf("\033[2J\033[H");
        print_header();

        uint64_t key = 0, next_key;
        struct cg_stats st;
        int first = 1;

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

        fflush(stdout);
        sleep(1);
    }

    close(fd);
    return 0;
}