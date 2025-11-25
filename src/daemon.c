// src/daemon.c
//
// Renamed from loader.c
// Main background process that:
// 1. Loads BPF programs (detect.bpf.o and enforce.bpf.o)
// 2. Links them via a shared map (congestion_map)
// 3. Attaches to kernel hooks (Tracepoint + TC)
// 4. Pins maps for the CLI tool

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>
#include <net/if.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#define PIN_BASE "/sys/fs/bpf/netcong"

// Updated paths to match the 'bin' output directory
static const char *detect_obj_path  = "bin/detect.bpf.o";
static const char *enforce_obj_path = "bin/enforce.bpf.o";

static void die(const char *msg)
{
    perror(msg);
    exit(EXIT_FAILURE);
}

static void usage(const char *prog)
{
    fprintf(stderr, "Usage: %s --iface IFACE\n", prog);
    exit(EXIT_FAILURE);
}

// Write the interface index into detect.c's config_map
static int configure_trace_map(struct bpf_object *obj, int ifindex)
{
    struct bpf_map *map = bpf_object__find_map_by_name(obj, "config_map");
    if (!map) {
        fprintf(stderr, "[!] Could not find 'config_map' in detect object\n");
        return -1;
    }

    int map_fd = bpf_map__fd(map);
    uint32_t key = 0;
    uint32_t value = ifindex;

    if (bpf_map_update_elem(map_fd, &key, &value, BPF_ANY) != 0) {
        fprintf(stderr, "[!] Failed to update config_map with ifindex: %s\n", strerror(errno));
        return -1;
    }
    
    printf("[+] Configured trace filter for ifindex: %d\n", ifindex);
    return 0;
}

static void pin_maps(struct bpf_object *detect_obj, struct bpf_object *enforce_obj)
{
    int err;
    char path[256];

    // Create base dir
    if (mkdir(PIN_BASE, 0755) && errno != EEXIST) {
        die("mkdir(/sys/fs/bpf/netcong)");
    }

    // 1. Pin congestion_map (from detect_obj, but shared with enforce_obj)
    struct bpf_map *cong = bpf_object__find_map_by_name(detect_obj, "congestion_map");
    if (!cong) {
        fprintf(stderr, "[!] congestion_map not found in detect object\n");
    } else {
        snprintf(path, sizeof(path), "%s/%s", PIN_BASE, "congestion_map");
        // Remove existing pin to prevent "File exists" errors on restart
        unlink(path);
        err = bpf_map__pin(cong, path);
        if (err) {
            fprintf(stderr, "[!] Failed to pin congestion_map: %s\n", strerror(-err));
        } else {
            printf("[+] Pinned congestion_map -> %s\n", path);
        }
    }

    // 2. Pin cg_buckets (from enforce_obj)
    struct bpf_map *buckets = bpf_object__find_map_by_name(enforce_obj, "cg_buckets");
    if (!buckets) {
        fprintf(stderr, "[!] cg_buckets not found in enforce object\n");
    } else {
        snprintf(path, sizeof(path), "%s/%s", PIN_BASE, "cg_buckets");
        unlink(path);
        err = bpf_map__pin(buckets, path);
        if (err) {
            fprintf(stderr, "[!] Failed to pin cg_buckets: %s\n", strerror(-err));
        } else {
            printf("[+] Pinned cg_buckets -> %s\n", path);
        }
    }

    // 3. Pin cg_stats_map (from enforce_obj)
    struct bpf_map *stats = bpf_object__find_map_by_name(enforce_obj, "cg_stats_map");
    if (!stats) {
        fprintf(stderr, "[!] cg_stats_map not found in enforce object\n");
    } else {
        snprintf(path, sizeof(path), "%s/%s", PIN_BASE, "cg_stats");
        unlink(path);
        err = bpf_map__pin(stats, path);
        if (err) {
            fprintf(stderr, "[!] Failed to pin cg_stats_map: %s\n", strerror(-err));
        } else {
            printf("[+] Pinned cg_stats_map -> %s\n", path);
        }
    }
}

static struct bpf_link *attach_tracepoint_drop(struct bpf_object *obj)
{
    struct bpf_program *prog;
    struct bpf_link *link;
    int err;

    // Defined in detect.c
    prog = bpf_object__find_program_by_name(obj, "trace_skb_drop");
    if (!prog) {
        fprintf(stderr, "[!] Could not find program 'trace_skb_drop'\n");
        return NULL;
    }

    link = bpf_program__attach_tracepoint(prog, "skb", "kfree_skb");
    if (!link) {
        err = -errno;
        fprintf(stderr, "[!] Failed to attach tracepoint skb:kfree_skb: %s\n",
                strerror(-err));
        return NULL;
    }

    printf("[+] Attached tracepoint to skb:kfree_skb\n");
    return link;
}

static int attach_tc_egress(struct bpf_object *obj, const char *ifname, int ifindex)
{
    struct bpf_program *prog;
    int prog_fd, err;

    // Defined in enforce.c
    prog = bpf_object__find_program_by_name(obj, "tc_cgroup_fair_enforcer");
    if (!prog) {
        fprintf(stderr, "[!] Could not find program 'tc_cgroup_fair_enforcer'\n");
        return -1;
    }

    prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) {
        fprintf(stderr, "[!] Invalid program FD\n");
        return -1;
    }

    // Libbpf TC Hook
    struct bpf_tc_hook hook;
    struct bpf_tc_opts opts;

    memset(&hook, 0, sizeof(hook));
    hook.sz = sizeof(hook);
    hook.ifindex = ifindex;
    hook.attach_point = BPF_TC_EGRESS;

    err = bpf_tc_hook_create(&hook);
    if (err && err != -EEXIST) {
        fprintf(stderr, "[!] bpf_tc_hook_create: %s\n", strerror(-err));
        return err;
    }

    memset(&opts, 0, sizeof(opts));
    opts.sz = sizeof(opts);
    opts.prog_fd = prog_fd;
    opts.flags = BPF_TC_F_REPLACE;

    err = bpf_tc_attach(&hook, &opts);
    if (err) {
        fprintf(stderr, "[!] bpf_tc_attach: %s\n", strerror(-err));
        return err;
    }

    printf("[+] Attached TC egress BPF to %s\n", ifname);
    return 0;
}

int main(int argc, char **argv)
{
    const char *ifname = NULL;
    int opt;
    struct bpf_object *detect_obj = NULL, *enforce_obj = NULL;
    struct bpf_link *trace_link = NULL;
    int err;

    static struct option long_opts[] = {
        { "iface", required_argument, NULL, 'i' },
        { "help",  no_argument,       NULL, 'h' },
        { 0, 0, 0, 0 }
    };

    while ((opt = getopt_long(argc, argv, "i:h", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'i':
            ifname = optarg;
            break;
        case 'h':
        default:
            usage(argv[0]);
        }
    }

    if (!ifname) usage(argv[0]);
        
    int ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        fprintf(stderr, "Unknown interface '%s'\n", ifname);
        return EXIT_FAILURE;
    }

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(NULL); 

    // --- 1. Load DETECT Object (Tracepoint) ---
    printf("[*] Loading %s...\n", detect_obj_path);
    detect_obj = bpf_object__open_file(detect_obj_path, NULL);
    if (!detect_obj) die("bpf_object__open_file(detect)");

    err = bpf_object__load(detect_obj);
    if (err) die("bpf_object__load(detect)");

    printf("[+] Loaded detect.bpf.o\n");

    // --- 2. Load ENFORCE Object (TC) with Map Sharing ---
    printf("[*] Loading %s...\n", enforce_obj_path);
    enforce_obj = bpf_object__open_file(enforce_obj_path, NULL);
    if (!enforce_obj) die("bpf_object__open_file(enforce)");

    // CRITICAL: Share 'congestion_map' between objects
    // We want enforce.c to read the SAME map that detect.c writes to.
    struct bpf_map *detect_map = bpf_object__find_map_by_name(detect_obj, "congestion_map");
    struct bpf_map *enforce_map = bpf_object__find_map_by_name(enforce_obj, "congestion_map");

    if (detect_map && enforce_map) {
        int detect_fd = bpf_map__fd(detect_map);
        // reuse the FD from detect object in enforce object
        err = bpf_map__reuse_fd(enforce_map, detect_fd);
        if (err) {
            fprintf(stderr, "[!] Failed to reuse congestion_map FD: %s\n", strerror(-err));
            goto out;
        }
        printf("[+] Map sharing enabled: enforce.c will see detect.c's congestion_map\n");
    } else {
        fprintf(stderr, "[!] WARNING: Could not find congestion_map in one of the objects. Sharing disabled.\n");
    }

    // Now load enforce object (after setting up map reuse)
    err = bpf_object__load(enforce_obj);
    if (err) die("bpf_object__load(enforce)");

    printf("[+] Loaded enforce.bpf.o\n");

    // --- 3. Pin Maps ---
    pin_maps(detect_obj, enforce_obj);

    // --- 4. Configure Trace Filter ---
    if (configure_trace_map(detect_obj, ifindex) != 0) {
        goto out;
    }

    // --- 5. Attach Tracepoint ---
    trace_link = attach_tracepoint_drop(detect_obj);
    if (!trace_link) {
        fprintf(stderr, "[!] Failed to attach tracepoint; exiting\n");
        goto out;
    }

    // --- 6. Attach TC Egress ---
    err = attach_tc_egress(enforce_obj, ifname, ifindex);
    if (err) {
        fprintf(stderr, "[!] Failed to attach TC egress; exiting\n");
        goto out;
    }

    printf("[*] Congestion controller running on %s. Press Ctrl+C to exit.\n", ifname);
    for (;;) {
        sleep(1);
    }

out:
    if (trace_link)
        bpf_link__destroy(trace_link);
    if (enforce_obj)
        bpf_object__close(enforce_obj);
    if (detect_obj)
        bpf_object__close(detect_obj);
    return err ? EXIT_FAILURE : EXIT_SUCCESS;
}