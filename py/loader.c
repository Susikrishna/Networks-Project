// project/loader.c
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

static const char *fqdrop_obj_path = "bpf/trace_fqdrop.bpf.o";
static const char *tc_obj_path     = "bpf/tc_enforcer.bpf.o";

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

// Helper to write the interface index into trace_fqdrop's config_map
static int configure_trace_map(struct bpf_object *obj, int ifindex)
{
    struct bpf_map *map = bpf_object__find_map_by_name(obj, "config_map");
    if (!map) {
        fprintf(stderr, "[!] Could not find 'config_map' in trace_fqdrop object\n");
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

static void pin_maps(struct bpf_object *fq_obj, struct bpf_object *tc_obj)
{
    int err;
    char path[256];

    // create base dir
    if (mkdir(PIN_BASE, 0755) && errno != EEXIST) {
        die("mkdir(/sys/fs/bpf/netcong)");
    }

    // congestion_map in trace_fqdrop
    struct bpf_map *cong = bpf_object__find_map_by_name(fq_obj, "congestion_map");
    if (!cong) {
        fprintf(stderr, "[!] congestion_map not found in fqdrop object\n");
    } else {
        snprintf(path, sizeof(path), "%s/%s", PIN_BASE, "congestion_map");
        err = bpf_map__pin(cong, path);
        if (err) {
            fprintf(stderr, "[!] Failed to pin congestion_map: %s\n", strerror(-err));
        } else {
            printf("[+] Pinned congestion_map -> %s\n", path);
        }
    }

    // cg_buckets in tc_enforcer
    struct bpf_map *buckets = bpf_object__find_map_by_name(tc_obj, "cg_buckets");
    if (!buckets) {
        fprintf(stderr, "[!] cg_buckets not found in tc object\n");
    } else {
        snprintf(path, sizeof(path), "%s/%s", PIN_BASE, "cg_buckets");
        err = bpf_map__pin(buckets, path);
        if (err) {
            fprintf(stderr, "[!] Failed to pin cg_buckets: %s\n", strerror(-err));
        } else {
            printf("[+] Pinned cg_buckets -> %s\n", path);
        }
    }

    // cg_stats_map in tc_enforcer
    struct bpf_map *stats = bpf_object__find_map_by_name(tc_obj, "cg_stats_map");
    if (!stats) {
        fprintf(stderr, "[!] cg_stats_map not found in tc object\n");
    } else {
        snprintf(path, sizeof(path), "%s/%s", PIN_BASE, "cg_stats");
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

    // We look for the function name defined in the C file: "trace_skb_drop"
    prog = bpf_object__find_program_by_name(obj, "trace_skb_drop");
    if (!prog) {
        fprintf(stderr, "[!] Could not find program 'trace_skb_drop'\n");
        return NULL;
    }

    // Attach to the standard "skb:kfree_skb" tracepoint
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

    // use libbpf tc-attach API
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
    opts.flags = BPF_TC_F_REPLACE;  // replace if exists

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
    struct bpf_object *fq_obj = NULL, *tc_obj = NULL;
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

    if (!ifname)
        usage(argv[0]);
        
    int ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        fprintf(stderr, "Unknown interface '%s'\n", ifname);
        return EXIT_FAILURE;
    }

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(NULL); 

    // --- 1. Load Trace Object (Congestion Detector) ---
    printf("[*] Loading %s...\n", fqdrop_obj_path);
    fq_obj = bpf_object__open_file(fqdrop_obj_path, NULL);
    if (!fq_obj) die("bpf_object__open_file(trace_fqdrop)");

    err = bpf_object__load(fq_obj);
    if (err) die("bpf_object__load(trace_fqdrop)");

    printf("[+] Loaded trace_fqdrop\n");

    // --- 2. Load TC Object (Enforcer) ---
    printf("[*] Loading %s...\n", tc_obj_path);
    tc_obj = bpf_object__open_file(tc_obj_path, NULL);
    if (!tc_obj) die("bpf_object__open_file(tc_enforcer)");

    err = bpf_object__load(tc_obj);
    if (err) die("bpf_object__load(tc_enforcer)");

    printf("[+] Loaded tc_enforcer\n");

    // --- 3. Pin Maps ---
    pin_maps(fq_obj, tc_obj);

    // --- 4. Configure Trace Filter ---
    // Tell the tracepoint program which interface to watch
    if (configure_trace_map(fq_obj, ifindex) != 0) {
        goto out;
    }

    // --- 5. Attach Tracepoint ---
    trace_link = attach_tracepoint_drop(fq_obj);
    if (!trace_link) {
        fprintf(stderr, "[!] Failed to attach tracepoint; exiting\n");
        goto out;
    }

    // --- 6. Attach TC Egress ---
    err = attach_tc_egress(tc_obj, ifname, ifindex);
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
    if (tc_obj)
        bpf_object__close(tc_obj);
    if (fq_obj)
        bpf_object__close(fq_obj);
    return err ? EXIT_FAILURE : EXIT_SUCCESS;
}