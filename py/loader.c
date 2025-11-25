// project/loader.c
//
// C replacement for loader.py
// - loads trace_fqdrop.bpf.o and tc_enforcer.bpf.o
// - attaches kprobe to fq_codel_drop()
// - attaches TC egress program
// - pins maps so cgctl/stats can access them
//
// Build (example):
//   gcc -O2 -Wall loader.c -o loader -lbpf -lelf -lz
//
// Run (as root):
//   sudo ./loader --iface eth0

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

static struct bpf_link *attach_kprobe_fqdrop(struct bpf_object *obj)
{
    struct bpf_program *prog;
    struct bpf_link *link;
    int err;

    // Program name from trace_fqdrop.c: SEC("kprobe/fq_codel_drop")
    // default name is "on_fq_codel_drop"
    prog = bpf_object__find_program_by_name(obj, "on_fq_codel_drop");
    if (!prog) {
        fprintf(stderr, "[!] Could not find program 'on_fq_codel_drop'\n");
        return NULL;
    }

    link = bpf_program__attach_kprobe(prog, false /* retprobe? */, "fq_codel_drop");
    if (!link) {
        err = -errno;
        fprintf(stderr, "[!] Failed to attach kprobe to fq_codel_drop: %s\n",
                strerror(-err));
        return NULL;
    }

    printf("[+] Attached kprobe to fq_codel_drop\n");
    return link;
}

static int attach_tc_egress(struct bpf_object *obj, const char *ifname)
{
    int ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        fprintf(stderr, "Unknown interface '%s'\n", ifname);
        return -1;
    }

    struct bpf_program *prog;
    int prog_fd, err;

    // program name from tc_enforcer.c: SEC("tc")
    // function: int tc_cgroup_fair_enforcer(struct __sk_buff *skb)
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
    struct bpf_link *kprobe_link = NULL;
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

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(NULL); // quiet, or pass a callback for debug

    printf("[*] Loading %s...\n", fqdrop_obj_path);
    fq_obj = bpf_object__open_file(fqdrop_obj_path, NULL);
    if (!fq_obj)
        die("bpf_object__open_file(trace_fqdrop)");

    err = bpf_object__load(fq_obj);
    if (err)
        die("bpf_object__load(trace_fqdrop)");

    printf("[+] Loaded trace_fqdrop\n");

    printf("[*] Loading %s...\n", tc_obj_path);
    tc_obj = bpf_object__open_file(tc_obj_path, NULL);
    if (!tc_obj)
        die("bpf_object__open_file(tc_enforcer)");

    err = bpf_object__load(tc_obj);
    if (err)
        die("bpf_object__load(tc_enforcer)");

    printf("[+] Loaded tc_enforcer\n");

    // Pin maps so userland tools can read them
    pin_maps(fq_obj, tc_obj);

    // Attach kprobe to fq_codel_drop
    kprobe_link = attach_kprobe_fqdrop(fq_obj);
    if (!kprobe_link) {
        fprintf(stderr, "[!] Failed to attach kprobe; exiting\n");
        goto out;
    }

    // Attach TC egress
    err = attach_tc_egress(tc_obj, ifname);
    if (err) {
        fprintf(stderr, "[!] Failed to attach TC egress; exiting\n");
        goto out;
    }

    printf("[*] Congestion controller running on %s. Press Ctrl+C to exit.\n", ifname);
    for (;;) {
        sleep(1);
    }

out:
    if (kprobe_link)
        bpf_link__destroy(kprobe_link);
    if (tc_obj)
        bpf_object__close(tc_obj);
    if (fq_obj)
        bpf_object__close(fq_obj);
    return err ? EXIT_FAILURE : EXIT_SUCCESS;
}
