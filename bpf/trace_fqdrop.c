// project/bpf/trace_fqdrop.c
//
// Trace fq_codel packet drops and mark "local congestion" state
// so the TC egress program can enforce fairness.
//
// This file is CO-RE compatible and should be compiled with clang + libbpf.
//
// NOTE: Kernel symbol names may differ (fq_codel_drop / __fq_codel_drop)
// You can check available symbols via:
//     cat /proc/kallsyms | grep fq_codel

#define __TARGET_ARCH_x86

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define FAIRNESS_WINDOW_NS (2ULL * 1000000000ULL)   // 2 seconds

struct congestion_state {
    __u64 active;        // 1 = fairness mode active, 0 = off
    __u64 expiry_ns;     // timestamp when fairness mode should turn off
    __u64 last_drop_ns;  // last time fq_codel dropped a packet
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct congestion_state);
} congestion_map SEC(".maps");

static __always_inline int mark_congestion(void)
{
    __u32 key = 0;
    __u64 now = bpf_ktime_get_ns();
    struct congestion_state *st = bpf_map_lookup_elem(&congestion_map, &key);

    if (!st)
        return 0;

    st->active       = 1;
    st->last_drop_ns = now;
    st->expiry_ns    = now + FAIRNESS_WINDOW_NS;

    return 0;
}

// Attach to fq_codel drop function
// If your kernel uses __fq_codel_drop, uncomment the alternative section below.
SEC("kprobe/fq_codel_drop")
int BPF_KPROBE(on_fq_codel_drop, void *sch, void *skb)
{
    return mark_congestion();
}

/*
// Optional alternative attach point:
// Uncomment this if your kernel symbol is "__fq_codel_drop"
// SEC("kprobe/__fq_codel_drop")
// int BPF_KPROBE(on___fq_codel_drop, void *sch, void *skb)
// {
//     return mark_congestion();
// }
*/
