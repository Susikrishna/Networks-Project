// project/bpf/detect.c
//
// Renamed from trace_fqdrop.c
// Detects packet drops via tracepoint and marks congestion state.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define FAIRNESS_WINDOW_NS (2ULL * 1000000000ULL)   // 2 seconds

// --- MAPS ---

// 1. Congestion State (Shared with TC Enforcer)
struct congestion_state {
    __u64 active;        // 1 = fairness mode active, 0 = off
    __u64 expiry_ns;     // timestamp when fairness mode should turn off
    __u64 last_drop_ns;  // last time a packet was dropped
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct congestion_state);
} congestion_map SEC(".maps");

// 2. Configuration Map (Filled by Daemon/Loader)
// Used to filter drops so we only count those on the target interface (e.g. wlan0)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32); // The ifindex of the target interface
} config_map SEC(".maps");

// --- HELPER ---

static __always_inline int mark_congestion(void)
{
    __u32 key = 0;
    __u64 now = bpf_ktime_get_ns();
    struct congestion_state *st = bpf_map_lookup_elem(&congestion_map, &key);

    if (!st)
        return 0;

    // Update state to indicate congestion is happening
    st->active       = 1;
    st->last_drop_ns = now;
    st->expiry_ns    = now + FAIRNESS_WINDOW_NS;
    
    // DEBUG: Print to /sys/kernel/debug/tracing/trace_pipe
    // Useful to confirm the system is catching drops
    bpf_printk("Packet dropped! Congestion mode ACTIVE until: %llu\n", st->expiry_ns);

    return 0;
}

// --- PROGRAM ---

// Hook into the standard kernel event for "packet freed" (kfree_skb)
// This catches fq_codel drops, tail drops, and driver drops.
SEC("tracepoint/skb/kfree_skb")
int trace_skb_drop(struct trace_event_raw_kfree_skb *ctx)
{
    // 1. Retrieve the pointer to the socket buffer (skb)
    // 'skbaddr' is a field in the tracepoint structure defined in vmlinux.h
    struct sk_buff *skb = (struct sk_buff *)ctx->skbaddr;
    
    // 2. Read the interface index from the skb
    // We use BPF_CORE_READ for safety across kernel versions
    u32 skb_ifindex = BPF_CORE_READ(skb, dev, ifindex);

    // 3. Get the target interface index (configured by user space)
    __u32 key = 0;
    __u32 *target_ifindex = bpf_map_lookup_elem(&config_map, &key);

    // If map isn't configured yet, exit safely
    if (!target_ifindex) return 0;

    // 4. Only trigger congestion logic if the drop happened on OUR interface
    if (skb_ifindex == *target_ifindex) {
        mark_congestion();
    }

    return 0;
}