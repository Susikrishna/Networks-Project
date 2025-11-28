// project/bpf/enforce.c

// Enforces Token Bucket rate limiting per CGroup when congestion is detected.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

// TC Return Codes
#define TC_ACT_OK       0
#define TC_ACT_SHOT     2

char LICENSE[] SEC("license") = "GPL";

// --- MAPS & STRUCTS ---

// 1. Congestion State (Shared with detect.c)
// Must match the definition in project/bpf/detect.c
struct congestion_state {
    __u64 active;        // 1 = fairness mode active, 0 = off
    __u64 expiry_ns;     // when to stop fairness mode
    __u64 last_drop_ns;  // last drop timestamp
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct congestion_state);
} congestion_map SEC(".maps");

// 2. Per-cgroup token bucket state
struct cg_bucket {
    __u64 last_ts_ns;        // last time tokens were updated
    __s64 tokens;            // current tokens (bytes)
    __u64 rate_bytes_per_s;  // refill rate (bytes/sec)
    __u32 burst_bytes;       // max tokens (bucket size)
    __u32 pad;
};

// 3. Per-cgroup statistics
struct cg_stats {
    __u64 bytes_passed;
    __u64 bytes_dropped;
    __u64 pkts_passed;
    __u64 pkts_dropped;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);        // up to 1024 cgroups
    __type(key, __u64);               // cgroup id
    __type(value, struct cg_bucket);
} cg_buckets SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);               // cgroup id
    __type(value, struct cg_stats);
} cg_stats_map SEC(".maps");

// Default parameters — can be overridden from userspace (cli)
#define DEFAULT_RATE_BYTES_PER_S  1250000ULL   // ~10 Mbit/s per cgroup
#define DEFAULT_BURST_BYTES       65536U       // 64 KB burst

// --- HELPERS ---

static __always_inline int is_fairness_active(void)
{
    __u32 key = 0;
    struct congestion_state *st;
    __u64 now = bpf_ktime_get_ns();

    st = bpf_map_lookup_elem(&congestion_map, &key);
    if (!st)
        return 0;

    if (!st->active)
        return 0;

    if (now > st->expiry_ns) {
        // Fairness window expired, turn it off lazy-style
        st->active = 0;
        return 0;
    }

    return 1;
}

static __always_inline void update_stats(__u64 cg_id, __u32 len, bool passed)
{
    struct cg_stats *st = bpf_map_lookup_elem(&cg_stats_map, &cg_id);
    struct cg_stats zero = {};

    if (!st) {
        // Initialize stats for this cgroup
        if (bpf_map_update_elem(&cg_stats_map, &cg_id, &zero, BPF_NOEXIST) < 0)
            return;
        st = bpf_map_lookup_elem(&cg_stats_map, &cg_id);
        if (!st)
            return;
    }

    if (passed) {
        __sync_fetch_and_add(&st->pkts_passed, 1);
        __sync_fetch_and_add(&st->bytes_passed, len);
    } else {
        __sync_fetch_and_add(&st->pkts_dropped, 1);
        __sync_fetch_and_add(&st->bytes_dropped, len);
    }
}

static __always_inline int enforce_cgroup_bucket(__u64 cg_id, __u32 len)
{
    struct cg_bucket *b;
    struct cg_bucket init = {};
    __u64 now = bpf_ktime_get_ns();

    b = bpf_map_lookup_elem(&cg_buckets, &cg_id);
    if (!b) {
        // First time we see this cgroup — initialize with defaults.
        init.last_ts_ns       = now;
        init.tokens           = (__s64)DEFAULT_BURST_BYTES;
        init.rate_bytes_per_s = DEFAULT_RATE_BYTES_PER_S;
        init.burst_bytes      = DEFAULT_BURST_BYTES;

        if (bpf_map_update_elem(&cg_buckets, &cg_id, &init, BPF_NOEXIST) < 0)
            goto allow; 

        b = bpf_map_lookup_elem(&cg_buckets, &cg_id);
        if (!b)
            goto allow;
    }

    // Refill tokens based on elapsed time.
    if (b->rate_bytes_per_s > 0) {
        __u64 delta_ns = now - b->last_ts_ns;
        if (delta_ns > 0) {
            // calc added tokens: (rate * time) / 1e9
            __u64 added = (b->rate_bytes_per_s * delta_ns) / 1000000000ULL;
            if (added > 0) {
                __s64 new_tokens = b->tokens + (__s64)added;
                if (new_tokens > (__s64)b->burst_bytes)
                    new_tokens = (__s64)b->burst_bytes;
                b->tokens = new_tokens;
                b->last_ts_ns = now;
            }
        }
    }

    // Check balance
    if (b->tokens >= (__s64)len) {
        b->tokens -= (__s64)len;
        update_stats(cg_id, len, true);
        return TC_ACT_OK;  // Allow
    }

    // Not enough tokens → Drop
    update_stats(cg_id, len, false);
    return TC_ACT_SHOT;

allow:
    update_stats(cg_id, len, true);
    return TC_ACT_OK;
}

// --- PROGRAM ---

SEC("tc")
int tc_cgroup_fair_enforcer(struct __sk_buff *skb)
{
    __u32 len = skb->len;
    __u64 cg_id;

    // 1. Check Global Congestion Flag
    if (!is_fairness_active())
        return TC_ACT_OK;

    // 2. Identify CGroup
    cg_id = bpf_get_current_cgroup_id();
    
    if (!cg_id) {
        // Fail open if we can't identify the owner
        return TC_ACT_OK;
    }

    // 3. Apply Token Bucket
    return enforce_cgroup_bucket(cg_id, len);
}