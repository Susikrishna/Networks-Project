#!/usr/bin/env python3
#
# project/py/cgctl.py
#
# Simple CLI to inspect the eBPF congestion-control maps:
#   - congestion_map   (global congestion state)
#   - cg_buckets       (per-cgroup token buckets)
#   - cg_stats_map     (per-cgroup stats)
#
# It uses `bpftool` under the hood for now, to keep this file simple.
# Later you can switch to libbpf-python and open pinned maps directly.
#
# Usage examples:
#   sudo python3 cgctl.py congestion
#   sudo python3 cgctl.py buckets
#   sudo python3 cgctl.py stats
#
# TODO (for you two):
#   - Add subcommands to update rate/burst for a given cgroup id.
#   - Integrate with libbpf-python instead of shelling out to bpftool.
#

import argparse
import json
import subprocess
import sys
from typing import Any, Dict, List

# Adjust these if you choose different pin paths
PIN_BASE = "/sys/fs/bpf/netcong"
PIN_CONGESTION = f"{PIN_BASE}/congestion_map"
PIN_BUCKETS = f"{PIN_BASE}/cg_buckets"
PIN_STATS = f"{PIN_BASE}/cg_stats"


# ---------------- bpftool helpers ----------------

def run_bpftool(args: List[str]) -> str:
    """Run bpftool and return stdout as string, or exit on error."""
    cmd = ["bpftool"] + args
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
        return out.decode("utf-8", errors="replace")
    except subprocess.CalledProcessError as e:
        print(f"[bpftool error] {' '.join(cmd)}")
        print(e.output.decode("utf-8", errors="replace"))
        sys.exit(1)


def dump_map_json(pinned_path: str) -> List[Dict[str, Any]]:
    """Dump a pinned map in JSON format via bpftool."""
    out = run_bpftool(["-j", "map", "dump", "pinned", pinned_path])
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        print("[!] Failed to parse bpftool JSON output.")
        print(out)
        sys.exit(1)
    return data


# ---------------- pretty printers ----------------

def print_congestion_state() -> None:
    """Show global congestion state from congestion_map."""
    print(f"[*] Reading congestion_map from {PIN_CONGESTION}")
    entries = dump_map_json(PIN_CONGESTION)
    if not entries:
        print("No entries in congestion_map (expected 1).")
        return

    # congestion_map is an ARRAY with 1 element: key=0
    e = entries[0]
    key = e.get("key", {})
    value = e.get("value", {})

    print("== congestion_map ==")
    print(f"  key: {key}")

    # value is a dict of fields like {active, expiry_ns, last_drop_ns}
    active = value.get("active", 0)
    expiry_ns = value.get("expiry_ns", 0)
    last_drop_ns = value.get("last_drop_ns", 0)

    print(f"  active      : {active}")
    print(f"  expiry_ns   : {expiry_ns}")
    print(f"  last_drop_ns: {last_drop_ns}")


def print_buckets() -> None:
    """Show per-cgroup token bucket configuration."""
    print(f"[*] Reading cg_buckets from {PIN_BUCKETS}")
    entries = dump_map_json(PIN_BUCKETS)
    if not entries:
        print("No cgroup buckets found.")
        return

    print("== cg_buckets (per-cgroup token buckets) ==")
    print(f"{'CGID':>16}  {'rate_bytes/s':>14}  {'burst_bytes':>11}  {'tokens':>14}  {'last_ts_ns':>18}")
    for e in entries:
        key = e.get("key", {})
        val = e.get("value", {})

        cg_id = key.get("cg_id", key.get("0", 0))  # bpftool may show key as {"cg_id":...} or {"0":...}

        rate = val.get("rate_bytes_per_s", 0)
        burst = val.get("burst_bytes", 0)
        tokens = val.get("tokens", 0)
        last_ts_ns = val.get("last_ts_ns", 0)

        print(f"{cg_id:16d}  {rate:14d}  {burst:11d}  {tokens:14d}  {last_ts_ns:18d}")


def print_stats() -> None:
    """Show per-cgroup traffic stats."""
    print(f"[*] Reading cg_stats_map from {PIN_STATS}")
    entries = dump_map_json(PIN_STATS)
    if not entries:
        print("No cgroup stats found.")
        return

    print("== cg_stats_map (per-cgroup stats) ==")
    header = (
        f"{'CGID':>16}  "
        f"{'pkts_passed':>12}  {'bytes_passed':>13}  "
        f"{'pkts_dropped':>12}  {'bytes_dropped':>13}"
    )
    print(header)
    for e in entries:
        key = e.get("key", {})
        val = e.get("value", {})

        cg_id = key.get("cg_id", key.get("0", 0))

        pkts_passed = val.get("pkts_passed", 0)
        bytes_passed = val.get("bytes_passed", 0)
        pkts_dropped = val.get("pkts_dropped", 0)
        bytes_dropped = val.get("bytes_dropped", 0)

        print(
            f"{cg_id:16d}  "
            f"{pkts_passed:12d}  {bytes_passed:13d}  "
            f"{pkts_dropped:12d}  {bytes_dropped:13d}"
        )


# ----------- CLI plumbing -----------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Control / inspect cgroup-aware congestion control"
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("congestion", help="Show global congestion state")
    sub.add_parser("buckets", help="List per-cgroup token buckets")
    sub.add_parser("stats", help="List per-cgroup stats")

    args = parser.parse_args()

    if args.cmd == "congestion":
        print_congestion_state()
    elif args.cmd == "buckets":
        print_buckets()
    elif args.cmd == "stats":
        print_stats()
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
