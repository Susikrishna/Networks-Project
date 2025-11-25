#!/usr/bin/env python3
#
# project/py/stats.py
#
# Live stats watcher for your cgroup-aware congestion controller.
#
# Continuously prints per-cgroup stats from:
#   /sys/fs/bpf/netcong/cg_stats
#
# Usage:
#   sudo python3 stats.py
#

import json
import subprocess
import time
import os
import sys

PIN_STATS = "/sys/fs/bpf/netcong/cg_stats"

REFRESH_INTERVAL = 1.0   # seconds


def run_bpftool(args):
    cmd = ["bpftool"] + args
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
        return out.decode("utf-8", errors="replace")
    except subprocess.CalledProcessError as e:
        print("[ERROR]", e.output.decode("utf-8"))
        sys.exit(1)


def dump_stats():
    if not os.path.exists(PIN_STATS):
        print(f"[!] Stats map not found at {PIN_STATS}")
        print("    Did you pin the maps in loader.py?")
        sys.exit(1)

    out = run_bpftool(["-j", "map", "dump", "pinned", PIN_STATS])
    try:
        entries = json.loads(out)
    except json.JSONDecodeError:
        print("[!] Failed to parse bpftool output")
        print(out)
        sys.exit(1)

    return entries


def print_header():
    print(
        f"{'CGID':>16}  "
        f"{'pkts_passed':>12}  {'bytes_passed':>13}  "
        f"{'pkts_dropped':>12}  {'bytes_dropped':>13}"
    )
    print("-" * 73)


def print_stats(entries):
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


def main():
    print("[*] Live cgroup stats viewer (Ctrl+C to stop)")
    time.sleep(1)

    while True:
        entries = dump_stats()

        os.system("clear")
        print("== cg_stats_map (live view) ==")
        print_header()
        print_stats(entries)

        time.sleep(REFRESH_INTERVAL)


if __name__ == "__main__":
    main()
