#!/usr/bin/env python3
#
# project/py/loader.py
#
# Loads:
#   - bpf/trace_fqdrop.bpf.o (kprobe on fq_codel_drop)
#   - bpf/tc_enforcer.bpf.o  (TC egress classifier)
#
# Pins maps so cgctl.py and stats.py can read them.
#
# Requirements:
#   pip install libbpf-python pyroute2
#
# Usage:
#   sudo python3 loader.py --iface eth0
#

import argparse
import sys
import time
from pathlib import Path

from bpf import BPFObject  # libbpf-python wrapper

# Base directory where maps will be pinned
PIN_BASE = Path("/sys/fs/bpf/netcong")


# ---------------------------------------------------------
# Attach kprobe helper
# ---------------------------------------------------------
def attach_kprobe(prog, func):
    try:
        link = prog.attach_kprobe(func=func)
        print(f"[+] Attached kprobe to {func}")
        return link
    except Exception as e:
        print(f"[!] Failed to attach kprobe to {func}: {e}")
        return None


# ---------------------------------------------------------
# Attach TC egress classifier
# ---------------------------------------------------------
def attach_tc_bpf(iface, obj, section="tc"):
    from pyroute2 import IPRoute

    ip = IPRoute()
    idx = ip.link_lookup(ifname=iface)[0]

    # Ensure clsact qdisc exists
    try:
        ip.tc("add", "clsact", idx)
        print(f"[+] Added clsact qdisc on {iface}")
    except Exception:
        print(f"[~] clsact already exists on {iface}")

    # Attach BPF classifier
    try:
        link = obj.attach_tc(sec=section, ifname=iface, direction="egress")
        print(f"[+] Attached TC egress BPF ({section}) to {iface}")
        return link
    except Exception as e:
        print(f"[!] Failed attaching TC program: {e}")
        sys.exit(1)


# ---------------------------------------------------------
# Pin maps to bpffs: allows cgctl.py & stats.py to read them
# ---------------------------------------------------------
def pin_maps(fq_obj, tc_obj):
    """
    Pin the BPF maps so other Python tools can access them.
    """
    PIN_BASE.mkdir(parents=True, exist_ok=True)

    # congestion_map from trace_fqdrop
    try:
        cong_map = fq_obj.maps["congestion_map"]
        cong_map.pin(str(PIN_BASE / "congestion_map"))
        print(f"[+] Pinned congestion_map -> {PIN_BASE / 'congestion_map'}")
    except Exception as e:
        print(f"[!] Failed to pin congestion_map: {e}")

    # cg_buckets from tc_enforcer
    try:
        buckets = tc_obj.maps["cg_buckets"]
        buckets.pin(str(PIN_BASE / "cg_buckets"))
        print(f"[+] Pinned cg_buckets -> {PIN_BASE / 'cg_buckets'}")
    except Exception as e:
        print(f"[!] Failed to pin cg_buckets: {e}")

    # cg_stats_map from tc_enforcer
    try:
        stats = tc_obj.maps["cg_stats_map"]
        stats.pin(str(PIN_BASE / "cg_stats"))
        print(f"[+] Pinned cg_stats_map -> {PIN_BASE / 'cg_stats'}")
    except Exception as e:
        print(f"[!] Failed to pin cg_stats_map: {e}")


# ---------------------------------------------------------
# Loader main
# ---------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Load eBPF congestion controller")
    parser.add_argument("--iface", required=True,
                        help="Interface to attach TC program to")
    parser.add_argument("--bpfdir", default="../bpf",
                        help="Directory containing .bpf.o files")
    args = parser.parse_args()

    bpf_dir = Path(args.bpfdir)

    fqdrop_bpf = bpf_dir / "trace_fqdrop.bpf.o"
    tc_bpf = bpf_dir / "tc_enforcer.bpf.o"

    if not fqdrop_bpf.exists() or not tc_bpf.exists():
        print("ERROR: Missing BPF object files. Did you run the build?")
        sys.exit(1)

    # --------------------------
    # Load trace_fqdrop program
    # --------------------------
    print("[*] Loading trace_fqdrop...")
    try:
        fq_obj = BPFObject(str(fqdrop_bpf))
        fq_obj.load()
        print("[+] Loaded trace_fqdrop")
    except Exception as e:
        print(f"[!] Failed to load trace_fqdrop: {e}")
        sys.exit(1)

    # Attach kprobe to fq_codel_drop()
    attach_kprobe(fq_obj, "fq_codel_drop")

    # --------------------------
    # Load tc_enforcer program
    # --------------------------
    print("[*] Loading tc_enforcer...")
    try:
        tc_obj = BPFObject(str(tc_bpf))
        tc_obj.load()
        print("[+] Loaded tc_enforcer")
    except Exception as e:
        print(f"[!] Failed to load tc_enforcer: {e}")
        sys.exit(1)

    # --------------------------
    # 🔴 PIN MAPS (important!)
    # --------------------------
    pin_maps(fq_obj, tc_obj)

    # --------------------------
    # Attach TC egress classifier
    # --------------------------
    attach_tc_bpf(args.iface, tc_obj, section="tc")

    # --------------------------
    # Main loop (keep programs loaded)
    # --------------------------
    print("[*] Congestion control active. Press Ctrl+C to exit.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[!] Exiting...")
        return


if __name__ == "__main__":
    main()
