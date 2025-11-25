#!/usr/bin/env bash
set -euo pipefail

# Get project root
PROJECT_ROOT="$(dirname "$(dirname "$(realpath "$0")")")"
cd "$PROJECT_ROOT"
BIN_DIR="bin"
mkdir -p "$BIN_DIR"

IFACE="lo"
LIMIT="10mbit"

echo "========================================"
echo "   NetCongestion: Aggressive Test       "
echo "========================================"

# --- 1. Cleanup ---
echo "[*] Cleaning up old state..."
sudo killall ping 2>/dev/null || true
sudo killall daemon 2>/dev/null || true
sudo tc qdisc del dev $IFACE root 2>/dev/null || true
sudo rmdir /sys/fs/cgroup/A 2>/dev/null || true
sudo rmdir /sys/fs/cgroup/B 2>/dev/null || true

# --- 2. DISABLE OFFLOADING (Critical for Loopback) ---
echo "[*] Disabling TSO/GSO on $IFACE..."
sudo ethtool -K $IFACE tso off gso off gro off 2>/dev/null || echo "Warning: ethtool failed, drops might be hard to trigger."

# --- 3. Compile BPF ---
echo "[*] Compiling BPF..."
if [ ! -f bpf/vmlinux.h ]; then
    bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h
fi

ARCH=$(uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
clang -O2 -g -target bpf -D__TARGET_ARCH_${ARCH} -I./bpf -c bpf/detect.c -o "$BIN_DIR/detect.bpf.o"
clang -O2 -g -target bpf -D__TARGET_ARCH_${ARCH} -I./bpf -c bpf/enforce.c -o "$BIN_DIR/enforce.bpf.o"

# --- 4. Compile User Tools ---
echo "[*] Compiling User Tools..."
gcc -O2 -Wall src/daemon.c -o "$BIN_DIR/daemon" -lbpf -lelf -lz
gcc -O2 -Wall src/cli.c    -o "$BIN_DIR/cli"    -lbpf

# --- 5. Network Limit (10mbit) ---
echo "[*] Setting $IFACE limit to $LIMIT..."
sudo tc qdisc add dev $IFACE root handle 1: htb default 10
sudo tc class add dev $IFACE parent 1: classid 1:10 htb rate $LIMIT ceil $LIMIT
sudo tc qdisc add dev $IFACE parent 1:10 fq_codel

# --- 6. Start Daemon ---
echo "[*] Starting Daemon..."
sudo ./$BIN_DIR/daemon --iface "$IFACE" > /tmp/daemon.log 2>&1 &
LOADER_PID=$!
sleep 2

# --- 7. Create Traffic Groups ---
echo "[*] Creating Cgroups..."
sudo mkdir -p /sys/fs/cgroup/A
sudo mkdir -p /sys/fs/cgroup/B

echo "[*] 🚀 LAUNCHING ATTACK..."
echo "    Targeting 10mbit limit with 65KB packets..."

# Group A: Nice user
sudo bash -c 'echo $$ > /sys/fs/cgroup/A/cgroup.procs; ping -i 0.2 -c 50 127.0.0.1 > /dev/null &'

# Group B: Bully
# -f: Flood
# -c 500000: Run for a long time
# -s 65000: HUGE packets (Instant buffer overflow)
sudo bash -c 'echo $$ > /sys/fs/cgroup/B/cgroup.procs; ping -f -c 500000 -s 65000 127.0.0.1 > /dev/null 2>&1 &'

# --- 8. Check Results ---
echo "[*] Checking status in 2 seconds..."
sleep 2

echo ""
echo ">>> CONGESTION STATUS <<<"
sudo ./$BIN_DIR/cli congestion

echo ""
echo ">>> DROPS & STATS <<<"
sudo ./$BIN_DIR/cli stats

echo ""
echo ">>> KERNEL DROP VERIFICATION <<<"
sudo tc -s qdisc show dev $IFACE | grep -A 2 "fq_codel"

# --- 9. Cleanup ---
echo ""
echo "[*] Cleaning up..."
sudo kill $LOADER_PID || true
sudo killall ping 2>/dev/null || true
echo "[*] Done."