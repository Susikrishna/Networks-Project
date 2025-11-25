#!/usr/bin/env bash
set -euo pipefail

# Get the project root directory (one level up from scripts/)
PROJECT_ROOT="$(dirname "$(dirname "$(realpath "$0")")")"
cd "$PROJECT_ROOT"

IFACE="${1:-wlan0}"
SERVER_IP="${2:-1.2.3.4}"
BIN_DIR="bin"

echo "Project Root: $PROJECT_ROOT"
echo "Output Dir:   $BIN_DIR"

mkdir -p "$BIN_DIR"

# --- 1. Build BPF ---
echo "[*] Building BPF programs..."
ARCH=$(uname -m)
if [ "$ARCH" = "x86_64" ]; then ARCH_FLAGS="-D__TARGET_ARCH_x86"
elif [ "$ARCH" = "aarch64" ]; then ARCH_FLAGS="-D__TARGET_ARCH_arm64"
else ARCH_FLAGS="-D__TARGET_ARCH_x86"; fi

# Ensure vmlinux.h exists
if [ ! -f bpf/vmlinux.h ]; then
    bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h
fi

# Compile BPF (Outputting to bin/)
clang -O2 -g -target bpf $ARCH_FLAGS -I./bpf \
    -c bpf/detect.c -o "$BIN_DIR/detect.bpf.o"

clang -O2 -g -target bpf $ARCH_FLAGS -I./bpf \
    -c bpf/enforce.c -o "$BIN_DIR/enforce.bpf.o"

# --- 2. Build User Tools ---
echo "[*] Building User-space tools..."
gcc -O2 -Wall src/daemon.c -o "$BIN_DIR/daemon" -lbpf -lelf -lz
gcc -O2 -Wall src/cli.c    -o "$BIN_DIR/cli"    -lbpf
gcc -O2 -Wall src/monitor.c -o "$BIN_DIR/monitor" -lbpf

# --- 3. Configure Link ---
echo "[*] Configuring TC on $IFACE..."
# Added 'sudo' to these commands because they modify kernel networking settings
sudo tc qdisc del dev $IFACE root 2>/dev/null || true
sudo tc qdisc add dev $IFACE root handle 1: htb default 10
sudo tc class add dev $IFACE parent 1: classid 1:10 htb rate 10mbit ceil 10mbit
sudo tc qdisc add dev $IFACE parent 1:10 fq_codel

# --- 4. Start Daemon ---
echo "[*] Starting Daemon..."
# Run from Project Root so it finds the BPF files in bin/
sudo ./$BIN_DIR/daemon --iface "$IFACE" &
LOADER_PID=$!
echo "Daemon PID=$LOADER_PID"
sleep 2

# --- 5. Traffic Test ---
echo "[*] Generating Traffic..."
cd /sys/fs/cgroup
# Ensure directories exist
sudo mkdir -p A B

# Run 1 light flow in Group A
sudo bash -c 'echo $$ > /sys/fs/cgroup/A/cgroup.procs; iperf3 -c '"$SERVER_IP"' -t 30 -b 0 > /tmp/iperfA.log 2>&1 &' 

# Run many flows in Group B
sudo bash -c 'echo $$ > /sys/fs/cgroup/B/cgroup.procs; for i in $(seq 1 12); do iperf3 -c '"$SERVER_IP"' -t 30 -b 0 > /tmp/iperfB_$i.log 2>&1 & done'

# --- 6. Stats Snapshot ---
echo "[*] Waiting for congestion..."
sleep 10

echo "--- Congestion Status ---"
sudo "$PROJECT_ROOT/$BIN_DIR/cli" congestion

echo "--- Stats ---"
sudo "$PROJECT_ROOT/$BIN_DIR/cli" stats

# --- 7. Cleanup ---
kill $LOADER_PID || true
echo "Done."