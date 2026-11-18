#!/usr/bin/env bash
# ==============================================================================
# Script: volatile_triage.sh
# Description: Rapid DFIR volatile artifact collector with SHA-256 integrity log
# ==============================================================================

set -euo pipefail

if [[ $# -lt 1 ]]; then
    echo "Usage: sudo $0 <output_directory>"
    exit 1
fi

OUT_DIR="$1/triage_$(hostname)_$(date -u +"%Y%m%dT%H%M%SZ")"
mkdir -p "$OUT_DIR"

echo "[*] Collecting volatile system artifacts into $OUT_DIR..."

date -u > "$OUT_DIR/00_timestamp_utc.txt"
uname -a > "$OUT_DIR/01_kernel_info.txt"
ps auxww > "$OUT_DIR/02_running_processes.txt"
ss -tulnp > "$OUT_DIR/03_network_sockets.txt"
ip addr show > "$OUT_DIR/04_network_interfaces.txt"
last -aiF > "$OUT_DIR/05_login_history.txt"
lsmod > "$OUT_DIR/06_kernel_modules.txt"

if [[ -f /var/log/auth.log ]]; then
    cp /var/log/auth.log "$OUT_DIR/07_auth.log"
fi

echo "[*] Generating SHA-256 Chain of Custody manifest..."
(cd "$OUT_DIR" && sha256sum * > SHA256SUMS.txt)

echo "[+] Triage complete. Manifest saved at $OUT_DIR/SHA256SUMS.txt"
