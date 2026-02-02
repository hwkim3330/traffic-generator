#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 4 ]]; then
  echo "Usage: $0 <tx_if> <rx_if> <dst_ip> <dst_mac> [rate_mbps] [duration_sec]"
  exit 1
fi

tx_if="$1"
rx_if="$2"
dst_ip="$3"
dst_mac="$4"
rate_mbps="${5:-100}"
duration="${6:-10}"

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tx_bin="${root_dir}/txgen"
rx_bin="${root_dir}/rxcap"

if [[ ! -x "$tx_bin" || ! -x "$rx_bin" ]]; then
  echo "Error: binaries not found. Run 'make' first."
  exit 1
fi

echo "RX: $rx_if, TX: $tx_if, rate: ${rate_mbps} Mbps, duration: ${duration}s"

sudo "$rx_bin" "$rx_if" --seq --latency --seq-only --duration "$duration" &
rx_pid=$!
sleep 1

sudo "$tx_bin" "$tx_if" -B "$dst_ip" -b "$dst_mac" --seq --timestamp \
  -r "$rate_mbps" --duration "$duration"

wait "$rx_pid"
