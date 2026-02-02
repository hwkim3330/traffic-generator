#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "Usage: $0 <iface> <on|off>"
  exit 1
fi

iface="$1"
state="$2"

case "$state" in
  on|off) ;;
  *)
    echo "Error: state must be 'on' or 'off'"
    exit 1
    ;;
esac

sudo ethtool -K "$iface" tso "$state" gso "$state" gro "$state" lro "$state"
