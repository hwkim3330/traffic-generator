#!/bin/bash
#
# presets.sh - Common traffic generation presets
#
# Usage: source presets.sh
#        udp_flood eth0 192.168.1.100 00:11:22:33:44:55
#

TRAFGEN="$(dirname "${BASH_SOURCE[0]}")/trafgen"

# UDP flood - maximum rate
udp_flood() {
    local iface=$1
    local dst_ip=$2
    local dst_mac=$3
    local rate=${4:-0}

    sudo "$TRAFGEN" -i "$iface" -d "$dst_ip" -m "$dst_mac" \
        -T udp -r "$rate" -l 1472
}

# TCP SYN flood
tcp_syn_flood() {
    local iface=$1
    local dst_ip=$2
    local dst_mac=$3
    local port=${4:-80}

    sudo "$TRAFGEN" -i "$iface" -d "$dst_ip" -m "$dst_mac" \
        -T tcp -p "$port" -r 0
}

# Small packet flood (high pps)
small_pkt_flood() {
    local iface=$1
    local dst_ip=$2
    local dst_mac=$3

    sudo "$TRAFGEN" -i "$iface" -d "$dst_ip" -m "$dst_mac" \
        -l 64 -r 0
}

# Jumbo frame flood
jumbo_flood() {
    local iface=$1
    local dst_ip=$2
    local dst_mac=$3

    sudo "$TRAFGEN" -i "$iface" -d "$dst_ip" -m "$dst_mac" \
        -l 9000 -r 0
}

# VLAN tagged traffic
vlan_traffic() {
    local iface=$1
    local dst_ip=$2
    local dst_mac=$3
    local vlan_id=$4
    local prio=${5:-0}
    local rate=${6:-1000}

    sudo "$TRAFGEN" -i "$iface" -d "$dst_ip" -m "$dst_mac" \
        -v "$vlan_id" -q "$prio" -r "$rate"
}

# QoS marked traffic (DSCP EF for VoIP)
voip_traffic() {
    local iface=$1
    local dst_ip=$2
    local dst_mac=$3
    local rate=${4:-100}

    sudo "$TRAFGEN" -i "$iface" -d "$dst_ip" -m "$dst_mac" \
        -D 46 -l 200 -r "$rate"
}

# Multi-stream for higher throughput
multi_stream() {
    local iface=$1
    local dst_ip=$2
    local dst_mac=$3
    local streams=${4:-4}
    local rate=${5:-0}

    sudo "$TRAFGEN" -i "$iface" -d "$dst_ip" -m "$dst_mac" \
        -n "$streams" -r "$rate"
}

# TSN CBS test - TC2 traffic
tsn_tc2() {
    local iface=$1
    local dst_ip=$2
    local dst_mac=$3
    local vlan=${4:-100}

    # PCP 4-7 -> Priority 2, Target 1.5 Mbps
    sudo "$TRAFGEN" -i "$iface" -d "$dst_ip" -m "$dst_mac" \
        -v "$vlan" -q 4 -r 1500
}

# TSN CBS test - TC6 traffic
tsn_tc6() {
    local iface=$1
    local dst_ip=$2
    local dst_mac=$3
    local vlan=${4:-100}

    # PCP 0-3 -> Priority 6, Target 3.5 Mbps
    sudo "$TRAFGEN" -i "$iface" -d "$dst_ip" -m "$dst_mac" \
        -v "$vlan" -q 0 -r 3500
}

# Bandwidth test - ramp up
bandwidth_ramp() {
    local iface=$1
    local dst_ip=$2
    local dst_mac=$3
    local max_rate=${4:-1000}
    local step=${5:-100}
    local duration=${6:-5}

    echo "Bandwidth ramp test: 0 -> ${max_rate} Mbps"

    for ((rate=step; rate<=max_rate; rate+=step)); do
        echo "Testing at ${rate} Mbps..."
        sudo "$TRAFGEN" -i "$iface" -d "$dst_ip" -m "$dst_mac" \
            -r "$rate" -t "$duration"
        sleep 1
    done
}

echo "Presets loaded. Available functions:"
echo "  udp_flood IFACE DST_IP DST_MAC [RATE]"
echo "  tcp_syn_flood IFACE DST_IP DST_MAC [PORT]"
echo "  small_pkt_flood IFACE DST_IP DST_MAC"
echo "  jumbo_flood IFACE DST_IP DST_MAC"
echo "  vlan_traffic IFACE DST_IP DST_MAC VLAN_ID [PRIO] [RATE]"
echo "  voip_traffic IFACE DST_IP DST_MAC [RATE]"
echo "  multi_stream IFACE DST_IP DST_MAC [STREAMS] [RATE]"
echo "  tsn_tc2 IFACE DST_IP DST_MAC [VLAN]"
echo "  tsn_tc6 IFACE DST_IP DST_MAC [VLAN]"
echo "  bandwidth_ramp IFACE DST_IP DST_MAC [MAX_RATE] [STEP] [DURATION]"
