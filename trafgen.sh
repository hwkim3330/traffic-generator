#!/bin/bash
#
# trafgen.sh - High-Performance Traffic Generator Wrapper
# Wraps mz (Mausezahn) with enhanced features for 1Gbps+ traffic generation
#
# Requirements: netsniff-ng package (contains mz)
# Install: sudo apt-get install netsniff-ng
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Default values
INTERFACE=""
DST_IP=""
DST_MAC=""
SRC_IP=""
SRC_PORT=10000
DST_PORT=5001
PACKET_SIZE=1472
RATE_MBPS=0
DURATION=0
VLAN_ID=""
VLAN_PRIO=0
DSCP=0
PROTOCOL="udp"
WORKERS=1
PAYLOAD=""

print_banner() {
    echo -e "${BLUE}"
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║     High-Performance Traffic Generator (mz wrapper)        ║"
    echo "║                    1Gbps+ Capable                          ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

print_usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Required:
  -i, --interface IFACE    Network interface (e.g., enp11s0)
  -d, --dst-ip IP          Destination IP address
  -m, --dst-mac MAC        Destination MAC address

Optional:
  -s, --src-ip IP          Source IP (default: interface IP)
  -p, --dst-port PORT      Destination port (default: 5001)
  -P, --src-port PORT      Source port (default: 10000)
  -l, --length SIZE        Packet size in bytes (default: 1472)
  -r, --rate MBPS          Target rate in Mbps (0 = max)
  -t, --duration SEC       Duration in seconds (0 = infinite)
  -w, --workers N          Number of parallel streams (default: 1)
  -v, --vlan ID            VLAN ID (1-4094)
  -q, --vlan-prio PRI      VLAN priority 0-7 (default: 0)
  -D, --dscp VALUE         DSCP value 0-63 (default: 0)
  -T, --type TYPE          Protocol: udp, tcp, icmp (default: udp)
  -x, --payload TEXT       Custom payload string
  -h, --help               Show this help

Examples:
  # Maximum rate UDP traffic
  $0 -i enp11s0 -d 192.168.1.100 -m 00:11:22:33:44:55

  # 1 Gbps with 1024-byte packets
  $0 -i enp11s0 -d 192.168.1.100 -m 00:11:22:33:44:55 -r 1000 -l 1024

  # 10 seconds test with VLAN
  $0 -i enp11s0 -d 192.168.1.100 -m 00:11:22:33:44:55 -t 10 -v 100 -q 5

  # Multi-stream for higher throughput
  $0 -i enp11s0 -d 192.168.1.100 -m 00:11:22:33:44:55 -w 4 -r 2500
EOF
}

check_requirements() {
    if ! command -v mz &> /dev/null; then
        echo -e "${RED}Error: mz (Mausezahn) not found${NC}"
        echo "Install with: sudo apt-get install netsniff-ng"
        exit 1
    fi

    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}Error: Root privileges required${NC}"
        echo "Run with: sudo $0 ..."
        exit 1
    fi
}

get_interface_ip() {
    local iface=$1
    ip -4 addr show "$iface" 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1
}

get_interface_mac() {
    local iface=$1
    cat /sys/class/net/"$iface"/address 2>/dev/null
}

calculate_delay() {
    local rate_mbps=$1
    local packet_size=$2

    if [[ $rate_mbps -eq 0 ]]; then
        echo "0"
        return
    fi

    # Calculate packets per second needed
    local bits_per_packet=$((packet_size * 8))
    local target_bps=$((rate_mbps * 1000000))
    local pps=$((target_bps / bits_per_packet))

    if [[ $pps -gt 0 ]]; then
        # Delay in microseconds
        local delay_us=$((1000000 / pps))
        if [[ $delay_us -lt 1 ]]; then
            echo "0"
        else
            echo "${delay_us}usec"
        fi
    else
        echo "0"
    fi
}

run_single_stream() {
    local stream_id=$1
    local src_port=$((SRC_PORT + stream_id * 100))

    # Build mz command
    local cmd="mz $INTERFACE"

    # Count (infinite or duration-based)
    if [[ $DURATION -gt 0 ]]; then
        # Estimate packet count based on rate
        if [[ $RATE_MBPS -gt 0 ]]; then
            local bits_per_packet=$((PACKET_SIZE * 8))
            local pps=$((RATE_MBPS * 1000000 / bits_per_packet / WORKERS))
            local count=$((pps * DURATION))
            cmd+=" -c $count"
        else
            cmd+=" -c 0"  # Will be killed after duration
        fi
    else
        cmd+=" -c 0"  # Infinite
    fi

    # Delay for rate limiting
    local delay=$(calculate_delay $((RATE_MBPS / WORKERS)) $PACKET_SIZE)
    if [[ "$delay" != "0" ]]; then
        cmd+=" -d $delay"
    fi

    # Source/Destination MAC
    local src_mac=$(get_interface_mac $INTERFACE)
    cmd+=" -a $src_mac -b $DST_MAC"

    # Source/Destination IP
    if [[ -n "$SRC_IP" ]]; then
        cmd+=" -A $SRC_IP"
    else
        local auto_src=$(get_interface_ip $INTERFACE)
        if [[ -n "$auto_src" ]]; then
            cmd+=" -A $auto_src"
        fi
    fi
    cmd+=" -B $DST_IP"

    # VLAN tagging
    if [[ -n "$VLAN_ID" ]]; then
        cmd+=" -Q $VLAN_PRIO:$VLAN_ID"
    fi

    # Protocol and ports
    case $PROTOCOL in
        udp)
            cmd+=" -t udp \"sp=$src_port,dp=$DST_PORT"
            if [[ $DSCP -gt 0 ]]; then
                cmd+=",dscp=$DSCP"
            fi
            cmd+="\""
            ;;
        tcp)
            cmd+=" -t tcp \"sp=$src_port,dp=$DST_PORT,flags=syn"
            if [[ $DSCP -gt 0 ]]; then
                cmd+=",dscp=$DSCP"
            fi
            cmd+="\""
            ;;
        icmp)
            cmd+=" -t icmp"
            ;;
    esac

    # Padding to packet size
    local header_size=42  # Eth(14) + IP(20) + UDP(8)
    if [[ -n "$VLAN_ID" ]]; then
        header_size=$((header_size + 4))
    fi
    local pad_size=$((PACKET_SIZE - header_size))
    if [[ $pad_size -gt 0 ]]; then
        cmd+=" -p $PACKET_SIZE"
    fi

    # Payload
    if [[ -n "$PAYLOAD" ]]; then
        cmd+=" -P \"$PAYLOAD\""
    fi

    echo -e "${GREEN}[Stream $stream_id]${NC} Starting..."
    eval "$cmd" &
    echo $!
}

cleanup() {
    echo -e "\n${YELLOW}Stopping traffic generation...${NC}"
    jobs -p | xargs -r kill 2>/dev/null
    wait 2>/dev/null
    echo -e "${GREEN}Done.${NC}"
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -i|--interface) INTERFACE="$2"; shift 2 ;;
        -d|--dst-ip) DST_IP="$2"; shift 2 ;;
        -m|--dst-mac) DST_MAC="$2"; shift 2 ;;
        -s|--src-ip) SRC_IP="$2"; shift 2 ;;
        -p|--dst-port) DST_PORT="$2"; shift 2 ;;
        -P|--src-port) SRC_PORT="$2"; shift 2 ;;
        -l|--length) PACKET_SIZE="$2"; shift 2 ;;
        -r|--rate) RATE_MBPS="$2"; shift 2 ;;
        -t|--duration) DURATION="$2"; shift 2 ;;
        -w|--workers) WORKERS="$2"; shift 2 ;;
        -v|--vlan) VLAN_ID="$2"; shift 2 ;;
        -q|--vlan-prio) VLAN_PRIO="$2"; shift 2 ;;
        -D|--dscp) DSCP="$2"; shift 2 ;;
        -T|--type) PROTOCOL="$2"; shift 2 ;;
        -x|--payload) PAYLOAD="$2"; shift 2 ;;
        -h|--help) print_usage; exit 0 ;;
        *) echo "Unknown option: $1"; print_usage; exit 1 ;;
    esac
done

# Validate required args
if [[ -z "$INTERFACE" || -z "$DST_IP" || -z "$DST_MAC" ]]; then
    echo -e "${RED}Error: Missing required arguments${NC}"
    print_usage
    exit 1
fi

print_banner
check_requirements

# Print configuration
echo -e "${BLUE}Configuration:${NC}"
echo "  Interface:    $INTERFACE ($(get_interface_mac $INTERFACE))"
echo "  Destination:  $DST_IP ($DST_MAC)"
echo "  Source IP:    ${SRC_IP:-$(get_interface_ip $INTERFACE)}"
echo "  Ports:        $SRC_PORT -> $DST_PORT"
echo "  Packet Size:  $PACKET_SIZE bytes"
echo "  Target Rate:  $([ $RATE_MBPS -eq 0 ] && echo 'Maximum' || echo "${RATE_MBPS} Mbps")"
echo "  Duration:     $([ $DURATION -eq 0 ] && echo 'Infinite' || echo "${DURATION} seconds")"
echo "  Workers:      $WORKERS streams"
[[ -n "$VLAN_ID" ]] && echo "  VLAN:         $VLAN_ID (priority: $VLAN_PRIO)"
[[ $DSCP -gt 0 ]] && echo "  DSCP:         $DSCP"
echo ""

# Setup cleanup trap
trap cleanup EXIT INT TERM

# Start workers
PIDS=()
for ((i=0; i<WORKERS; i++)); do
    pid=$(run_single_stream $i)
    PIDS+=($pid)
done

echo -e "\n${GREEN}Traffic generation started with ${#PIDS[@]} stream(s)${NC}"
echo "Press Ctrl+C to stop"
echo ""

# Monitor or wait for duration
if [[ $DURATION -gt 0 ]]; then
    sleep $DURATION
else
    wait
fi
