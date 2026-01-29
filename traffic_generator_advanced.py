#!/usr/bin/env python3
"""
Advanced Traffic Generator with Multiple Traffic Patterns
Supports: Constant, Burst, Ramp, Random patterns
"""

import argparse
import socket
import struct
import time
import os
import sys
import signal
import multiprocessing as mp
from multiprocessing import Process, Value, Array, Queue
from ctypes import c_uint64, c_double, c_bool
import random
import fcntl
import json
import yaml
from enum import Enum
from dataclasses import dataclass
from typing import Optional, List
import threading

# Constants
ETH_P_IP = 0x0800
SIOCGIFINDEX = 0x8933
SIOCGIFHWADDR = 0x8927


class TrafficPattern(Enum):
    CONSTANT = "constant"
    BURST = "burst"
    RAMP = "ramp"
    RANDOM = "random"
    SINE = "sine"


@dataclass
class TrafficConfig:
    interface: str
    dst_ip: str
    dst_mac: str
    src_ip: str = "192.168.1.1"
    src_port: int = 10000
    dst_port: int = 5001
    packet_size: int = 1472
    rate_mbps: float = 0  # 0 = max
    duration: float = 0  # 0 = infinite
    workers: int = 0  # 0 = auto
    pattern: TrafficPattern = TrafficPattern.CONSTANT
    # Pattern-specific settings
    burst_duration: float = 0.1  # seconds
    burst_interval: float = 1.0  # seconds
    ramp_start: float = 100  # Mbps
    ramp_end: float = 1000  # Mbps
    ramp_step_time: float = 5.0  # seconds per step
    vlan_id: Optional[int] = None
    vlan_priority: int = 0
    dscp: int = 0
    # Multi-flow support
    num_flows: int = 1
    flow_distribution: str = "round-robin"  # round-robin, random, weighted


class PacketBuilder:
    """Enhanced packet builder with VLAN and QoS support"""

    @staticmethod
    def mac_to_bytes(mac: str) -> bytes:
        return bytes.fromhex(mac.replace(':', '').replace('-', ''))

    @staticmethod
    def build_ethernet_header(src_mac: bytes, dst_mac: bytes,
                               vlan_id: Optional[int] = None,
                               vlan_priority: int = 0) -> bytes:
        if vlan_id is not None:
            # 802.1Q VLAN tagged frame
            vlan_tci = (vlan_priority << 13) | vlan_id
            return (dst_mac + src_mac +
                    struct.pack('!HH', 0x8100, vlan_tci) +
                    struct.pack('!H', ETH_P_IP))
        else:
            return dst_mac + src_mac + struct.pack('!H', ETH_P_IP)

    @staticmethod
    def build_ip_header(src_ip: str, dst_ip: str, total_length: int,
                        protocol: int = 17, dscp: int = 0) -> bytes:
        version_ihl = (4 << 4) | 5
        dscp_ecn = dscp << 2
        identification = random.randint(0, 65535)
        flags_fragment = 0
        ttl = 64

        header = struct.pack('!BBHHHBBH4s4s',
            version_ihl,
            dscp_ecn,
            total_length,
            identification,
            flags_fragment,
            ttl,
            protocol,
            0,
            socket.inet_aton(src_ip),
            socket.inet_aton(dst_ip)
        )

        checksum = PacketBuilder.calculate_checksum(header)
        header = header[:10] + struct.pack('!H', checksum) + header[12:]
        return header

    @staticmethod
    def build_udp_header(src_port: int, dst_port: int, length: int) -> bytes:
        return struct.pack('!HHHH', src_port, dst_port, length, 0)

    @staticmethod
    def build_tcp_header(src_port: int, dst_port: int, seq: int = 0) -> bytes:
        """Build TCP header (SYN packet for testing)"""
        ack = 0
        data_offset = 5 << 4
        flags = 0x02  # SYN
        window = 65535
        urgent = 0

        header = struct.pack('!HHIIBBHHH',
            src_port, dst_port, seq, ack,
            data_offset, flags, window, 0, urgent
        )
        return header

    @staticmethod
    def calculate_checksum(data: bytes) -> int:
        if len(data) % 2:
            data += b'\x00'
        total = sum(struct.unpack('!%dH' % (len(data) // 2), data))
        total = (total >> 16) + (total & 0xffff)
        total += total >> 16
        return ~total & 0xffff

    @staticmethod
    def build_packet(config: TrafficConfig, flow_id: int = 0) -> bytes:
        """Build complete packet based on configuration"""
        src_mac_bytes = PacketBuilder.mac_to_bytes(config.src_mac) if hasattr(config, 'src_mac') else b'\x00' * 6
        dst_mac_bytes = PacketBuilder.mac_to_bytes(config.dst_mac)

        vlan_overhead = 4 if config.vlan_id else 0
        header_size = 14 + vlan_overhead + 20 + 8  # Eth + VLAN + IP + UDP
        payload_size = max(1, config.packet_size - header_size)

        # Generate payload with pattern for identification
        payload = struct.pack('!IQ', flow_id, int(time.time() * 1000000))
        payload += os.urandom(max(0, payload_size - 12))

        udp_length = 8 + len(payload)
        ip_length = 20 + udp_length

        eth_header = PacketBuilder.build_ethernet_header(
            src_mac_bytes, dst_mac_bytes, config.vlan_id, config.vlan_priority
        )
        ip_header = PacketBuilder.build_ip_header(
            config.src_ip, config.dst_ip, ip_length, 17, config.dscp
        )
        udp_header = PacketBuilder.build_udp_header(
            config.src_port + flow_id, config.dst_port, udp_length
        )

        return eth_header + ip_header + udp_header + payload


class TrafficStats:
    """Enhanced statistics tracking"""

    def __init__(self, num_workers: int):
        self.packets_sent = Array(c_uint64, num_workers)
        self.bytes_sent = Array(c_uint64, num_workers)
        self.errors = Array(c_uint64, num_workers)
        self.start_time = Value(c_double, 0.0)
        self.running = Value(c_bool, True)
        self.current_rate = Value(c_double, 0.0)


class RateController:
    """Dynamic rate control for various traffic patterns"""

    def __init__(self, config: TrafficConfig):
        self.config = config
        self.start_time = time.time()

    def get_current_rate(self) -> float:
        """Get current target rate based on pattern"""
        elapsed = time.time() - self.start_time

        if self.config.pattern == TrafficPattern.CONSTANT:
            return self.config.rate_mbps

        elif self.config.pattern == TrafficPattern.BURST:
            cycle_time = self.config.burst_duration + self.config.burst_interval
            cycle_pos = elapsed % cycle_time
            if cycle_pos < self.config.burst_duration:
                return self.config.rate_mbps
            return 0

        elif self.config.pattern == TrafficPattern.RAMP:
            step = int(elapsed / self.config.ramp_step_time)
            rate_range = self.config.ramp_end - self.config.ramp_start
            steps_total = 10
            rate = self.config.ramp_start + (rate_range * min(step, steps_total) / steps_total)
            return min(rate, self.config.ramp_end)

        elif self.config.pattern == TrafficPattern.SINE:
            import math
            amplitude = (self.config.ramp_end - self.config.ramp_start) / 2
            offset = (self.config.ramp_end + self.config.ramp_start) / 2
            return offset + amplitude * math.sin(elapsed * 0.5)

        elif self.config.pattern == TrafficPattern.RANDOM:
            return random.uniform(self.config.ramp_start, self.config.ramp_end)

        return self.config.rate_mbps


def get_interface_info(interface: str) -> tuple:
    """Get MAC address and interface index"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(sock.fileno(), SIOCGIFHWADDR,
                       struct.pack('256s', interface.encode()[:15]))
    mac = ':'.join('%02x' % b for b in info[18:24])
    info = fcntl.ioctl(sock.fileno(), SIOCGIFINDEX,
                       struct.pack('256s', interface.encode()[:15]))
    ifindex = struct.unpack('I', info[16:20])[0]
    sock.close()
    return mac, ifindex


def worker_process(worker_id: int, config: TrafficConfig, stats: TrafficStats,
                   rate_queue: Queue):
    """Enhanced worker process with dynamic rate control"""
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_IP))
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 32 * 1024 * 1024)

        config.src_mac, ifindex = get_interface_info(config.interface)
        sock.bind((config.interface, 0))

        # Pre-build packets for each flow
        packets = []
        for flow_id in range(config.num_flows):
            packet = PacketBuilder.build_packet(config, flow_id)
            packets.append(packet)

        packet_size = len(packets[0])
        flow_idx = worker_id % config.num_flows
        current_rate = config.rate_mbps

        local_packets = 0
        local_bytes = 0
        local_errors = 0
        last_update = time.time()
        last_rate_check = time.time()

        while stats.running.value:
            # Check for rate updates
            try:
                if not rate_queue.empty():
                    current_rate = rate_queue.get_nowait()
            except:
                pass

            # Calculate delay for rate limiting
            if current_rate > 0:
                packet_bits = packet_size * 8
                target_rate_bps = current_rate * 1_000_000 / max(1, config.workers)
                packets_per_second = target_rate_bps / packet_bits
                delay = 1.0 / packets_per_second if packets_per_second > 0 else 0
            else:
                delay = 0

            # Select packet based on flow distribution
            if config.flow_distribution == "random":
                packet = random.choice(packets)
            else:  # round-robin
                packet = packets[flow_idx % len(packets)]
                flow_idx += 1

            try:
                sock.send(packet)
                local_packets += 1
                local_bytes += len(packet)
            except BlockingIOError:
                continue
            except Exception:
                local_errors += 1
                continue

            if delay > 0:
                time.sleep(delay)

            # Update shared stats
            now = time.time()
            if now - last_update >= 0.1:
                stats.packets_sent[worker_id] += local_packets
                stats.bytes_sent[worker_id] += local_bytes
                stats.errors[worker_id] += local_errors
                local_packets = 0
                local_bytes = 0
                local_errors = 0
                last_update = now

        # Final update
        stats.packets_sent[worker_id] += local_packets
        stats.bytes_sent[worker_id] += local_bytes
        stats.errors[worker_id] += local_errors
        sock.close()

    except Exception as e:
        print(f"Worker {worker_id} error: {e}")


def rate_controller_process(config: TrafficConfig, stats: TrafficStats,
                            rate_queues: List[Queue]):
    """Process to manage dynamic rate changes"""
    controller = RateController(config)

    while stats.running.value:
        current_rate = controller.get_current_rate()
        stats.current_rate.value = current_rate

        for q in rate_queues:
            try:
                # Clear old values and add new
                while not q.empty():
                    q.get_nowait()
                q.put(current_rate)
            except:
                pass

        time.sleep(0.1)


def stats_printer(stats: TrafficStats, config: TrafficConfig):
    """Enhanced statistics printer"""
    print("\n" + "=" * 80)
    print(f"Traffic Generator - Pattern: {config.pattern.value.upper()}")
    print("=" * 80)
    print(f"{'Time':>8} | {'Packets':>12} | {'Rate':>10} | {'Throughput':>12} | {'Target':>10} | {'Errors':>8}")
    print("-" * 80)

    last_packets = 0
    last_bytes = 0
    last_time = time.time()
    start_time = last_time

    while stats.running.value:
        time.sleep(1.0)

        current_time = time.time()
        elapsed = current_time - start_time
        interval = current_time - last_time

        total_packets = sum(stats.packets_sent)
        total_bytes = sum(stats.bytes_sent)
        total_errors = sum(stats.errors)

        delta_packets = total_packets - last_packets
        delta_bytes = total_bytes - last_bytes

        pps = delta_packets / interval if interval > 0 else 0
        throughput_mbps = (delta_bytes * 8) / (interval * 1_000_000) if interval > 0 else 0
        target_rate = stats.current_rate.value

        if throughput_mbps >= 1000:
            tp_str = f"{throughput_mbps/1000:.2f} Gbps"
        else:
            tp_str = f"{throughput_mbps:.1f} Mbps"

        target_str = f"{target_rate:.0f} Mbps" if target_rate > 0 else "MAX"

        print(f"{elapsed:>7.1f}s | {total_packets:>12,} | {pps:>10,.0f} | {tp_str:>12} | {target_str:>10} | {total_errors:>8,}")

        last_packets = total_packets
        last_bytes = total_bytes
        last_time = current_time

        if config.duration > 0 and elapsed >= config.duration:
            stats.running.value = False
            break

    # Summary
    total_time = time.time() - start_time
    total_packets = sum(stats.packets_sent)
    total_bytes = sum(stats.bytes_sent)
    total_errors = sum(stats.errors)

    print("-" * 80)
    print("\nSummary:")
    print(f"  Duration:       {total_time:.2f} seconds")
    print(f"  Total Packets:  {total_packets:,}")
    print(f"  Total Data:     {total_bytes / (1024**3):.3f} GB")
    print(f"  Avg Rate:       {total_packets / total_time:,.0f} pps")
    print(f"  Avg Throughput: {(total_bytes * 8) / (total_time * 1_000_000_000):.3f} Gbps")
    print(f"  Errors:         {total_errors:,}")
    print("=" * 80)


def load_config(config_file: str) -> TrafficConfig:
    """Load configuration from YAML file"""
    with open(config_file, 'r') as f:
        data = yaml.safe_load(f)

    pattern = TrafficPattern(data.get('pattern', 'constant'))

    return TrafficConfig(
        interface=data['interface'],
        dst_ip=data['dst_ip'],
        dst_mac=data['dst_mac'],
        src_ip=data.get('src_ip', '192.168.1.1'),
        src_port=data.get('src_port', 10000),
        dst_port=data.get('dst_port', 5001),
        packet_size=data.get('packet_size', 1472),
        rate_mbps=data.get('rate_mbps', 0),
        duration=data.get('duration', 0),
        workers=data.get('workers', 0),
        pattern=pattern,
        burst_duration=data.get('burst_duration', 0.1),
        burst_interval=data.get('burst_interval', 1.0),
        ramp_start=data.get('ramp_start', 100),
        ramp_end=data.get('ramp_end', 1000),
        ramp_step_time=data.get('ramp_step_time', 5.0),
        vlan_id=data.get('vlan_id'),
        vlan_priority=data.get('vlan_priority', 0),
        dscp=data.get('dscp', 0),
        num_flows=data.get('num_flows', 1),
        flow_distribution=data.get('flow_distribution', 'round-robin')
    )


def main():
    parser = argparse.ArgumentParser(
        description='Advanced High-Performance Traffic Generator',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Traffic Patterns:
  constant  - Steady rate traffic
  burst     - Periodic bursts of traffic
  ramp      - Gradually increasing rate
  sine      - Sinusoidal rate variation
  random    - Random rate within range

Examples:
  # Constant 1Gbps traffic
  sudo python3 traffic_generator_advanced.py -i enp11s0 -d 192.168.1.100 --dst-mac 00:11:22:33:44:55 -r 1000

  # Burst pattern (100ms burst every 1s)
  sudo python3 traffic_generator_advanced.py -i enp11s0 -d 192.168.1.100 --dst-mac 00:11:22:33:44:55 \\
      --pattern burst --burst-duration 0.1 --burst-interval 1.0 -r 1000

  # Ramp from 100 Mbps to 2 Gbps
  sudo python3 traffic_generator_advanced.py -i enp11s0 -d 192.168.1.100 --dst-mac 00:11:22:33:44:55 \\
      --pattern ramp --ramp-start 100 --ramp-end 2000

  # Load from config file
  sudo python3 traffic_generator_advanced.py -c config.yaml
        """
    )

    parser.add_argument('-c', '--config', help='Configuration file (YAML)')
    parser.add_argument('-i', '--interface', help='Network interface')
    parser.add_argument('-d', '--dst-ip', help='Destination IP')
    parser.add_argument('--dst-mac', help='Destination MAC')
    parser.add_argument('--src-ip', default='192.168.1.1', help='Source IP')
    parser.add_argument('-p', '--dst-port', type=int, default=5001, help='Destination port')
    parser.add_argument('--src-port', type=int, default=10000, help='Source port base')
    parser.add_argument('-s', '--packet-size', type=int, default=1472, help='Packet size')
    parser.add_argument('-r', '--rate', type=float, default=0, help='Target rate (Mbps)')
    parser.add_argument('-t', '--duration', type=float, default=0, help='Duration (seconds)')
    parser.add_argument('-w', '--workers', type=int, default=0, help='Worker processes')
    parser.add_argument('--pattern', choices=['constant', 'burst', 'ramp', 'sine', 'random'],
                        default='constant', help='Traffic pattern')
    parser.add_argument('--burst-duration', type=float, default=0.1, help='Burst duration (s)')
    parser.add_argument('--burst-interval', type=float, default=1.0, help='Burst interval (s)')
    parser.add_argument('--ramp-start', type=float, default=100, help='Ramp start rate (Mbps)')
    parser.add_argument('--ramp-end', type=float, default=1000, help='Ramp end rate (Mbps)')
    parser.add_argument('--vlan', type=int, help='VLAN ID')
    parser.add_argument('--vlan-priority', type=int, default=0, help='VLAN priority (0-7)')
    parser.add_argument('--dscp', type=int, default=0, help='DSCP value')
    parser.add_argument('--flows', type=int, default=1, help='Number of flows')

    args = parser.parse_args()

    if os.geteuid() != 0:
        print("Error: Requires root privileges. Run with sudo.")
        sys.exit(1)

    # Load config
    if args.config:
        config = load_config(args.config)
    else:
        if not all([args.interface, args.dst_ip, args.dst_mac]):
            parser.error("Required: -i/--interface, -d/--dst-ip, --dst-mac")

        config = TrafficConfig(
            interface=args.interface,
            dst_ip=args.dst_ip,
            dst_mac=args.dst_mac,
            src_ip=args.src_ip,
            src_port=args.src_port,
            dst_port=args.dst_port,
            packet_size=args.packet_size,
            rate_mbps=args.rate,
            duration=args.duration,
            workers=args.workers or mp.cpu_count(),
            pattern=TrafficPattern(args.pattern),
            burst_duration=args.burst_duration,
            burst_interval=args.burst_interval,
            ramp_start=args.ramp_start,
            ramp_end=args.ramp_end,
            vlan_id=args.vlan,
            vlan_priority=args.vlan_priority,
            dscp=args.dscp,
            num_flows=args.flows
        )

    if config.workers == 0:
        config.workers = mp.cpu_count()

    src_mac, _ = get_interface_info(config.interface)
    config.src_mac = src_mac

    print(f"\nConfiguration:")
    print(f"  Interface:    {config.interface} ({src_mac})")
    print(f"  Destination:  {config.dst_ip} ({config.dst_mac})")
    print(f"  Packet Size:  {config.packet_size} bytes")
    print(f"  Pattern:      {config.pattern.value}")
    print(f"  Target Rate:  {'Maximum' if config.rate_mbps == 0 else f'{config.rate_mbps} Mbps'}")
    print(f"  Workers:      {config.workers}")
    print(f"  Flows:        {config.num_flows}")
    if config.vlan_id:
        print(f"  VLAN:         {config.vlan_id} (priority: {config.vlan_priority})")
    if config.dscp:
        print(f"  DSCP:         {config.dscp}")

    # Initialize
    stats = TrafficStats(config.workers)
    stats.start_time.value = time.time()

    rate_queues = [Queue() for _ in range(config.workers)]

    # Start workers
    workers = []
    for i in range(config.workers):
        p = Process(target=worker_process, args=(i, config, stats, rate_queues[i]))
        p.start()
        workers.append(p)

    # Start rate controller for dynamic patterns
    if config.pattern != TrafficPattern.CONSTANT:
        rate_proc = Process(target=rate_controller_process, args=(config, stats, rate_queues))
        rate_proc.start()
    else:
        rate_proc = None
        stats.current_rate.value = config.rate_mbps

    def signal_handler(sig, frame):
        print("\n\nStopping...")
        stats.running.value = False

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        stats_printer(stats, config)
    except KeyboardInterrupt:
        stats.running.value = False

    for p in workers:
        p.join(timeout=2)
        if p.is_alive():
            p.terminate()

    if rate_proc:
        rate_proc.join(timeout=1)
        if rate_proc.is_alive():
            rate_proc.terminate()


if __name__ == '__main__':
    main()
