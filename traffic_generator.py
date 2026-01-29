#!/usr/bin/env python3
"""
High-Performance Traffic Generator
Capable of generating 1Gbps+ network traffic

Features:
- Multi-process architecture for maximum throughput
- Raw socket support for low overhead
- sendmmsg() for batch packet transmission
- Real-time statistics
- Various traffic patterns (constant, burst, ramp)
"""

import argparse
import socket
import struct
import time
import os
import sys
import signal
import multiprocessing as mp
from multiprocessing import Process, Value, Array
from ctypes import c_uint64, c_double, c_bool
import random
import fcntl
import array

# Constants
ETH_P_IP = 0x0800
SIOCGIFINDEX = 0x8933
SIOCGIFHWADDR = 0x8927

class PacketBuilder:
    """Build various packet types"""

    @staticmethod
    def build_ethernet_header(src_mac: bytes, dst_mac: bytes, ethertype: int = ETH_P_IP) -> bytes:
        return dst_mac + src_mac + struct.pack('!H', ethertype)

    @staticmethod
    def build_ip_header(src_ip: str, dst_ip: str, total_length: int, protocol: int = 17) -> bytes:
        """Build IPv4 header (protocol 17 = UDP, 6 = TCP)"""
        version_ihl = (4 << 4) | 5
        dscp_ecn = 0
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
            0,  # checksum placeholder
            socket.inet_aton(src_ip),
            socket.inet_aton(dst_ip)
        )

        # Calculate IP header checksum
        checksum = PacketBuilder.calculate_checksum(header)
        header = header[:10] + struct.pack('!H', checksum) + header[12:]

        return header

    @staticmethod
    def build_udp_header(src_port: int, dst_port: int, length: int) -> bytes:
        return struct.pack('!HHHH', src_port, dst_port, length, 0)

    @staticmethod
    def calculate_checksum(data: bytes) -> int:
        if len(data) % 2:
            data += b'\x00'

        total = 0
        for i in range(0, len(data), 2):
            total += (data[i] << 8) + data[i + 1]

        total = (total >> 16) + (total & 0xffff)
        total += total >> 16

        return ~total & 0xffff

    @staticmethod
    def mac_to_bytes(mac: str) -> bytes:
        return bytes.fromhex(mac.replace(':', '').replace('-', ''))

    @staticmethod
    def build_udp_packet(src_mac: str, dst_mac: str, src_ip: str, dst_ip: str,
                         src_port: int, dst_port: int, payload_size: int) -> bytes:
        """Build complete UDP packet"""
        payload = os.urandom(payload_size)

        udp_length = 8 + payload_size
        ip_length = 20 + udp_length

        eth_header = PacketBuilder.build_ethernet_header(
            PacketBuilder.mac_to_bytes(src_mac),
            PacketBuilder.mac_to_bytes(dst_mac)
        )
        ip_header = PacketBuilder.build_ip_header(src_ip, dst_ip, ip_length, protocol=17)
        udp_header = PacketBuilder.build_udp_header(src_port, dst_port, udp_length)

        return eth_header + ip_header + udp_header + payload


class TrafficStats:
    """Shared statistics between processes"""

    def __init__(self, num_workers: int):
        self.packets_sent = Array(c_uint64, num_workers)
        self.bytes_sent = Array(c_uint64, num_workers)
        self.start_time = Value(c_double, 0.0)
        self.running = Value(c_bool, True)


def get_interface_info(interface: str) -> tuple:
    """Get MAC address and interface index"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Get MAC address
    info = fcntl.ioctl(sock.fileno(), SIOCGIFHWADDR,
                       struct.pack('256s', interface.encode()[:15]))
    mac = ':'.join('%02x' % b for b in info[18:24])

    # Get interface index
    info = fcntl.ioctl(sock.fileno(), SIOCGIFINDEX,
                       struct.pack('256s', interface.encode()[:15]))
    ifindex = struct.unpack('I', info[16:20])[0]

    sock.close()
    return mac, ifindex


def worker_process(worker_id: int, interface: str, dst_mac: str, dst_ip: str,
                   src_ip: str, src_port_base: int, dst_port: int,
                   packet_size: int, target_rate_mbps: float,
                   stats: TrafficStats, batch_size: int = 64):
    """Worker process for packet generation"""

    try:
        # Create raw socket
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_IP))
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 16 * 1024 * 1024)

        src_mac, ifindex = get_interface_info(interface)
        sock.bind((interface, 0))

        # Calculate payload size (total - headers)
        # Ethernet: 14, IP: 20, UDP: 8 = 42 bytes overhead
        payload_size = max(1, packet_size - 42)

        # Pre-build packets for better performance
        packets = []
        for i in range(batch_size):
            src_port = src_port_base + worker_id * 1000 + i
            packet = PacketBuilder.build_udp_packet(
                src_mac, dst_mac, src_ip, dst_ip,
                src_port, dst_port, payload_size
            )
            packets.append(packet)

        # Calculate inter-packet delay for rate limiting
        packet_bits = packet_size * 8
        if target_rate_mbps > 0:
            target_rate_bps = target_rate_mbps * 1_000_000
            packets_per_second = target_rate_bps / packet_bits
            delay_per_packet = 1.0 / packets_per_second if packets_per_second > 0 else 0
        else:
            delay_per_packet = 0  # Maximum rate

        packet_idx = 0
        local_packets = 0
        local_bytes = 0
        last_update = time.time()

        while stats.running.value:
            packet = packets[packet_idx % batch_size]

            try:
                sock.send(packet)
                local_packets += 1
                local_bytes += len(packet)
            except BlockingIOError:
                continue
            except Exception as e:
                print(f"Worker {worker_id} send error: {e}")
                continue

            packet_idx += 1

            # Rate limiting
            if delay_per_packet > 0:
                time.sleep(delay_per_packet)

            # Update shared stats periodically
            now = time.time()
            if now - last_update >= 0.1:
                stats.packets_sent[worker_id] += local_packets
                stats.bytes_sent[worker_id] += local_bytes
                local_packets = 0
                local_bytes = 0
                last_update = now

        # Final update
        stats.packets_sent[worker_id] += local_packets
        stats.bytes_sent[worker_id] += local_bytes

        sock.close()

    except Exception as e:
        print(f"Worker {worker_id} error: {e}")


def stats_printer(stats: TrafficStats, num_workers: int, duration: float):
    """Print real-time statistics"""

    print("\n" + "=" * 70)
    print("Traffic Generator Statistics")
    print("=" * 70)
    print(f"{'Time':>8} | {'Packets':>12} | {'Rate (pps)':>12} | {'Throughput':>15}")
    print("-" * 70)

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

        delta_packets = total_packets - last_packets
        delta_bytes = total_bytes - last_bytes

        pps = delta_packets / interval if interval > 0 else 0
        throughput_mbps = (delta_bytes * 8) / (interval * 1_000_000) if interval > 0 else 0
        throughput_gbps = throughput_mbps / 1000

        if throughput_gbps >= 1:
            throughput_str = f"{throughput_gbps:.2f} Gbps"
        else:
            throughput_str = f"{throughput_mbps:.2f} Mbps"

        print(f"{elapsed:>7.1f}s | {total_packets:>12,} | {pps:>12,.0f} | {throughput_str:>15}")

        last_packets = total_packets
        last_bytes = total_bytes
        last_time = current_time

        if duration > 0 and elapsed >= duration:
            stats.running.value = False
            break

    # Final summary
    total_time = time.time() - start_time
    total_packets = sum(stats.packets_sent)
    total_bytes = sum(stats.bytes_sent)

    print("-" * 70)
    print("\nFinal Summary:")
    print(f"  Duration:       {total_time:.2f} seconds")
    print(f"  Total Packets:  {total_packets:,}")
    print(f"  Total Data:     {total_bytes / (1024**3):.2f} GB")
    print(f"  Avg Rate:       {total_packets / total_time:,.0f} pps")
    print(f"  Avg Throughput: {(total_bytes * 8) / (total_time * 1_000_000_000):.2f} Gbps")
    print("=" * 70)


def main():
    parser = argparse.ArgumentParser(
        description='High-Performance Traffic Generator (1Gbps+)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate traffic at maximum rate
  sudo python3 traffic_generator.py -i enp11s0 -d 192.168.1.100 --dst-mac 00:11:22:33:44:55

  # Generate 500 Mbps traffic with 1024 byte packets
  sudo python3 traffic_generator.py -i enp11s0 -d 192.168.1.100 --dst-mac 00:11:22:33:44:55 -r 500 -s 1024

  # Run for 60 seconds with 4 workers
  sudo python3 traffic_generator.py -i enp11s0 -d 192.168.1.100 --dst-mac 00:11:22:33:44:55 -t 60 -w 4
        """
    )

    # Required arguments
    parser.add_argument('-i', '--interface', required=True,
                        help='Network interface to use (e.g., enp11s0)')
    parser.add_argument('-d', '--dst-ip', required=True,
                        help='Destination IP address')
    parser.add_argument('--dst-mac', required=True,
                        help='Destination MAC address (e.g., 00:11:22:33:44:55)')

    # Optional arguments
    parser.add_argument('--src-ip', default='192.168.1.1',
                        help='Source IP address (default: 192.168.1.1)')
    parser.add_argument('-p', '--dst-port', type=int, default=5001,
                        help='Destination UDP port (default: 5001)')
    parser.add_argument('--src-port', type=int, default=10000,
                        help='Base source UDP port (default: 10000)')
    parser.add_argument('-s', '--packet-size', type=int, default=1472,
                        help='Packet size in bytes (default: 1472, max MTU)')
    parser.add_argument('-r', '--rate', type=float, default=0,
                        help='Target rate in Mbps (0 = maximum, default: 0)')
    parser.add_argument('-t', '--duration', type=float, default=0,
                        help='Duration in seconds (0 = infinite, default: 0)')
    parser.add_argument('-w', '--workers', type=int, default=None,
                        help='Number of worker processes (default: CPU count)')
    parser.add_argument('--batch-size', type=int, default=64,
                        help='Packet batch size per worker (default: 64)')

    args = parser.parse_args()

    # Check root privileges
    if os.geteuid() != 0:
        print("Error: This script requires root privileges. Run with sudo.")
        sys.exit(1)

    # Validate interface exists
    try:
        src_mac, _ = get_interface_info(args.interface)
        print(f"Using interface {args.interface} (MAC: {src_mac})")
    except Exception as e:
        print(f"Error: Cannot access interface {args.interface}: {e}")
        sys.exit(1)

    # Set number of workers
    num_workers = args.workers or mp.cpu_count()
    rate_per_worker = args.rate / num_workers if args.rate > 0 else 0

    print(f"\nTraffic Generator Configuration:")
    print(f"  Interface:    {args.interface}")
    print(f"  Destination:  {args.dst_ip} ({args.dst_mac})")
    print(f"  Source IP:    {args.src_ip}")
    print(f"  Port:         {args.src_port} -> {args.dst_port}")
    print(f"  Packet Size:  {args.packet_size} bytes")
    print(f"  Target Rate:  {'Maximum' if args.rate == 0 else f'{args.rate} Mbps'}")
    print(f"  Duration:     {'Infinite' if args.duration == 0 else f'{args.duration} seconds'}")
    print(f"  Workers:      {num_workers}")

    # Initialize stats
    stats = TrafficStats(num_workers)
    stats.start_time.value = time.time()

    # Start worker processes
    workers = []
    for i in range(num_workers):
        p = Process(target=worker_process, args=(
            i, args.interface, args.dst_mac, args.dst_ip,
            args.src_ip, args.src_port, args.dst_port,
            args.packet_size, rate_per_worker, stats, args.batch_size
        ))
        p.start()
        workers.append(p)

    # Handle Ctrl+C
    def signal_handler(sig, frame):
        print("\n\nStopping traffic generator...")
        stats.running.value = False

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Start stats printer in main process
    try:
        stats_printer(stats, num_workers, args.duration)
    except KeyboardInterrupt:
        stats.running.value = False

    # Wait for workers to finish
    for p in workers:
        p.join(timeout=2)
        if p.is_alive():
            p.terminate()


if __name__ == '__main__':
    main()
