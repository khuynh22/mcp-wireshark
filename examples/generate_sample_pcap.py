#!/usr/bin/env python3
"""
Create a sample pcap file for testing mcp-wireshark.

This script generates synthetic network traffic and saves it to a pcap file.
Note: This requires scapy to be installed: pip install scapy
"""

import sys

try:
    from scapy.all import DNS, DNSQR, IP, TCP, UDP, Ether, wrpcap
except ImportError:
    print("Error: scapy is required. Install it with: pip install scapy")
    sys.exit(1)


def create_sample_pcap(filename: str = "sample.pcap") -> None:
    """Create a sample pcap file with various packet types."""
    packets = []

    # HTTP SYN
    packets.append(
        Ether()
        / IP(src="192.168.1.100", dst="93.184.216.34")
        / TCP(sport=12345, dport=80, flags="S")
    )

    # HTTP SYN-ACK
    packets.append(
        Ether()
        / IP(src="93.184.216.34", dst="192.168.1.100")
        / TCP(sport=80, dport=12345, flags="SA")
    )

    # HTTP ACK
    packets.append(
        Ether()
        / IP(src="192.168.1.100", dst="93.184.216.34")
        / TCP(sport=12345, dport=80, flags="A")
    )

    # HTTPS SYN
    packets.append(
        Ether()
        / IP(src="192.168.1.100", dst="172.217.14.206")
        / TCP(sport=54321, dport=443, flags="S")
    )

    # DNS Query
    packets.append(
        Ether()
        / IP(src="192.168.1.100", dst="8.8.8.8")
        / UDP(sport=53210, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="example.com"))
    )

    # UDP packet
    packets.append(
        Ether()
        / IP(src="192.168.1.100", dst="192.168.1.1")
        / UDP(sport=5000, dport=6000)
        / b"Hello"
    )

    # More TCP traffic
    for i in range(10):
        packets.append(
            Ether()
            / IP(src="192.168.1.100", dst="10.0.0.1")
            / TCP(sport=1024 + i, dport=8080, flags="S")
        )

    # Write packets to file
    wrpcap(filename, packets)
    print(f"Created {filename} with {len(packets)} packets")
    print("\nPacket types:")
    print(f"  - TCP: {sum(1 for p in packets if TCP in p)}")
    print(f"  - UDP: {sum(1 for p in packets if UDP in p)}")
    print(f"  - DNS: {sum(1 for p in packets if DNS in p)}")


if __name__ == "__main__":
    output_file = sys.argv[1] if len(sys.argv) > 1 else "sample.pcap"
    create_sample_pcap(output_file)
