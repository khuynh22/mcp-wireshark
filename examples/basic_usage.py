"""Example: Basic packet capture and analysis."""

import asyncio
from pathlib import Path

from mcp_wireshark.server import (
    handle_list_interfaces,
    handle_read_pcap,
    handle_stats_by_proto,
)


async def main() -> None:
    """Run example packet analysis."""
    print("MCP Wireshark Example\n")

    # List available interfaces
    print("1. Listing network interfaces...")
    interfaces = await handle_list_interfaces()
    for content in interfaces:
        print(content.text)
    print()

    # Example pcap file path (you'll need to provide your own)
    pcap_file = "example.pcap"

    if not Path(pcap_file).exists():
        print(f"Note: {pcap_file} not found. Create a sample capture first.")
        return

    # Read packets from pcap
    print(f"2. Reading packets from {pcap_file}...")
    packets = await handle_read_pcap({"file_path": pcap_file, "packet_count": 10})
    for content in packets:
        print(content.text)
    print()

    # Get protocol statistics
    print("3. Generating protocol statistics...")
    stats = await handle_stats_by_proto({"file_path": pcap_file})
    for content in stats:
        print(content.text)
    print()


if __name__ == "__main__":
    asyncio.run(main())
