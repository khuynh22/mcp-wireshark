"""Example: TCP stream analysis."""

import asyncio
from pathlib import Path

from mcp_wireshark.server import handle_follow_tcp, handle_read_pcap


async def main() -> None:
    """Demonstrate TCP stream analysis."""
    pcap_file = "example.pcap"

    if not Path(pcap_file).exists():
        print(f"Error: {pcap_file} not found")
        print("Please create a sample pcap file first.")
        return

    # First, read some packets to see what's available
    print("Reading packets from pcap file...")
    packets = await handle_read_pcap(
        {"file_path": pcap_file, "packet_count": 20, "display_filter": "tcp"}
    )
    for content in packets:
        print(content.text)
    print()

    # Follow TCP stream 0
    print("Following TCP stream 0...")
    stream = await handle_follow_tcp({"file_path": pcap_file, "stream_id": 0})
    for content in stream:
        print(content.text)


if __name__ == "__main__":
    asyncio.run(main())
