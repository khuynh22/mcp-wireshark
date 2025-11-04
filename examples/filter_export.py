"""Example: Filtering and exporting packets."""

import asyncio
from pathlib import Path

from mcp_wireshark.server import handle_display_filter, handle_export_json


async def main() -> None:
    """Demonstrate filtering and exporting."""
    pcap_file = "example.pcap"
    output_file = "filtered_packets.json"

    if not Path(pcap_file).exists():
        print(f"Error: {pcap_file} not found")
        return

    # Apply display filter
    print("Filtering HTTP traffic...")
    result = await handle_display_filter(
        {"file_path": pcap_file, "filter": "http", "packet_count": 50}
    )
    for content in result:
        print(content.text)
    print()

    # Export to JSON
    print(f"Exporting packets to {output_file}...")
    result = await handle_export_json(
        {
            "file_path": pcap_file,
            "output_path": output_file,
            "packet_count": 100,
            "display_filter": "tcp.port == 80",
        }
    )
    for content in result:
        print(content.text)


if __name__ == "__main__":
    asyncio.run(main())
