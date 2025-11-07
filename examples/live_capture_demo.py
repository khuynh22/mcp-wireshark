"""Example: Live packet capture demo."""

import asyncio

from mcp_wireshark.server import handle_list_interfaces, handle_live_capture


async def main() -> None:
    """Demonstrate live packet capture."""
    # List available interfaces
    print("Available network interfaces:")
    interfaces = await handle_list_interfaces()
    for content in interfaces:
        print(content.text)
    print()

    # Prompt user to select interface
    interface_name = input(
        "Enter interface name to capture from (or press Enter to skip): "
    ).strip()

    if not interface_name:
        print("Skipping live capture.")
        return

    # Capture packets
    print(f"\nCapturing packets from '{interface_name}' for 5 seconds...")
    print("(This may require elevated permissions)")

    try:
        result = await handle_live_capture(
            {
                "interface": interface_name,
                "duration": 5,
                "packet_count": 50,
                "display_filter": "tcp or udp",  # Only TCP and UDP packets
            }
        )
        for content in result:
            print(content.text)
    except Exception as e:
        print(f"Error during capture: {e}")
        print("\nNote: Packet capture may require elevated permissions.")
        print("Try running with sudo or adjust permissions for dumpcap/tshark.")


if __name__ == "__main__":
    asyncio.run(main())
