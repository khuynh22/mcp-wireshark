"""MCP server implementation for Wireshark integration."""

import json
import tempfile
from pathlib import Path
from typing import Any

from mcp.server import Server
from mcp.types import TextContent, Tool

from .utils import (
    WiresharkNotFoundError,
    check_wireshark_installed,
    run_dumpcap,
    run_tshark,
)

# Create the MCP server
app = Server("mcp-wireshark")


@app.list_tools()
async def list_tools() -> list[Tool]:
    """List available MCP tools."""
    return [
        Tool(
            name="list_interfaces",
            description="List all available network interfaces for packet capture",
            inputSchema={
                "type": "object",
                "properties": {},
            },
        ),
        Tool(
            name="live_capture",
            description="Capture live network traffic from a specified interface",
            inputSchema={
                "type": "object",
                "properties": {
                    "interface": {
                        "type": "string",
                        "description": "Network interface name (e.g., eth0, Wi-Fi)",
                    },
                    "duration": {
                        "type": "number",
                        "description": "Capture duration in seconds (default: 10)",
                        "default": 10,
                    },
                    "packet_count": {
                        "type": "number",
                        "description": "Maximum number of packets to capture (optional)",
                    },
                    "display_filter": {
                        "type": "string",
                        "description": "Wireshark display filter to apply (optional)",
                    },
                },
                "required": ["interface"],
            },
        ),
        Tool(
            name="read_pcap",
            description="Read and analyze packets from a .pcap or .pcapng file",
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Path to the .pcap or .pcapng file",
                    },
                    "packet_count": {
                        "type": "number",
                        "description": "Maximum number of packets to read (default: 100)",
                        "default": 100,
                    },
                    "display_filter": {
                        "type": "string",
                        "description": "Wireshark display filter to apply (optional)",
                    },
                },
                "required": ["file_path"],
            },
        ),
        Tool(
            name="display_filter",
            description="Apply a Wireshark display filter to a pcap file or live capture",
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Path to the .pcap or .pcapng file",
                    },
                    "filter": {
                        "type": "string",
                        "description": "Wireshark display filter (e.g., 'tcp.port == 80', 'http')",
                    },
                    "packet_count": {
                        "type": "number",
                        "description": "Maximum number of packets to return (default: 100)",
                        "default": 100,
                    },
                },
                "required": ["file_path", "filter"],
            },
        ),
        Tool(
            name="stats_by_proto",
            description="Generate protocol statistics from a pcap file",
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Path to the .pcap or .pcapng file",
                    },
                },
                "required": ["file_path"],
            },
        ),
        Tool(
            name="follow_tcp",
            description="Follow a TCP stream and extract payload data",
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Path to the .pcap or .pcapng file",
                    },
                    "stream_id": {
                        "type": "number",
                        "description": "TCP stream ID to follow (default: 0)",
                        "default": 0,
                    },
                },
                "required": ["file_path"],
            },
        ),
        Tool(
            name="export_json",
            description="Export packets from a pcap file to JSON format",
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Path to the .pcap or .pcapng file",
                    },
                    "output_path": {
                        "type": "string",
                        "description": "Path to save the JSON output",
                    },
                    "packet_count": {
                        "type": "number",
                        "description": "Maximum number of packets to export (default: 1000)",
                        "default": 1000,
                    },
                    "display_filter": {
                        "type": "string",
                        "description": "Wireshark display filter to apply (optional)",
                    },
                },
                "required": ["file_path", "output_path"],
            },
        ),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: Any) -> list[TextContent]:
    """Handle tool calls."""
    try:
        # Check if Wireshark is installed
        tools = check_wireshark_installed()
        if not tools["tshark"]:
            return [
                TextContent(
                    type="text",
                    text="Error: tshark not found. Please install Wireshark/tshark.",
                )
            ]

        if name == "list_interfaces":
            return await handle_list_interfaces()
        if name == "live_capture":
            return await handle_live_capture(arguments)
        if name == "read_pcap":
            return await handle_read_pcap(arguments)
        if name == "display_filter":
            return await handle_display_filter(arguments)
        if name == "stats_by_proto":
            return await handle_stats_by_proto(arguments)
        if name == "follow_tcp":
            return await handle_follow_tcp(arguments)
        if name == "export_json":
            return await handle_export_json(arguments)
        return [TextContent(type="text", text=f"Unknown tool: {name}")]

    except WiresharkNotFoundError as e:
        return [TextContent(type="text", text=f"Error: {e}")]
    except Exception as e:
        return [TextContent(type="text", text=f"Error: {e}")]


async def handle_list_interfaces() -> list[TextContent]:
    """List available network interfaces."""
    try:
        output = await run_tshark(["-D"], timeout=10)
        interfaces = []
        for line in output.strip().split("\n"):
            if line:
                interfaces.append(line)

        return [
            TextContent(
                type="text",
                text=f"Found {len(interfaces)} network interface(s):\n\n" + "\n".join(interfaces),
            )
        ]
    except Exception as e:
        return [TextContent(type="text", text=f"Error listing interfaces: {e}")]


async def handle_live_capture(arguments: dict[str, Any]) -> list[TextContent]:
    """Capture live network traffic."""
    interface = arguments["interface"]
    duration = arguments.get("duration", 10)
    packet_count = arguments.get("packet_count")
    display_filter = arguments.get("display_filter")

    try:
        # Create temporary file for capture
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as temp_file:
            temp_path = temp_file.name

        # Build capture command
        args = ["-i", interface, "-w", temp_path, "-a", f"duration:{duration}"]

        if packet_count:
            args.extend(["-c", str(packet_count)])

        # Use dumpcap if available, otherwise tshark
        tools = check_wireshark_installed()
        if tools["dumpcap"]:
            await run_dumpcap(args, timeout=duration + 10)
        else:
            await run_tshark(args, timeout=duration + 10)

        # Read captured packets
        read_args = ["-r", temp_path, "-T", "json"]
        if display_filter:
            read_args.extend(["-Y", display_filter])
        read_args.extend(["-c", "100"])  # Limit output

        output = await run_tshark(read_args, timeout=30)

        # Clean up temp file
        Path(temp_path).unlink(missing_ok=True)

        # Parse packets
        if output.strip():
            packets = json.loads(output)
            packet_count_result = len(packets) if isinstance(packets, list) else 1

            return [
                TextContent(
                    type="text",
                    text=f"Captured {packet_count_result} packet(s) from interface '{interface}'\n\n"
                    f"Preview:\n{json.dumps(packets[:5] if isinstance(packets, list) else packets, indent=2)}",
                )
            ]
        return [
            TextContent(
                type="text",
                text=f"No packets captured from interface '{interface}' in {duration} seconds",
            )
        ]

    except Exception as e:
        # Clean up temp file on error
        Path(temp_path).unlink(missing_ok=True)
        return [TextContent(type="text", text=f"Error during live capture: {e}")]


async def handle_read_pcap(arguments: dict[str, Any]) -> list[TextContent]:
    """Read packets from a pcap file."""
    file_path = arguments["file_path"]
    packet_count = arguments.get("packet_count", 100)
    display_filter = arguments.get("display_filter")

    try:
        # Validate file exists
        if not Path(file_path).exists():
            return [TextContent(type="text", text=f"Error: File not found: {file_path}")]

        # Build command
        args = ["-r", file_path, "-T", "json", "-c", str(packet_count)]
        if display_filter:
            args.extend(["-Y", display_filter])

        output = await run_tshark(args, timeout=60)

        if output.strip():
            packets = json.loads(output)
            count = len(packets) if isinstance(packets, list) else 1

            return [
                TextContent(
                    type="text",
                    text=f"Read {count} packet(s) from {file_path}\n\n"
                    f"Preview:\n{json.dumps(packets[:5] if isinstance(packets, list) else packets, indent=2)}",
                )
            ]
        return [
            TextContent(
                type="text",
                text=f"No packets found in {file_path}"
                + (f" matching filter '{display_filter}'" if display_filter else ""),
            )
        ]

    except json.JSONDecodeError as e:
        return [TextContent(type="text", text=f"Error parsing packet data: {e}")]
    except Exception as e:
        return [TextContent(type="text", text=f"Error reading pcap file: {e}")]


async def handle_display_filter(arguments: dict[str, Any]) -> list[TextContent]:
    """Apply display filter to pcap file."""
    file_path = arguments["file_path"]
    filter_expr = arguments["filter"]
    packet_count = arguments.get("packet_count", 100)

    try:
        if not Path(file_path).exists():
            return [TextContent(type="text", text=f"Error: File not found: {file_path}")]

        args = [
            "-r",
            file_path,
            "-Y",
            filter_expr,
            "-T",
            "json",
            "-c",
            str(packet_count),
        ]

        output = await run_tshark(args, timeout=60)

        if output.strip():
            packets = json.loads(output)
            count = len(packets) if isinstance(packets, list) else 1

            return [
                TextContent(
                    type="text",
                    text=f"Found {count} packet(s) matching filter '{filter_expr}'\n\n"
                    f"Preview:\n{json.dumps(packets[:5] if isinstance(packets, list) else packets, indent=2)}",
                )
            ]
        return [
            TextContent(
                type="text",
                text=f"No packets found matching filter '{filter_expr}'",
            )
        ]

    except Exception as e:
        return [TextContent(type="text", text=f"Error applying display filter: {e}")]


async def handle_stats_by_proto(arguments: dict[str, Any]) -> list[TextContent]:
    """Generate protocol statistics."""
    file_path = arguments["file_path"]

    try:
        if not Path(file_path).exists():
            return [TextContent(type="text", text=f"Error: File not found: {file_path}")]

        # Use tshark statistics
        args = ["-r", file_path, "-q", "-z", "io,phs"]

        output = await run_tshark(args, timeout=60)

        return [
            TextContent(
                type="text",
                text=f"Protocol Statistics for {file_path}:\n\n{output}",
            )
        ]

    except Exception as e:
        return [TextContent(type="text", text=f"Error generating statistics: {e}")]


async def handle_follow_tcp(arguments: dict[str, Any]) -> list[TextContent]:
    """Follow a TCP stream."""
    file_path = arguments["file_path"]
    stream_id = arguments.get("stream_id", 0)

    try:
        if not Path(file_path).exists():
            return [TextContent(type="text", text=f"Error: File not found: {file_path}")]

        # Follow TCP stream
        args = ["-r", file_path, "-q", "-z", f"follow,tcp,ascii,{stream_id}"]

        output = await run_tshark(args, timeout=60)

        if output.strip():
            return [
                TextContent(
                    type="text",
                    text=f"TCP Stream {stream_id} from {file_path}:\n\n{output}",
                )
            ]
        return [
            TextContent(
                type="text",
                text=f"No data found for TCP stream {stream_id}",
            )
        ]

    except Exception as e:
        return [TextContent(type="text", text=f"Error following TCP stream: {e}")]


async def handle_export_json(arguments: dict[str, Any]) -> list[TextContent]:
    """Export packets to JSON."""
    file_path = arguments["file_path"]
    output_path = arguments["output_path"]
    packet_count = arguments.get("packet_count", 1000)
    display_filter = arguments.get("display_filter")

    try:
        if not Path(file_path).exists():
            return [TextContent(type="text", text=f"Error: File not found: {file_path}")]

        # Build command
        args = ["-r", file_path, "-T", "json", "-c", str(packet_count)]
        if display_filter:
            args.extend(["-Y", display_filter])

        output = await run_tshark(args, timeout=120)

        # Write to file
        Path(output_path).write_text(output)

        if output.strip():
            packets = json.loads(output)
            count = len(packets) if isinstance(packets, list) else 1

            return [
                TextContent(
                    type="text",
                    text=f"Exported {count} packet(s) from {file_path} to {output_path}",
                )
            ]
        return [
            TextContent(
                type="text",
                text=f"No packets to export from {file_path}",
            )
        ]

    except Exception as e:
        return [TextContent(type="text", text=f"Error exporting to JSON: {e}")]


async def main() -> None:
    """Run the MCP server."""
    from mcp.server.stdio import stdio_server

    async with stdio_server() as (read_stream, write_stream):
        await app.run(
            read_stream,
            write_stream,
            app.create_initialization_options(),
        )
