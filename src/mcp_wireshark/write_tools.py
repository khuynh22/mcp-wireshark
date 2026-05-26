"""Write tools — capture live traffic and export packets to disk.

Tools in this module have side effects: they create or modify files, or pull
packets off the network. They are annotated with ``readOnlyHint=False`` and
``destructiveHint=False`` (additive: they create new files, never overwrite or
delete existing user data without an explicit path argument).
"""

import json
import tempfile
from pathlib import Path
from typing import Any

from mcp.types import TextContent, Tool, ToolAnnotations

from .utils import check_wireshark_installed, run_dumpcap, run_tshark
from .validation import (
    MAX_DURATION_SECONDS,
    MAX_PACKET_COUNT,
    validate_display_filter,
    validate_file_path,
)


def _additive_write(title: str) -> ToolAnnotations:
    """Annotation factory for tools that create new files / capture traffic."""
    return ToolAnnotations(
        title=title,
        readOnlyHint=False,
        destructiveHint=False,
        idempotentHint=False,
        openWorldHint=True,
    )


WRITE_TOOLS: list[Tool] = [
    Tool(
        name="live_capture",
        description="Capture live network traffic from an interface. Writes to a "
        "temporary pcap that is deleted after the preview is returned.",
        annotations=_additive_write("Live packet capture"),
        inputSchema={
            "type": "object",
            "properties": {
                "interface": {
                    "type": "string",
                    "description": "Network interface name (e.g., eth0, Wi-Fi)",
                },
                "duration": {
                    "type": "number",
                    "description": "Capture duration in seconds (default: 10, max: 300)",
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
        name="export_json",
        description="Export packets from a pcap file to a JSON file at output_path. "
        "Creates the output file if it does not exist; overwrites if it does.",
        annotations=_additive_write("Export packets to JSON"),
        inputSchema={
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "Path to the source .pcap or .pcapng file",
                },
                "output_path": {
                    "type": "string",
                    "description": "Path where the JSON output will be written",
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


async def handle_live_capture(arguments: dict[str, Any]) -> list[TextContent]:
    """Capture live traffic from an interface."""
    interface = arguments["interface"]
    duration = min(arguments.get("duration", 10), MAX_DURATION_SECONDS)
    packet_count = arguments.get("packet_count")
    if packet_count:
        packet_count = min(packet_count, MAX_PACKET_COUNT)
    display_filter = arguments.get("display_filter")

    temp_path: str | None = None
    try:
        if display_filter:
            display_filter = validate_display_filter(display_filter)

        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as temp_file:
            temp_path = temp_file.name

        args = ["-i", interface, "-w", temp_path, "-a", f"duration:{duration}"]
        if packet_count:
            args.extend(["-c", str(packet_count)])

        tools = check_wireshark_installed()
        if tools["dumpcap"]:
            await run_dumpcap(args, timeout=duration + 10)
        else:
            await run_tshark(args, timeout=duration + 10)

        # tshark's -c counts raw frames before -Y is applied, so combining the
        # two would silently drop matches outside the first N frames. Drop -c
        # when filtering and slice in Python.
        read_args = ["-r", temp_path, "-T", "json"]
        if display_filter:
            read_args.extend(["-Y", display_filter])
        else:
            read_args.extend(["-c", "100"])

        output = await run_tshark(read_args, timeout=30)

        Path(temp_path).unlink(missing_ok=True)

        if output.strip():
            packets = json.loads(output)
            if isinstance(packets, list):
                packets = packets[:100]
                count = len(packets)
                preview = packets[:5]
            else:
                count = 1
                preview = packets
            return [
                TextContent(
                    type="text",
                    text=f"Captured {count} packet(s) from interface '{interface}'\n\n"
                    f"Preview:\n{json.dumps(preview, indent=2)}",
                )
            ]
        return [
            TextContent(
                type="text",
                text=f"No packets captured from interface '{interface}' in {duration} seconds",
            )
        ]

    except Exception as e:
        if temp_path:
            Path(temp_path).unlink(missing_ok=True)
        return [TextContent(type="text", text=f"Error during live capture: {e}")]


async def handle_export_json(arguments: dict[str, Any]) -> list[TextContent]:
    """Export packets to a JSON file at the user-supplied path."""
    file_path = arguments["file_path"]
    output_path = arguments["output_path"]
    packet_count = min(arguments.get("packet_count", 1000), MAX_PACKET_COUNT)
    display_filter = arguments.get("display_filter")

    try:
        validated_path = validate_file_path(file_path)
        if not validated_path.exists():
            return [TextContent(type="text", text=f"Error: File not found: {file_path}")]
        file_path = str(validated_path)

        if display_filter:
            display_filter = validate_display_filter(display_filter)

        # tshark's -c counts raw frames before -Y is applied, so dropping it
        # when a filter is set and slicing in Python is the only way to get
        # exactly N matches written to disk.
        args = ["-r", file_path, "-T", "json"]
        if display_filter:
            args.extend(["-Y", display_filter])
        else:
            args.extend(["-c", str(packet_count)])

        output = await run_tshark(args, timeout=120)

        if output.strip():
            packets = json.loads(output)
            if isinstance(packets, list):
                packets = packets[:packet_count]
                count = len(packets)
            else:
                count = 1
            Path(output_path).write_text(json.dumps(packets, indent=2))
            return [
                TextContent(
                    type="text",
                    text=f"Exported {count} packet(s) from {file_path} to {output_path}",
                )
            ]
        Path(output_path).write_text(output)
        return [TextContent(type="text", text=f"No packets to export from {file_path}")]

    except Exception as e:
        return [TextContent(type="text", text=f"Error exporting to JSON: {e}")]


WRITE_HANDLERS = {
    "live_capture": handle_live_capture,
    "export_json": handle_export_json,
}
