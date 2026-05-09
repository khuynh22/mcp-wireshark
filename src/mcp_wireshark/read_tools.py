"""Read-only tools — inspect tshark, list interfaces, and analyze pcap files.

Every tool in this module is annotated with ``readOnlyHint=True``. None of them
write files, capture traffic, or modify any environment state. They are safe to
call freely.
"""

import asyncio
import json
from typing import Any

from mcp.types import TextContent, Tool, ToolAnnotations

from .utils import run_tshark
from .validation import MAX_PACKET_COUNT, validate_display_filter, validate_file_path


def _read_only(title: str) -> ToolAnnotations:
    """Annotation factory for tools that don't modify any state."""
    return ToolAnnotations(title=title, readOnlyHint=True, openWorldHint=False)


READ_TOOLS: list[Tool] = [
    Tool(
        name="check_installation",
        description="Check if Wireshark/tshark is installed and return version info.",
        annotations=_read_only("Check tshark installation"),
        inputSchema={"type": "object", "properties": {}},
    ),
    Tool(
        name="list_interfaces",
        description="List all network interfaces available for packet capture.",
        annotations=_read_only("List network interfaces"),
        inputSchema={"type": "object", "properties": {}},
    ),
    Tool(
        name="read_pcap",
        description="Read and analyze packets from a .pcap or .pcapng file. Returns a "
        "preview of up to 5 packets in JSON plus the total match count.",
        annotations=_read_only("Read pcap file"),
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
        description="Apply a Wireshark display filter to a pcap file and return a "
        "preview of matching packets.",
        annotations=_read_only("Apply display filter"),
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
        name="summarize_pcap",
        description="Get a high-level summary of a pcap file: I/O stats, protocol "
        "hierarchy, and top IP conversations. Prefer this over read_pcap when the "
        "goal is to characterize a capture.",
        annotations=_read_only("Summarize pcap file"),
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
        name="stats_by_proto",
        description="Generate the protocol hierarchy statistics for a pcap file.",
        annotations=_read_only("Protocol hierarchy stats"),
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
        description="Follow a TCP stream by index and return its ASCII payload.",
        annotations=_read_only("Follow TCP stream"),
        inputSchema={
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "Path to the .pcap or .pcapng file",
                },
                "stream_id": {
                    "type": "number",
                    "description": "TCP stream index to follow (default: 0)",
                    "default": 0,
                },
            },
            "required": ["file_path"],
        },
    ),
    Tool(
        name="follow_udp",
        description="Follow a UDP stream by index and return its ASCII payload.",
        annotations=_read_only("Follow UDP stream"),
        inputSchema={
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "Path to the .pcap or .pcapng file",
                },
                "stream_id": {
                    "type": "number",
                    "description": "UDP stream index to follow (default: 0)",
                    "default": 0,
                },
            },
            "required": ["file_path"],
        },
    ),
]


async def handle_check_installation(arguments: dict[str, Any] | None = None) -> list[TextContent]:
    """Return tshark/dumpcap version + path info."""
    del arguments
    from .utils import check_wireshark_installed

    tools = check_wireshark_installed()
    lines = []

    if tools["tshark"]:
        try:
            version_output = await run_tshark(["--version"], timeout=10)
            first_line = version_output.strip().split("\n")[0]
            lines.append(f"tshark: {first_line}")
            lines.append(f"  Path: {tools['tshark']}")
        except Exception as e:
            lines.append(f"tshark: found at {tools['tshark']} (version check failed: {e})")
    else:
        lines.append(
            "tshark: NOT FOUND — install Wireshark from https://www.wireshark.org/download.html"
        )

    if tools["dumpcap"]:
        lines.append(f"dumpcap: found at {tools['dumpcap']} (used for live capture)")
    else:
        lines.append("dumpcap: not found (live capture will fall back to tshark)")

    return [TextContent(type="text", text="\n".join(lines))]


async def handle_list_interfaces(arguments: dict[str, Any] | None = None) -> list[TextContent]:
    """List interfaces visible to tshark -D."""
    del arguments
    try:
        output = await run_tshark(["-D"], timeout=10)
        interfaces = [line for line in output.strip().split("\n") if line]
        return [
            TextContent(
                type="text",
                text=f"Found {len(interfaces)} network interface(s):\n\n" + "\n".join(interfaces),
            )
        ]
    except Exception as e:
        return [TextContent(type="text", text=f"Error listing interfaces: {e}")]


async def handle_read_pcap(arguments: dict[str, Any]) -> list[TextContent]:
    """Read packets from a pcap file. Returns a 5-packet preview."""
    file_path = arguments["file_path"]
    packet_count = min(arguments.get("packet_count", 100), MAX_PACKET_COUNT)
    display_filter = arguments.get("display_filter")

    try:
        validated_path = validate_file_path(file_path)
        if not validated_path.exists():
            return [TextContent(type="text", text=f"Error: File not found: {file_path}")]
        file_path = str(validated_path)

        if display_filter:
            display_filter = validate_display_filter(display_filter)

        # tshark's -c counts raw frames BEFORE -Y is applied, so combining the
        # two silently drops matches that aren't in the first N frames. When a
        # filter is set we omit -c and slice in Python instead.
        args = ["-r", file_path, "-T", "json"]
        if display_filter:
            args.extend(["-Y", display_filter])
        else:
            args.extend(["-c", str(packet_count)])

        output = await run_tshark(args, timeout=60)

        if output.strip():
            packets = json.loads(output)
            if isinstance(packets, list):
                packets = packets[:packet_count]
                count = len(packets)
                preview = packets[:5]
            else:
                count = 1
                preview = packets
            return [
                TextContent(
                    type="text",
                    text=f"Read {count} packet(s) from {file_path}\n\n"
                    f"Preview:\n{json.dumps(preview, indent=2)}",
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
    """Apply a display filter to a pcap file."""
    file_path = arguments["file_path"]
    filter_expr = arguments["filter"]
    packet_count = min(arguments.get("packet_count", 100), MAX_PACKET_COUNT)

    try:
        validated_path = validate_file_path(file_path)
        if not validated_path.exists():
            return [TextContent(type="text", text=f"Error: File not found: {file_path}")]
        file_path = str(validated_path)

        filter_expr = validate_display_filter(filter_expr)

        # tshark's -c counts raw frames BEFORE -Y is applied, which would drop
        # matches that aren't in the first N frames. Read all matches and slice
        # in Python instead. MAX_PACKET_COUNT bounds the output size.
        args = ["-r", file_path, "-Y", filter_expr, "-T", "json"]
        output = await run_tshark(args, timeout=60)

        if output.strip():
            packets = json.loads(output)
            if isinstance(packets, list):
                packets = packets[:packet_count]
                count = len(packets)
                preview = packets[:5]
            else:
                count = 1
                preview = packets
            return [
                TextContent(
                    type="text",
                    text=f"Found {count} packet(s) matching filter '{filter_expr}'\n\n"
                    f"Preview:\n{json.dumps(preview, indent=2)}",
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


async def handle_summarize_pcap(arguments: dict[str, Any]) -> list[TextContent]:
    """High-level pcap summary: I/O stats, proto hierarchy, top IP convs."""
    file_path = arguments["file_path"]

    try:
        validated_path = validate_file_path(file_path)
        if not validated_path.exists():
            return [TextContent(type="text", text=f"Error: File not found: {file_path}")]
        file_path = str(validated_path)

        frame_args = ["-r", file_path, "-q", "-z", "io,stat,0"]
        phs_args = ["-r", file_path, "-q", "-z", "io,phs"]
        talker_args = ["-r", file_path, "-q", "-z", "conv,ip"]

        frame_output, phs_output, talker_output = await asyncio.gather(
            run_tshark(frame_args, timeout=60),
            run_tshark(phs_args, timeout=60),
            run_tshark(talker_args, timeout=60),
        )

        sections = [
            f"=== Summary: {file_path} ===",
            "",
            "--- I/O Statistics ---",
            frame_output.strip(),
            "",
            "--- Protocol Hierarchy ---",
            phs_output.strip(),
            "",
            "--- Top IP Conversations ---",
            talker_output.strip(),
        ]

        return [TextContent(type="text", text="\n".join(sections))]

    except Exception as e:
        return [TextContent(type="text", text=f"Error summarizing pcap: {e}")]


async def handle_stats_by_proto(arguments: dict[str, Any]) -> list[TextContent]:
    """Protocol hierarchy statistics."""
    file_path = arguments["file_path"]

    try:
        validated_path = validate_file_path(file_path)
        if not validated_path.exists():
            return [TextContent(type="text", text=f"Error: File not found: {file_path}")]
        file_path = str(validated_path)

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
    """Follow a TCP stream and return its ASCII payload."""
    file_path = arguments["file_path"]
    stream_id = arguments.get("stream_id", 0)

    try:
        validated_path = validate_file_path(file_path)
        if not validated_path.exists():
            return [TextContent(type="text", text=f"Error: File not found: {file_path}")]
        file_path = str(validated_path)

        args = ["-r", file_path, "-q", "-z", f"follow,tcp,ascii,{stream_id}"]
        output = await run_tshark(args, timeout=60)

        if output.strip():
            return [
                TextContent(
                    type="text",
                    text=f"TCP Stream {stream_id} from {file_path}:\n\n{output}",
                )
            ]
        return [TextContent(type="text", text=f"No data found for TCP stream {stream_id}")]

    except Exception as e:
        return [TextContent(type="text", text=f"Error following TCP stream: {e}")]


async def handle_follow_udp(arguments: dict[str, Any]) -> list[TextContent]:
    """Follow a UDP stream and return its ASCII payload."""
    file_path = arguments["file_path"]
    stream_id = arguments.get("stream_id", 0)

    try:
        validated_path = validate_file_path(file_path)
        if not validated_path.exists():
            return [TextContent(type="text", text=f"Error: File not found: {file_path}")]
        file_path = str(validated_path)

        args = ["-r", file_path, "-q", "-z", f"follow,udp,ascii,{stream_id}"]
        output = await run_tshark(args, timeout=60)

        if output.strip():
            return [
                TextContent(
                    type="text",
                    text=f"UDP Stream {stream_id} from {file_path}:\n\n{output}",
                )
            ]
        return [TextContent(type="text", text=f"No data found for UDP stream {stream_id}")]

    except Exception as e:
        return [TextContent(type="text", text=f"Error following UDP stream: {e}")]


READ_HANDLERS = {
    "check_installation": handle_check_installation,
    "list_interfaces": handle_list_interfaces,
    "read_pcap": handle_read_pcap,
    "display_filter": handle_display_filter,
    "summarize_pcap": handle_summarize_pcap,
    "stats_by_proto": handle_stats_by_proto,
    "follow_tcp": handle_follow_tcp,
    "follow_udp": handle_follow_udp,
}
