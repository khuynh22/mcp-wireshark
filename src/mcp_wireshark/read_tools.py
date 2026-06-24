"""Read-only tools — inspect tshark, list interfaces, and analyze pcap files.

Every tool in this module is annotated with ``readOnlyHint=True``. None of them
write files, capture traffic, or modify any environment state. They are safe to
call freely.
"""

import asyncio
import json
from typing import Any

from mcp.types import TextContent, Tool, ToolAnnotations

from .iec61850 import (
    BASE_FILTERS,
    FIELD_SETS,
    analyze_goose,
    analyze_mms,
    analyze_sv,
    format_report,
    parse_field_rows,
)
from .utils import run_tshark
from .validation import MAX_PACKET_COUNT, validate_display_filter, validate_file_path

# Dispatch table mapping a protocol token to its analyzer (see iec61850.py).
_IEC_ANALYZERS = {
    "goose": analyze_goose,
    "sv": analyze_sv,
    "mms": analyze_mms,
}


def _read_only(title: str) -> ToolAnnotations:
    """Annotation factory for tools that don't modify any state."""
    return ToolAnnotations(title=title, readOnlyHint=True, openWorldHint=False)


# Curated default field sets per protocol used by ``decode_protocol``. The key
# is the protocol token used both as the base display filter and the keyword
# that selects the default field list. Values are tshark ``-e`` field names
# ordered for human readability.
#
# Adding a protocol: pick the 5-10 fields that an analyst would write down
# manually when triaging that protocol. Keep ``frame.number`` first.
PROTOCOL_DEFAULTS: dict[str, list[str]] = {
    "http": [
        "frame.number",
        "ip.src",
        "ip.dst",
        "http.request.method",
        "http.request.uri",
        "http.host",
        "http.response.code",
        "http.response.phrase",
        "http.content_type",
    ],
    "dns": [
        "frame.number",
        "ip.src",
        "ip.dst",
        "dns.flags.response",
        "dns.qry.name",
        "dns.qry.type",
        "dns.flags.rcode",
        "dns.a",
        "dns.aaaa",
        "dns.cname",
    ],
    "tls": [
        "frame.number",
        "ip.src",
        "ip.dst",
        "tls.handshake.type",
        "tls.handshake.version",
        "tls.handshake.extensions_server_name",
        "tls.handshake.ciphersuite",
        "x509ce.dNSName",
    ],
    "goose": [
        "frame.number",
        "frame.time_relative",
        "eth.src",
        "eth.dst",
        "goose.gocbRef",
        "goose.datSet",
        "goose.stNum",
        "goose.sqNum",
        "goose.timeAllowedtoLive",
        "goose.ndsCom",
    ],
    "mms": [
        "frame.number",
        "ip.src",
        "ip.dst",
        "mms.invokeID",
        "mms.confirmedServiceRequest",
        "mms.confirmedServiceResponse",
        "mms.domainId",
        "mms.objectName_domain_specific_itemId",
    ],
    "sv": [
        "frame.number",
        "frame.time_relative",
        "eth.src",
        "eth.dst",
        "sv.svID",
        "sv.smpCnt",
        "sv.smpSynch",
        "sv.confRev",
    ],
    "sip": [
        "frame.number",
        "ip.src",
        "ip.dst",
        "sip.Method",
        "sip.Request-Line",
        "sip.Status-Code",
        "sip.from.user",
        "sip.to.user",
        "sip.Call-ID",
    ],
    "icmp": [
        "frame.number",
        "ip.src",
        "ip.dst",
        "icmp.type",
        "icmp.code",
    ],
}

# Some protocols need a base display filter that isn't just the protocol
# token — TLS only matches handshake records by default, and HTTP only
# matches request/response packets to skip the chunked-data frames.
PROTOCOL_BASE_FILTERS: dict[str, str] = {
    "http": "http.request or http.response",
    "tls": "tls.handshake",
}


# Whitelist of supported (protocol, variant) pairs for ``protocol_stats``.
# Maps to the full ``-z`` argument string. tshark accepts many variants;
# this list is the high-signal subset that parses cleanly into LLM context.
STATS_VARIANTS: dict[tuple[str, str], str] = {
    ("io", "phs"): "io,phs",
    ("io", "stat"): "io,stat,0",
    ("conv", "ip"): "conv,ip",
    ("conv", "ipv6"): "conv,ipv6",
    ("conv", "tcp"): "conv,tcp",
    ("conv", "udp"): "conv,udp",
    ("conv", "eth"): "conv,eth",
    ("endpoints", "ip"): "endpoints,ip",
    ("endpoints", "ipv6"): "endpoints,ipv6",
    ("endpoints", "tcp"): "endpoints,tcp",
    ("endpoints", "udp"): "endpoints,udp",
    ("endpoints", "eth"): "endpoints,eth",
    ("http", "tree"): "http,tree",
    ("http", "stat"): "http,stat",
    ("http_req", "tree"): "http_req,tree",
    ("dns", "tree"): "dns,tree",
    ("smb", "srt"): "smb,srt",
    ("smb2", "srt"): "smb2,srt",
    ("rpc", "srt"): "rpc,srt",
    ("sip", "stat"): "sip,stat",
}


def _supported_protocols() -> str:
    return ", ".join(sorted(PROTOCOL_DEFAULTS))


def _supported_stats() -> str:
    seen: dict[str, list[str]] = {}
    for proto, variant in STATS_VARIANTS:
        seen.setdefault(proto, []).append(variant)
    return "; ".join(f"{p}: {', '.join(sorted(v))}" for p, v in sorted(seen.items()))


def _resolve_protocol(protocol: str) -> tuple[str, list[str] | None]:
    """Map a protocol token to (base_filter, default_fields).

    If ``protocol`` is a known curated key, returns the configured base filter
    (or the protocol token itself) and the default field list. Otherwise the
    token is treated as an arbitrary display filter and no defaults are
    returned — caller must supply ``fields``.
    """
    key = protocol.strip().lower()
    if key in PROTOCOL_DEFAULTS:
        base = PROTOCOL_BASE_FILTERS.get(key, key)
        return base, list(PROTOCOL_DEFAULTS[key])
    return protocol, None


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
    Tool(
        name="expert_info",
        description=(
            "Run tshark expert analysis on a pcap file. Returns warnings, errors, "
            "and notes grouped by severity. Useful for diagnosing protocol issues "
            "without reading individual packets."
        ),
        annotations=_read_only("Expert info analysis"),
        inputSchema={
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "Path to the .pcap or .pcapng file",
                },
                "severity": {
                    "type": "string",
                    "description": (
                        "Minimum severity to report: 'chat', 'note', 'warn', or "
                        "'error' (default: 'warn')"
                    ),
                    "enum": ["chat", "note", "warn", "error"],
                    "default": "warn",
                },
            },
            "required": ["file_path"],
        },
    ),
    Tool(
        name="decode_protocol",
        description=(
            "Extract protocol-specific fields from a pcap file using tshark "
            "'-T fields'. Pass a known protocol name to use curated defaults "
            f"(supported: {_supported_protocols()}), or supply your own 'fields' "
            "list for any other protocol. Returns a tab-separated table — "
            "much smaller than full JSON. Use a 'filter' to narrow results "
            "(e.g. only request packets, only specific stNum values)."
        ),
        annotations=_read_only("Decode protocol fields"),
        inputSchema={
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "Path to the .pcap or .pcapng file",
                },
                "protocol": {
                    "type": "string",
                    "description": (
                        "Protocol name or display filter (e.g. 'http', 'goose', "
                        "'mms', 'sv', 'sip', or any tshark display filter such "
                        "as 'icmp.type == 8')"
                    ),
                },
                "fields": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "Optional override of the field list. If omitted and the "
                        "protocol has curated defaults, those are used. Required "
                        "for protocols without defaults. Max 20 fields."
                    ),
                },
                "filter": {
                    "type": "string",
                    "description": (
                        "Optional additional display filter ANDed with the "
                        "protocol filter (e.g. 'goose.stNum >= 5'). Numeric "
                        "comparisons with == != >= <= are supported."
                    ),
                },
                "packet_count": {
                    "type": "number",
                    "description": "Maximum number of packets to return (default: 50)",
                    "default": 50,
                },
            },
            "required": ["file_path", "protocol"],
        },
    ),
    Tool(
        name="protocol_stats",
        description=(
            "Run a tshark '-z' aggregate-statistics report on a pcap file and "
            "return its parsed output. Use this for protocol-hierarchy, "
            "conversation, endpoint, and per-protocol stat tables — much "
            "more compact than per-packet JSON. Supported (protocol, variant) "
            f"pairs: {_supported_stats()}."
        ),
        annotations=_read_only("Protocol aggregate statistics"),
        inputSchema={
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "Path to the .pcap or .pcapng file",
                },
                "protocol": {
                    "type": "string",
                    "description": (
                        "Stat family: 'io', 'conv', 'endpoints', 'http', "
                        "'http_req', 'dns', 'smb', 'smb2', 'rpc', 'sip'"
                    ),
                },
                "variant": {
                    "type": "string",
                    "description": (
                        "Variant within the family: e.g. 'phs', 'stat', 'tree', "
                        "'srt', 'ip', 'ipv6', 'tcp', 'udp', 'eth'"
                    ),
                },
                "max_lines": {
                    "type": "number",
                    "description": (
                        "Maximum number of output lines to return (default: 100). "
                        "Conversation/endpoint tables can be very long."
                    ),
                    "default": 100,
                },
            },
            "required": ["file_path", "protocol", "variant"],
        },
    ),
    Tool(
        name="analyze_iec61850",
        description=(
            "Analyze an IEC 61850 capture for protocol health and return a "
            "compact, worst-first OK/WARN/FAIL report per source. protocol is "
            "one of 'goose' (stNum/sqNum gaps, timeAllowedtoLive violations, "
            "state-change storms), 'sv' (smpCnt continuity, loss of time sync, "
            "confRev changes), or 'mms' (error/reject PDUs, unpaired requests, "
            "slow responses). Scans the whole capture but returns only a bounded "
            "summary, so it is safe on high-rate SV streams."
        ),
        annotations=_read_only("Analyze IEC 61850 health"),
        inputSchema={
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "Path to the .pcap or .pcapng file",
                },
                "protocol": {
                    "type": "string",
                    "enum": ["goose", "sv", "mms"],
                    "description": "IEC 61850 protocol to analyze",
                },
                "filter": {
                    "type": "string",
                    "description": (
                        "Optional display filter ANDed with the protocol filter "
                        "to scope to one gocbRef/svID/host (e.g. "
                        'goose.gocbRef contains "gcb01")'
                    ),
                },
            },
            "required": ["file_path", "protocol"],
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


async def handle_expert_info(arguments: dict[str, Any]) -> list[TextContent]:
    """Run ``tshark -z expert,<severity>`` and return grouped findings."""
    file_path = arguments["file_path"]
    severity = arguments.get("severity", "warn")

    try:
        validated_path = validate_file_path(file_path)
        if not validated_path.exists():
            return [TextContent(type="text", text=f"Error: File not found: {file_path}")]
        file_path = str(validated_path)

        if severity not in {"chat", "note", "warn", "error"}:
            return [
                TextContent(
                    type="text",
                    text=f"Error: invalid severity {severity!r}. "
                    "Use 'chat', 'note', 'warn', or 'error'.",
                )
            ]

        args = ["-r", file_path, "-q", "-z", f"expert,{severity}"]
        output = await run_tshark(args, timeout=60)

        if output.strip():
            return [
                TextContent(
                    type="text",
                    text=f"Expert Info (severity >= {severity}):\n\n{output.strip()}",
                )
            ]
        return [TextContent(type="text", text="No expert info entries found.")]

    except Exception as e:
        return [TextContent(type="text", text=f"Error running expert analysis: {e}")]


async def handle_decode_protocol(arguments: dict[str, Any]) -> list[TextContent]:
    """Extract per-packet protocol fields via ``tshark -T fields -e ...``."""
    file_path = arguments["file_path"]
    protocol = arguments["protocol"]
    user_fields = arguments.get("fields")
    user_filter = arguments.get("filter")
    packet_count = min(int(arguments.get("packet_count", 50)), MAX_PACKET_COUNT)

    try:
        validated_path = validate_file_path(file_path)
        if not validated_path.exists():
            return [TextContent(type="text", text=f"Error: File not found: {file_path}")]
        file_path = str(validated_path)

        if not isinstance(protocol, str) or not protocol.strip():
            return [TextContent(type="text", text="Error: 'protocol' must be a non-empty string.")]

        base_filter, default_fields = _resolve_protocol(protocol)

        # Field list resolution: explicit user fields win; otherwise fall back
        # to curated defaults; otherwise error out.
        if user_fields is not None:
            if not isinstance(user_fields, list) or not user_fields:
                return [
                    TextContent(
                        type="text",
                        text="Error: 'fields' must be a non-empty list when provided.",
                    )
                ]
            if len(user_fields) > 20:
                return [TextContent(type="text", text="Error: maximum 20 fields allowed.")]
            fields: list[str] = []
            for field in user_fields:
                if not isinstance(field, str) or not field.strip():
                    return [TextContent(type="text", text=f"Error: invalid field name: {field!r}")]
                validate_display_filter(field)
                fields.append(field.strip())
        elif default_fields is not None:
            fields = default_fields
        else:
            return [
                TextContent(
                    type="text",
                    text=(
                        f"Error: protocol {protocol!r} has no curated defaults. "
                        "Pass an explicit 'fields' list. Known protocols with "
                        f"defaults: {_supported_protocols()}."
                    ),
                )
            ]

        # base_filter is either a known internal string (PROTOCOL_BASE_FILTERS)
        # or the user-supplied ``protocol`` token; either way validate it.
        base_filter = validate_display_filter(base_filter)
        if user_filter:
            user_filter = validate_display_filter(user_filter)
            combined_filter = f"({base_filter}) and ({user_filter})"
        else:
            combined_filter = base_filter

        args = ["-r", file_path, "-Y", combined_filter, "-T", "fields"]
        for f in fields:
            args.extend(["-e", f])
        args.extend(["-E", "header=y", "-E", "separator=\t", "-E", "quote=n"])

        output = await run_tshark(args, timeout=60)

        if output.strip():
            lines = output.strip().split("\n")
            limited = lines[: packet_count + 1]  # +1 to retain the header row
            count = max(len(limited) - 1, 0)
            total = max(len(lines) - 1, 0)
            suffix = f" (showing first {count} of {total})" if total > count else ""
            return [
                TextContent(
                    type="text",
                    text=(
                        f"Protocol '{protocol}' — {count} packet(s){suffix}:\n\n"
                        + "\n".join(limited)
                    ),
                )
            ]
        return [
            TextContent(
                type="text",
                text=f"No packets matching filter '{combined_filter}' found.",
            )
        ]

    except Exception as e:
        return [TextContent(type="text", text=f"Error decoding protocol: {e}")]


async def handle_protocol_stats(arguments: dict[str, Any]) -> list[TextContent]:
    """Run a whitelisted ``tshark -z`` aggregate-statistics variant."""
    file_path = arguments["file_path"]
    protocol = arguments.get("protocol", "")
    variant = arguments.get("variant", "")
    max_lines = int(arguments.get("max_lines", 100))
    if max_lines <= 0:
        max_lines = 100

    try:
        validated_path = validate_file_path(file_path)
        if not validated_path.exists():
            return [TextContent(type="text", text=f"Error: File not found: {file_path}")]
        file_path = str(validated_path)

        if not isinstance(protocol, str) or not isinstance(variant, str):
            return [
                TextContent(type="text", text="Error: 'protocol' and 'variant' must be strings.")
            ]

        key = (protocol.strip().lower(), variant.strip().lower())
        z_arg = STATS_VARIANTS.get(key)
        if z_arg is None:
            return [
                TextContent(
                    type="text",
                    text=(
                        f"Error: unsupported (protocol, variant) pair "
                        f"({protocol!r}, {variant!r}). Supported: {_supported_stats()}."
                    ),
                )
            ]

        args = ["-r", file_path, "-q", "-z", z_arg]
        output = await run_tshark(args, timeout=60)

        if not output.strip():
            return [
                TextContent(
                    type="text",
                    text=f"No statistics returned for {z_arg} on {file_path}.",
                )
            ]

        lines = output.splitlines()
        if len(lines) > max_lines:
            kept = lines[:max_lines]
            kept.append(f"... ({len(lines) - max_lines} more line(s) truncated)")
        else:
            kept = lines

        return [
            TextContent(
                type="text",
                text=f"Stats '{z_arg}' for {file_path}:\n\n" + "\n".join(kept),
            )
        ]

    except Exception as e:
        return [TextContent(type="text", text=f"Error running stats: {e}")]


async def handle_analyze_iec61850(arguments: dict[str, Any]) -> list[TextContent]:
    """Analyze GOOSE/SV/MMS health and return a worst-first text report."""
    file_path = arguments["file_path"]
    protocol = str(arguments.get("protocol", "")).strip().lower()
    user_filter = arguments.get("filter")

    try:
        if protocol not in BASE_FILTERS:
            return [
                TextContent(
                    type="text",
                    text=f"Error: 'protocol' must be one of {', '.join(sorted(BASE_FILTERS))}.",
                )
            ]

        validated_path = validate_file_path(file_path)
        if not validated_path.exists():
            return [TextContent(type="text", text=f"Error: File not found: {file_path}")]
        file_path = str(validated_path)

        base_filter = BASE_FILTERS[protocol]
        if user_filter:
            user_filter = validate_display_filter(user_filter)
            combined_filter = f"({base_filter}) and ({user_filter})"
        else:
            combined_filter = base_filter

        columns = FIELD_SETS[protocol]
        args = ["-r", file_path, "-Y", combined_filter, "-T", "fields"]
        for column in columns:
            args.extend(["-e", column])
        args.extend(["-E", "header=y", "-E", "separator=\t", "-E", "quote=n"])

        output = await run_tshark(args, timeout=120)
        rows = parse_field_rows(output, columns)
        if not rows:
            return [
                TextContent(
                    type="text",
                    text=f"No {protocol.upper()} packets found in {file_path}"
                    + (f" matching filter '{user_filter}'" if user_filter else ""),
                )
            ]

        report = _IEC_ANALYZERS[protocol](rows)
        return [TextContent(type="text", text=format_report(protocol, file_path, report))]

    except Exception as e:
        return [TextContent(type="text", text=f"Error analyzing IEC 61850 capture: {e}")]


READ_HANDLERS = {
    "check_installation": handle_check_installation,
    "list_interfaces": handle_list_interfaces,
    "read_pcap": handle_read_pcap,
    "display_filter": handle_display_filter,
    "summarize_pcap": handle_summarize_pcap,
    "stats_by_proto": handle_stats_by_proto,
    "follow_tcp": handle_follow_tcp,
    "follow_udp": handle_follow_udp,
    "expert_info": handle_expert_info,
    "decode_protocol": handle_decode_protocol,
    "protocol_stats": handle_protocol_stats,
    "analyze_iec61850": handle_analyze_iec61850,
}
