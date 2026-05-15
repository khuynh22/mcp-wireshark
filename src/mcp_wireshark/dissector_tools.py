"""Protocol-specific dissector tools — structured extraction of application-layer fields.

These tools parse protocol-specific information from pcap files using tshark's
field extraction (`-T fields -e`) and statistics (`-z`) capabilities. They return
focused, token-efficient output rather than full JSON packet dumps.

Every tool in this module is annotated with ``readOnlyHint=True``.
"""

from typing import Any

from mcp.types import TextContent, Tool, ToolAnnotations

from .utils import run_tshark
from .validation import MAX_PACKET_COUNT, validate_display_filter, validate_file_path


def _read_only(title: str) -> ToolAnnotations:
    return ToolAnnotations(title=title, readOnlyHint=True, openWorldHint=False)


DISSECTOR_TOOLS: list[Tool] = [
    Tool(
        name="decode_http",
        description="Extract HTTP transactions from a pcap file: request method, URI, "
        "host, status code, and content type. Returns a compact table.",
        annotations=_read_only("Decode HTTP transactions"),
        inputSchema={
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "Path to the .pcap or .pcapng file",
                },
                "display_filter": {
                    "type": "string",
                    "description": "Additional display filter to narrow results (optional)",
                },
                "packet_count": {
                    "type": "number",
                    "description": "Maximum number of transactions to return (default: 50)",
                    "default": 50,
                },
            },
            "required": ["file_path"],
        },
    ),
    Tool(
        name="decode_dns",
        description="Extract DNS queries and responses: query name, type, response "
        "code, and answers. Returns a compact table.",
        annotations=_read_only("Decode DNS queries/responses"),
        inputSchema={
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "Path to the .pcap or .pcapng file",
                },
                "display_filter": {
                    "type": "string",
                    "description": "Additional display filter to narrow results (optional)",
                },
                "packet_count": {
                    "type": "number",
                    "description": "Maximum number of DNS packets to return (default: 50)",
                    "default": 50,
                },
            },
            "required": ["file_path"],
        },
    ),
    Tool(
        name="decode_tls",
        description="Extract TLS handshake information: version, cipher suites, SNI, "
        "and certificate subjects. Focuses on ClientHello/ServerHello messages.",
        annotations=_read_only("Decode TLS handshakes"),
        inputSchema={
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "Path to the .pcap or .pcapng file",
                },
                "display_filter": {
                    "type": "string",
                    "description": "Additional display filter to narrow results (optional)",
                },
                "packet_count": {
                    "type": "number",
                    "description": "Maximum number of handshake records to return (default: 50)",
                    "default": 50,
                },
            },
            "required": ["file_path"],
        },
    ),
    Tool(
        name="decode_goose",
        description="Extract IEC 61850 GOOSE messages: gocbRef, datSet, stNum, sqNum, "
        "timeAllowedtoLive, and data values. Essential for substation automation analysis.",
        annotations=_read_only("Decode GOOSE messages"),
        inputSchema={
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "Path to the .pcap or .pcapng file",
                },
                "display_filter": {
                    "type": "string",
                    "description": "Additional display filter (optional, e.g. 'goose.stNum > 0')",
                },
                "packet_count": {
                    "type": "number",
                    "description": "Maximum number of GOOSE messages to return (default: 50)",
                    "default": 50,
                },
            },
            "required": ["file_path"],
        },
    ),
    Tool(
        name="expert_info",
        description="Run tshark expert analysis on a pcap file. Returns warnings, "
        "errors, and notes grouped by severity. Useful for diagnosing protocol issues.",
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
                    "description": "Minimum severity: 'chat', 'note', 'warn', or 'error' "
                    "(default: 'warn')",
                    "enum": ["chat", "note", "warn", "error"],
                    "default": "warn",
                },
            },
            "required": ["file_path"],
        },
    ),
    Tool(
        name="decode_protocol",
        description="Generic protocol field extraction. Specify a protocol filter and "
        "a list of tshark field names to extract. Returns a tab-separated table.",
        annotations=_read_only("Generic protocol field extraction"),
        inputSchema={
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "Path to the .pcap or .pcapng file",
                },
                "protocol_filter": {
                    "type": "string",
                    "description": "Display filter to select the protocol (e.g. 'sip', 'mms', "
                    "'sv', 'icmp')",
                },
                "fields": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of tshark field names to extract "
                    "(e.g. ['ip.src', 'ip.dst', 'tcp.port'])",
                },
                "packet_count": {
                    "type": "number",
                    "description": "Maximum number of packets to return (default: 50)",
                    "default": 50,
                },
            },
            "required": ["file_path", "protocol_filter", "fields"],
        },
    ),
]


async def handle_decode_http(arguments: dict[str, Any]) -> list[TextContent]:
    file_path = arguments["file_path"]
    display_filter = arguments.get("display_filter")
    packet_count = min(arguments.get("packet_count", 50), MAX_PACKET_COUNT)

    try:
        validated_path = validate_file_path(file_path)
        if not validated_path.exists():
            return [TextContent(type="text", text=f"Error: File not found: {file_path}")]
        file_path = str(validated_path)

        base_filter = "http.request || http.response"
        if display_filter:
            display_filter = validate_display_filter(display_filter)
            combined_filter = f"({base_filter}) && ({display_filter})"
        else:
            combined_filter = base_filter

        fields = [
            "frame.number",
            "ip.src",
            "ip.dst",
            "http.request.method",
            "http.request.uri",
            "http.host",
            "http.response.code",
            "http.response.phrase",
            "http.content_type",
        ]
        args = ["-r", file_path, "-Y", combined_filter, "-T", "fields"]
        for f in fields:
            args.extend(["-e", f])
        args.extend(["-E", "header=y", "-E", "separator=\t", "-E", "quote=n"])

        output = await run_tshark(args, timeout=60)

        if output.strip():
            lines = output.strip().split("\n")
            limited = lines[:packet_count + 1]  # +1 for header
            count = len(limited) - 1
            return [
                TextContent(
                    type="text",
                    text=f"HTTP transactions ({count} packets):\n\n" + "\n".join(limited),
                )
            ]
        return [TextContent(type="text", text="No HTTP traffic found in capture.")]

    except Exception as e:
        return [TextContent(type="text", text=f"Error decoding HTTP: {e}")]


async def handle_decode_dns(arguments: dict[str, Any]) -> list[TextContent]:
    file_path = arguments["file_path"]
    display_filter = arguments.get("display_filter")
    packet_count = min(arguments.get("packet_count", 50), MAX_PACKET_COUNT)

    try:
        validated_path = validate_file_path(file_path)
        if not validated_path.exists():
            return [TextContent(type="text", text=f"Error: File not found: {file_path}")]
        file_path = str(validated_path)

        base_filter = "dns"
        if display_filter:
            display_filter = validate_display_filter(display_filter)
            combined_filter = f"({base_filter}) && ({display_filter})"
        else:
            combined_filter = base_filter

        fields = [
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
        ]
        args = ["-r", file_path, "-Y", combined_filter, "-T", "fields"]
        for f in fields:
            args.extend(["-e", f])
        args.extend(["-E", "header=y", "-E", "separator=\t", "-E", "quote=n"])

        output = await run_tshark(args, timeout=60)

        if output.strip():
            lines = output.strip().split("\n")
            limited = lines[:packet_count + 1]
            count = len(limited) - 1
            return [
                TextContent(
                    type="text",
                    text=f"DNS packets ({count}):\n\n" + "\n".join(limited),
                )
            ]
        return [TextContent(type="text", text="No DNS traffic found in capture.")]

    except Exception as e:
        return [TextContent(type="text", text=f"Error decoding DNS: {e}")]


async def handle_decode_tls(arguments: dict[str, Any]) -> list[TextContent]:
    file_path = arguments["file_path"]
    display_filter = arguments.get("display_filter")
    packet_count = min(arguments.get("packet_count", 50), MAX_PACKET_COUNT)

    try:
        validated_path = validate_file_path(file_path)
        if not validated_path.exists():
            return [TextContent(type="text", text=f"Error: File not found: {file_path}")]
        file_path = str(validated_path)

        base_filter = "tls.handshake"
        if display_filter:
            display_filter = validate_display_filter(display_filter)
            combined_filter = f"({base_filter}) && ({display_filter})"
        else:
            combined_filter = base_filter

        fields = [
            "frame.number",
            "ip.src",
            "ip.dst",
            "tls.handshake.type",
            "tls.handshake.version",
            "tls.handshake.extensions_server_name",
            "tls.handshake.ciphersuite",
            "x509ce.dNSName",
        ]
        args = ["-r", file_path, "-Y", combined_filter, "-T", "fields"]
        for f in fields:
            args.extend(["-e", f])
        args.extend(["-E", "header=y", "-E", "separator=\t", "-E", "quote=n"])

        output = await run_tshark(args, timeout=60)

        if output.strip():
            lines = output.strip().split("\n")
            limited = lines[:packet_count + 1]
            count = len(limited) - 1
            return [
                TextContent(
                    type="text",
                    text=f"TLS handshake records ({count}):\n\n" + "\n".join(limited),
                )
            ]
        return [TextContent(type="text", text="No TLS handshake traffic found in capture.")]

    except Exception as e:
        return [TextContent(type="text", text=f"Error decoding TLS: {e}")]


async def handle_decode_goose(arguments: dict[str, Any]) -> list[TextContent]:
    file_path = arguments["file_path"]
    display_filter = arguments.get("display_filter")
    packet_count = min(arguments.get("packet_count", 50), MAX_PACKET_COUNT)

    try:
        validated_path = validate_file_path(file_path)
        if not validated_path.exists():
            return [TextContent(type="text", text=f"Error: File not found: {file_path}")]
        file_path = str(validated_path)

        base_filter = "goose"
        if display_filter:
            display_filter = validate_display_filter(display_filter)
            combined_filter = f"({base_filter}) && ({display_filter})"
        else:
            combined_filter = base_filter

        fields = [
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
        ]
        args = ["-r", file_path, "-Y", combined_filter, "-T", "fields"]
        for f in fields:
            args.extend(["-e", f])
        args.extend(["-E", "header=y", "-E", "separator=\t", "-E", "quote=n"])

        output = await run_tshark(args, timeout=60)

        if output.strip():
            lines = output.strip().split("\n")
            limited = lines[:packet_count + 1]
            count = len(limited) - 1
            return [
                TextContent(
                    type="text",
                    text=f"GOOSE messages ({count}):\n\n" + "\n".join(limited),
                )
            ]
        return [TextContent(type="text", text="No GOOSE traffic found in capture.")]

    except Exception as e:
        return [TextContent(type="text", text=f"Error decoding GOOSE: {e}")]


async def handle_expert_info(arguments: dict[str, Any]) -> list[TextContent]:
    file_path = arguments["file_path"]
    severity = arguments.get("severity", "warn")

    try:
        validated_path = validate_file_path(file_path)
        if not validated_path.exists():
            return [TextContent(type="text", text=f"Error: File not found: {file_path}")]
        file_path = str(validated_path)

        severity_filter = {
            "chat": "chat",
            "note": "note",
            "warn": "warn",
            "error": "error",
        }
        sev = severity_filter.get(severity, "warn")

        args = ["-r", file_path, "-q", "-z", f"expert,{sev}"]
        output = await run_tshark(args, timeout=60)

        if output.strip():
            return [
                TextContent(
                    type="text",
                    text=f"Expert Info (severity >= {sev}):\n\n{output.strip()}",
                )
            ]
        return [TextContent(type="text", text="No expert info entries found.")]

    except Exception as e:
        return [TextContent(type="text", text=f"Error running expert analysis: {e}")]


async def handle_decode_protocol(arguments: dict[str, Any]) -> list[TextContent]:
    file_path = arguments["file_path"]
    protocol_filter = arguments["protocol_filter"]
    fields = arguments["fields"]
    packet_count = min(arguments.get("packet_count", 50), MAX_PACKET_COUNT)

    try:
        validated_path = validate_file_path(file_path)
        if not validated_path.exists():
            return [TextContent(type="text", text=f"Error: File not found: {file_path}")]
        file_path = str(validated_path)

        protocol_filter = validate_display_filter(protocol_filter)

        if not fields or not isinstance(fields, list):
            return [TextContent(type="text", text="Error: 'fields' must be a non-empty list.")]
        if len(fields) > 20:
            return [TextContent(type="text", text="Error: maximum 20 fields allowed.")]

        for field in fields:
            if not isinstance(field, str) or not field.strip():
                return [TextContent(type="text", text=f"Error: invalid field name: {field!r}")]
            validate_display_filter(field)

        args = ["-r", file_path, "-Y", protocol_filter, "-T", "fields"]
        for f in fields:
            args.extend(["-e", f.strip()])
        args.extend(["-E", "header=y", "-E", "separator=\t", "-E", "quote=n"])

        output = await run_tshark(args, timeout=60)

        if output.strip():
            lines = output.strip().split("\n")
            limited = lines[:packet_count + 1]
            count = len(limited) - 1
            return [
                TextContent(
                    type="text",
                    text=f"Protocol '{protocol_filter}' — {count} packet(s):\n\n"
                    + "\n".join(limited),
                )
            ]
        return [
            TextContent(
                type="text",
                text=f"No packets matching filter '{protocol_filter}' found.",
            )
        ]

    except Exception as e:
        return [TextContent(type="text", text=f"Error decoding protocol: {e}")]


DISSECTOR_HANDLERS = {
    "decode_http": handle_decode_http,
    "decode_dns": handle_decode_dns,
    "decode_tls": handle_decode_tls,
    "decode_goose": handle_decode_goose,
    "expert_info": handle_expert_info,
    "decode_protocol": handle_decode_protocol,
}
