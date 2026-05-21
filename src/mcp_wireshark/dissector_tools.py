"""Protocol-specific dissector tools — structured extraction of application-layer fields.

These tools parse protocol-specific information from pcap files using tshark's
field extraction (``-T fields -e``) and statistics (``-z``) capabilities. They
return focused, token-efficient output rather than full JSON packet dumps.

Three tools live here, each with a distinct purpose:

* ``expert_info`` — wraps ``-z expert``. Returns warnings, errors, and notes.
* ``decode_protocol`` — generic per-packet field extractor with curated
  defaults per protocol. One tool covers HTTP, DNS, TLS, GOOSE, MMS, SV,
  SIP, ICMP, and any other protocol via custom field lists.
* ``protocol_stats`` — wraps the ``-z`` aggregate-stats family (``io,phs``,
  ``conv,*``, ``endpoints,*``, ``http,tree``, ``dns,tree``, ``smb,srt`` …)
  and parses the fixed-width tshark output into a compact summary.

Every tool in this module is annotated with ``readOnlyHint=True``.
"""

from typing import Any

from mcp.types import TextContent, Tool, ToolAnnotations

from .utils import run_tshark
from .validation import MAX_PACKET_COUNT, validate_display_filter, validate_file_path


def _read_only(title: str) -> ToolAnnotations:
    return ToolAnnotations(title=title, readOnlyHint=True, openWorldHint=False)


# Curated default field sets per protocol. The key is the protocol token used
# both as the base display filter and the keyword that selects the default
# field list. Values are tshark `-e` field names ordered for human readability.
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
        "mms.domainID",
        "mms.itemID",
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
# token — e.g. TLS only matches handshake records by default, and HTTP only
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


DISSECTOR_TOOLS: list[Tool] = [
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
]


# A relaxed validator for use INSIDE display_filter values. The strict
# ``validate_display_filter`` rejects ``>``/``<`` which makes numeric
# comparisons like ``goose.stNum > 0`` impossible. Comparisons are a
# legitimate Wireshark filter feature and are safe inside an exec'd argv —
# the dangerous characters are the shell metacharacters that could break
# out of an argv element if it ever hit a shell. We never pass to a shell,
# but we still reject the worst offenders defensively.
_FILTER_FORBIDDEN = (";", "`", "$(", "${", "\n", "\r")


def _validate_filter_relaxed(filter_expr: str) -> str:
    """Reject only true shell metacharacters; allow ``>``/``<``/``&&``/``||``.

    tshark display filters legitimately need ``and``/``or``/``&&``/``||`` and
    numeric comparisons. We always invoke tshark via ``create_subprocess_exec``
    with an explicit argv, so these characters are not shell-interpreted.
    """
    if not filter_expr:
        return filter_expr
    if len(filter_expr) > 1000:
        raise ValueError("Display filter too long (max 1000 characters)")
    for token in _FILTER_FORBIDDEN:
        if token in filter_expr:
            raise ValueError(f"Invalid character in display filter: {token!r}")
    return filter_expr


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


async def handle_expert_info(arguments: dict[str, Any]) -> list[TextContent]:
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
                # Field names look like 'goose.stNum' — they should not contain
                # filter metacharacters. Use the strict validator here.
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

        # Validate base filter (relaxed) and combine with user filter.
        base_filter = _validate_filter_relaxed(base_filter)
        if user_filter:
            user_filter = _validate_filter_relaxed(user_filter)
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


DISSECTOR_HANDLERS = {
    "expert_info": handle_expert_info,
    "decode_protocol": handle_decode_protocol,
    "protocol_stats": handle_protocol_stats,
}
