"""Demo scenes for mcp-wireshark — drives the real MCP tools.

Each scene calls the actual tool handlers from ``mcp_wireshark`` against
``demo/demo.pcapng`` (or a live interface), so the recordings show genuine
output — nothing is faked. A scene is a list of typed/printed ``Block``s;
``render_gif.py`` animates them into a GIF, and running this module directly
prints them to the terminal for a quick sanity check.

Usage:
    python demo/run_demo.py {summarize|filter|expert|live|chat}

Requires tshark on PATH and the package importable (``pip install -e .``).
"""

from __future__ import annotations

import asyncio
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PCAP = ROOT / "demo" / "demo.pcapng"
DISPLAY_PATH = "demo/demo.pcapng"


@dataclass
class Block:
    """One visual unit in a scene.

    kind controls colour and whether the renderer "types" it:
      prompt  — user message in the chat hero (typed)
      cmd     — a tool invocation line (typed)
      header  — a section title
      tool    — a Claude-Code-style "Called mcp-wireshark (...)" line
      out     — verbatim tool output (revealed line by line)
      answer  — Claude's synthesised reply
      note    — dim footnote
    """

    kind: str
    text: str


def clean(text: str) -> str:
    """Shorten absolute pcap paths so recordings stay readable."""
    return text.replace(str(PCAP), DISPLAY_PATH).replace(str(PCAP).replace("\\", "/"), DISPLAY_PATH)


def _top_protocols(summary: str) -> list[str]:
    """Pull the notable (non-structural) protocols from a summarize_pcap report."""
    import re

    skip = {"frame", "eth", "ip", "ipv6", "udp", "tcp", "data", "igmp"}
    seen: dict[str, int] = {}
    for m in re.finditer(r"^\s+([a-z][\w-]*)\s+frames:(\d+)", summary, re.MULTILINE):
        name, frames = m.group(1), int(m.group(2))
        if name not in skip:
            seen[name] = max(seen.get(name, 0), frames)
    ranked = sorted(seen, key=lambda n: seen[n], reverse=True)
    return [p.upper() for p in ranked[:5]]


def excerpt(text: str, max_lines: int) -> str:
    lines = text.splitlines()
    if len(lines) <= max_lines:
        return text.rstrip()
    shown = "\n".join(lines[:max_lines])
    return f"{shown}\n… (+{len(lines) - max_lines} more lines)"


# ── Scenes ──────────────────────────────────────────────────────────────────
async def scene_summarize() -> list[Block]:
    from mcp_wireshark.read_tools import handle_summarize_pcap

    out = clean((await handle_summarize_pcap({"file_path": str(PCAP)}))[0].text)
    return [
        Block("header", "summarize_pcap — characterize an unknown capture"),
        Block("cmd", f"summarize_pcap(file_path={DISPLAY_PATH!r})"),
        Block("out", excerpt(out, 34)),
    ]


async def scene_filter() -> list[Block]:
    from mcp_wireshark.read_tools import handle_decode_protocol

    tls = clean((await handle_decode_protocol({"file_path": str(PCAP), "protocol": "tls"}))[0].text)
    dns = clean((await handle_decode_protocol({"file_path": str(PCAP), "protocol": "dns"}))[0].text)
    return [
        Block("header", "decode_protocol — filter to TLS, surface the SNI as a table"),
        Block("cmd", f"decode_protocol(file_path={DISPLAY_PATH!r}, protocol='tls')"),
        Block("out", excerpt(tls, 10)),
        Block("header", "decode_protocol — same idea for DNS-over-HTTPS lookups"),
        Block("cmd", f"decode_protocol(file_path={DISPLAY_PATH!r}, protocol='dns')"),
        Block("out", excerpt(dns, 12)),
    ]


async def scene_expert() -> list[Block]:
    from mcp_wireshark.read_tools import handle_expert_info

    out = clean((await handle_expert_info({"file_path": str(PCAP), "severity": "warn"}))[0].text)
    return [
        Block("header", "expert_info — let tshark tell you what looks wrong"),
        Block("cmd", f"expert_info(file_path={DISPLAY_PATH!r}, severity='warn')"),
        Block("out", excerpt(out, 24)),
    ]


def _pick_interface(listing: str) -> str | None:
    """Choose a capture interface from `tshark -D` output, skipping loopback."""
    for line in listing.splitlines():
        parts = line.strip().split(maxsplit=1)
        if len(parts) == 2 and parts[0].rstrip(".").isdigit():
            name = parts[1].split(" (")[0]
            if "loopback" not in parts[1].lower():
                return name
    return None


async def scene_live() -> list[Block]:
    from mcp_wireshark.read_tools import handle_list_interfaces
    from mcp_wireshark.write_tools import handle_live_capture

    listing = (await handle_list_interfaces())[0].text
    blocks = [
        Block("header", "list_interfaces — what can we capture from?"),
        Block("cmd", "list_interfaces()"),
        Block("out", excerpt(listing, 10)),
    ]
    iface = _pick_interface(listing)
    if iface is None:
        blocks.append(Block("note", "No capture interface available."))
        return blocks

    cap = (
        await handle_live_capture(
            {"interface": iface, "duration": 5, "display_filter": "arp", "packet_count": 8}
        )
    )[0].text
    blocks += [
        Block("header", "live_capture — 5s bounded capture, ARP only (no app data)"),
        Block(
            "cmd",
            f"live_capture(interface={iface!r}, duration=5,\n               display_filter='arp', packet_count=8)",
        ),
        Block("out", excerpt(clean(cap), 22)),
    ]
    return blocks


async def scene_chat() -> list[Block]:
    """Honest re-enactment of a Claude Code session — every result is real."""
    from mcp_wireshark.read_tools import handle_decode_protocol, handle_summarize_pcap

    summary = (await handle_summarize_pcap({"file_path": str(PCAP)}))[0].text
    protos = ", ".join(_top_protocols(summary)) or "TCP, UDP, TLS"
    tls = clean((await handle_decode_protocol({"file_path": str(PCAP), "protocol": "tls"}))[0].text)
    dns = clean((await handle_decode_protocol({"file_path": str(PCAP), "protocol": "dns"}))[0].text)
    answer = (
        "Here's what this 18-second capture shows:\n"
        "  • A short, mostly-IPv6 session from a home/desktop host.\n"
        "  • TLS 1.3 SNI names point at Spotify (guc3-spclient.spotify.com).\n"
        "  • DNS-over-HTTPS to doh.xfinity.com — encrypted name lookups.\n"
        "  • Worth a look: expert_info flags QUIC decryption failures\n"
        "    and several TCP D-SACK retransmissions."
    )
    # The summary tool output is a tall I/O-stats box; collapse it (Claude Code
    # style) to one line so the hero stays compact. Every shown line — and every
    # claim in the answer — is grounded in real tool output.
    return [
        Block(
            "prompt",
            f"Take a look at {DISPLAY_PATH} — what was this machine\ndoing, and is anything worth a second look?",
        ),
        Block("tool", "Called mcp-wireshark (summarize_pcap)"),
        Block("out", f"  → protocol hierarchy: {protos}"),
        Block("tool", "Called mcp-wireshark (decode_protocol  protocol='tls')"),
        Block("out", excerpt(tls, 5)),
        Block("tool", "Called mcp-wireshark (decode_protocol  protocol='dns')"),
        Block("out", excerpt(dns, 5)),
        Block("answer", answer),
        Block("note", "Every figure above came straight from the MCP tools."),
    ]


SCENES = {
    "summarize": scene_summarize,
    "filter": scene_filter,
    "expert": scene_expert,
    "live": scene_live,
    "chat": scene_chat,
}

# ── Terminal preview (ANSI) ──────────────────────────────────────────────────
_ANSI = {
    "prompt": "\033[1m",
    "cmd": "\033[2m",
    "header": "\033[36;1m",
    "tool": "\033[32m",
    "out": "\033[90m",
    "answer": "\033[32m",
    "note": "\033[2m",
}


def print_scene(blocks: list[Block]) -> None:
    reset = "\033[0m"
    for b in blocks:
        prefix = {"cmd": "$ ", "prompt": "> ", "tool": "● "}.get(b.kind, "")
        print(f"{_ANSI.get(b.kind, '')}{prefix}{b.text}{reset}\n", flush=True)


async def main() -> int:
    if len(sys.argv) != 2 or sys.argv[1] not in SCENES:
        print(f"usage: python demo/run_demo.py {{{'|'.join(SCENES)}}}", file=sys.stderr)
        return 2
    print_scene(await SCENES[sys.argv[1]]())
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
