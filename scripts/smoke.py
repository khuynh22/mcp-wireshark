"""Functional smoke test — exercises every read tool against demo/demo.pcapng.

This script is intentionally outside the pytest suite because it needs a real
tshark on PATH and a real pcap, neither of which CI provides. It exists to
catch the things unit tests can't: invalid tshark field names, output-parsing
bugs, real expert-info content, and end-to-end shape of every tool.

Run from the repo root after ``pip install -e .``:

    python scripts/smoke.py

Or without an editable install, point PYTHONPATH at the source tree:

    # PowerShell
    $env:PYTHONPATH = "src"; python scripts/smoke.py
    # bash
    PYTHONPATH=src python scripts/smoke.py

Output is meant to be eyeballed — the script does not assert pass/fail. Look
for ``Error`` lines and surprising counts.
"""

import asyncio
import sys
from pathlib import Path

PCAP = str(Path(__file__).resolve().parent.parent / "demo" / "demo.pcapng")


def banner(title: str) -> None:
    print(f"\n{'=' * 6} {title} {'=' * 6}")


async def main() -> None:
    from mcp_wireshark.read_tools import (
        handle_decode_protocol,
        handle_display_filter,
        handle_expert_info,
        handle_protocol_stats,
        handle_summarize_pcap,
    )

    def show(result, limit: int = 1800) -> None:
        text = result[0].text
        print(text if len(text) <= limit else text[:limit] + f"\n... [+{len(text)-limit} chars]")

    banner("summarize_pcap (to discover what's in the pcap)")
    show(await handle_summarize_pcap({"file_path": PCAP}))

    banner("expert_info (warn)")
    show(await handle_expert_info({"file_path": PCAP, "severity": "warn"}))

    for proto in ("http", "dns", "tls", "goose", "mms", "sv", "icmp"):
        banner(f"decode_protocol {proto}")
        show(
            await handle_decode_protocol(
                {"file_path": PCAP, "protocol": proto, "packet_count": 3}
            )
        )

    banner("decode_protocol with comparison filter (validator relaxation test)")
    show(
        await handle_decode_protocol(
            {
                "file_path": PCAP,
                "protocol": "dns",
                "filter": "frame.number > 1",
                "packet_count": 3,
            }
        )
    )

    banner("protocol_stats io,phs")
    show(await handle_protocol_stats({"file_path": PCAP, "protocol": "io", "variant": "phs"}))

    banner("protocol_stats conv,ip")
    show(
        await handle_protocol_stats(
            {"file_path": PCAP, "protocol": "conv", "variant": "ip", "max_lines": 25}
        )
    )

    banner("display_filter with && (regression: previously rejected)")
    show(
        await handle_display_filter(
            {
                "file_path": PCAP,
                "filter": "tcp.flags.syn == 1 && tcp.flags.ack == 0",
                "packet_count": 3,
            }
        )
    )

    banner("display_filter rejects real shell injection")
    show(
        await handle_display_filter(
            {"file_path": PCAP, "filter": "tcp; rm -rf /", "packet_count": 1}
        )
    )


if __name__ == "__main__":
    sys.exit(asyncio.run(main()) or 0)
