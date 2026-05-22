"""Tests for the dissector tools: expert_info, decode_protocol, protocol_stats.

These tools live in ``mcp_wireshark.read_tools`` alongside the other read-only
tools. The tests are kept in a separate file so the cohesive protocol-dissector
suite is easy to find and run.
"""

from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from mcp_wireshark.read_tools import (
    PROTOCOL_DEFAULTS,
    READ_HANDLERS,
    READ_TOOLS,
    STATS_VARIANTS,
    handle_decode_protocol,
    handle_expert_info,
    handle_protocol_stats,
)

DISSECTOR_TOOL_NAMES = {"expert_info", "decode_protocol", "protocol_stats"}

FAKE_TSV_HTTP = (
    "frame.number\tip.src\tip.dst\thttp.request.method\thttp.request.uri\t"
    "http.host\thttp.response.code\thttp.response.phrase\thttp.content_type\n"
    "1\t192.168.1.1\t10.0.0.1\tGET\t/index.html\texample.com\t\t\t\n"
    "2\t10.0.0.1\t192.168.1.1\t\t\t\t200\tOK\ttext/html\n"
)

FAKE_TSV_GOOSE = (
    "frame.number\tframe.time_relative\teth.src\teth.dst\tgoose.gocbRef\t"
    "goose.datSet\tgoose.stNum\tgoose.sqNum\tgoose.timeAllowedtoLive\tgoose.ndsCom\n"
    "1\t0.000000\t01:0c:cd:01:00:01\t01:0c:cd:01:00:00\tIED1/LLN0$GO$gcb01\t"
    "IED1/LLN0$ds01\t5\t0\t1000\tFALSE\n"
)

FAKE_EXPERT = (
    "Expert Info\n"
    "Severity: Warning\n"
    "  Group: Sequence  Count: 3\n"
    "    TCP: Out-of-order segment\n"
)

FAKE_PHS = (
    "===================================================================\n"
    "Protocol Hierarchy Statistics\n"
    "Filter: \n"
    "\n"
    "  eth                                      frames:10 bytes:1024\n"
    "    ip                                     frames:10 bytes:1024\n"
    "      tcp                                  frames:8  bytes:900\n"
    "===================================================================\n"
)


# --- registration -----------------------------------------------------------


def test_dissector_tools_registered_in_read_tools() -> None:
    exposed = {t.name for t in READ_TOOLS}
    assert exposed >= DISSECTOR_TOOL_NAMES


def test_all_dissector_tools_have_handlers() -> None:
    for name in DISSECTOR_TOOL_NAMES:
        assert name in READ_HANDLERS, f"missing handler for {name}"


def test_all_dissector_tools_are_read_only() -> None:
    for tool in READ_TOOLS:
        if tool.name not in DISSECTOR_TOOL_NAMES:
            continue
        assert tool.annotations is not None
        assert tool.annotations.readOnlyHint is True


# --- expert_info ------------------------------------------------------------


@pytest.mark.asyncio
async def test_expert_info_success(tmp_path: Path) -> None:
    pcap = tmp_path / "expert.pcap"
    pcap.touch()

    with patch(
        "mcp_wireshark.read_tools.run_tshark",
        AsyncMock(return_value=FAKE_EXPERT),
    ):
        result = await handle_expert_info({"file_path": str(pcap)})

    assert "Expert Info" in result[0].text
    assert "Warning" in result[0].text


@pytest.mark.asyncio
async def test_expert_info_severity_arg_passed_through(tmp_path: Path) -> None:
    pcap = tmp_path / "expert.pcap"
    pcap.touch()

    captured: dict[str, list[str]] = {}

    async def fake_tshark(args: list[str], **_: Any) -> str:
        captured["args"] = args
        return FAKE_EXPERT

    with patch("mcp_wireshark.read_tools.run_tshark", AsyncMock(side_effect=fake_tshark)):
        await handle_expert_info({"file_path": str(pcap), "severity": "error"})

    assert "expert,error" in captured["args"]


@pytest.mark.asyncio
async def test_expert_info_invalid_severity(tmp_path: Path) -> None:
    pcap = tmp_path / "x.pcap"
    pcap.touch()

    result = await handle_expert_info({"file_path": str(pcap), "severity": "bogus"})
    assert "invalid severity" in result[0].text.lower()


@pytest.mark.asyncio
async def test_expert_info_file_not_found() -> None:
    result = await handle_expert_info({"file_path": "/nonexistent/file.pcap"})
    assert "not found" in result[0].text.lower() or "error" in result[0].text.lower()


# --- decode_protocol --------------------------------------------------------


@pytest.mark.asyncio
async def test_decode_protocol_curated_http_defaults(tmp_path: Path) -> None:
    pcap = tmp_path / "http.pcap"
    pcap.touch()

    captured: dict[str, list[str]] = {}

    async def fake_tshark(args: list[str], **_: Any) -> str:
        captured["args"] = args
        return FAKE_TSV_HTTP

    with patch("mcp_wireshark.read_tools.run_tshark", AsyncMock(side_effect=fake_tshark)):
        result = await handle_decode_protocol({"file_path": str(pcap), "protocol": "http"})

    # All curated HTTP fields should be passed as -e arguments.
    for field in PROTOCOL_DEFAULTS["http"]:
        assert field in captured["args"]
    # HTTP base filter is the request-or-response filter.
    y_idx = captured["args"].index("-Y")
    assert "http.request" in captured["args"][y_idx + 1]
    assert "2 packet(s)" in result[0].text


@pytest.mark.asyncio
async def test_decode_protocol_curated_goose_defaults(tmp_path: Path) -> None:
    pcap = tmp_path / "goose.pcap"
    pcap.touch()

    with patch(
        "mcp_wireshark.read_tools.run_tshark",
        AsyncMock(return_value=FAKE_TSV_GOOSE),
    ):
        result = await handle_decode_protocol({"file_path": str(pcap), "protocol": "goose"})

    assert "1 packet(s)" in result[0].text
    assert "IED1" in result[0].text


@pytest.mark.asyncio
async def test_decode_protocol_numeric_filter_allowed(tmp_path: Path) -> None:
    """Comparisons like 'goose.stNum > 0' must be accepted in the filter arg.

    ``validate_display_filter`` permits ``>``/``<``/``&&``/``||`` because they
    are legitimate Wireshark syntax and never reach a shell (we always invoke
    tshark via ``create_subprocess_exec`` with an explicit argv).
    """
    pcap = tmp_path / "goose.pcap"
    pcap.touch()

    captured: dict[str, list[str]] = {}

    async def fake_tshark(args: list[str], **_: Any) -> str:
        captured["args"] = args
        return FAKE_TSV_GOOSE

    with patch("mcp_wireshark.read_tools.run_tshark", AsyncMock(side_effect=fake_tshark)):
        result = await handle_decode_protocol(
            {
                "file_path": str(pcap),
                "protocol": "goose",
                "filter": "goose.stNum > 0",
            }
        )

    assert "Error" not in result[0].text or "1 packet(s)" in result[0].text
    y_idx = captured["args"].index("-Y")
    assert "goose.stNum > 0" in captured["args"][y_idx + 1]


@pytest.mark.asyncio
async def test_decode_protocol_rejects_shell_metacharacters(tmp_path: Path) -> None:
    pcap = tmp_path / "x.pcap"
    pcap.touch()

    result = await handle_decode_protocol(
        {"file_path": str(pcap), "protocol": "http", "filter": "x; rm -rf /"}
    )

    assert "error" in result[0].text.lower() or "invalid" in result[0].text.lower()


@pytest.mark.asyncio
async def test_decode_protocol_unknown_protocol_requires_fields(tmp_path: Path) -> None:
    pcap = tmp_path / "x.pcap"
    pcap.touch()

    result = await handle_decode_protocol({"file_path": str(pcap), "protocol": "ftp"})
    assert "no curated defaults" in result[0].text.lower()


@pytest.mark.asyncio
async def test_decode_protocol_custom_fields_override(tmp_path: Path) -> None:
    pcap = tmp_path / "ftp.pcap"
    pcap.touch()

    captured: dict[str, list[str]] = {}

    async def fake_tshark(args: list[str], **_: Any) -> str:
        captured["args"] = args
        return "ftp.request.command\nUSER\n"

    with patch("mcp_wireshark.read_tools.run_tshark", AsyncMock(side_effect=fake_tshark)):
        result = await handle_decode_protocol(
            {
                "file_path": str(pcap),
                "protocol": "ftp",
                "fields": ["ftp.request.command"],
            }
        )

    assert "ftp.request.command" in captured["args"]
    assert "1 packet(s)" in result[0].text


@pytest.mark.asyncio
async def test_decode_protocol_too_many_fields(tmp_path: Path) -> None:
    pcap = tmp_path / "x.pcap"
    pcap.touch()

    result = await handle_decode_protocol(
        {
            "file_path": str(pcap),
            "protocol": "tcp",
            "fields": [f"field.{i}" for i in range(21)],
        }
    )

    assert "maximum 20" in result[0].text.lower()


@pytest.mark.asyncio
async def test_decode_protocol_packet_count_limit(tmp_path: Path) -> None:
    pcap = tmp_path / "x.pcap"
    pcap.touch()

    many = "frame.number\tip.src\n" + "".join(f"{i}\t10.0.0.{i}\n" for i in range(100))

    with patch(
        "mcp_wireshark.read_tools.run_tshark",
        AsyncMock(return_value=many),
    ):
        result = await handle_decode_protocol(
            {
                "file_path": str(pcap),
                "protocol": "icmp",
                "fields": ["frame.number", "ip.src"],
                "packet_count": 5,
            }
        )

    assert "5 packet(s)" in result[0].text
    assert "showing first 5 of 100" in result[0].text


@pytest.mark.asyncio
async def test_decode_protocol_no_match(tmp_path: Path) -> None:
    pcap = tmp_path / "empty.pcap"
    pcap.touch()

    with patch("mcp_wireshark.read_tools.run_tshark", AsyncMock(return_value="")):
        result = await handle_decode_protocol({"file_path": str(pcap), "protocol": "http"})

    assert "no packets" in result[0].text.lower()


# --- protocol_stats ---------------------------------------------------------


@pytest.mark.asyncio
async def test_protocol_stats_phs(tmp_path: Path) -> None:
    pcap = tmp_path / "x.pcap"
    pcap.touch()

    captured: dict[str, list[str]] = {}

    async def fake_tshark(args: list[str], **_: Any) -> str:
        captured["args"] = args
        return FAKE_PHS

    with patch("mcp_wireshark.read_tools.run_tshark", AsyncMock(side_effect=fake_tshark)):
        result = await handle_protocol_stats(
            {"file_path": str(pcap), "protocol": "io", "variant": "phs"}
        )

    assert "io,phs" in captured["args"]
    assert "Protocol Hierarchy Statistics" in result[0].text


@pytest.mark.asyncio
async def test_protocol_stats_unsupported_pair(tmp_path: Path) -> None:
    pcap = tmp_path / "x.pcap"
    pcap.touch()

    result = await handle_protocol_stats(
        {"file_path": str(pcap), "protocol": "bogus", "variant": "thing"}
    )
    assert "unsupported" in result[0].text.lower()


@pytest.mark.asyncio
async def test_protocol_stats_truncates_long_output(tmp_path: Path) -> None:
    pcap = tmp_path / "x.pcap"
    pcap.touch()

    big = "\n".join(f"line {i}" for i in range(500))

    with patch("mcp_wireshark.read_tools.run_tshark", AsyncMock(return_value=big)):
        result = await handle_protocol_stats(
            {
                "file_path": str(pcap),
                "protocol": "conv",
                "variant": "ip",
                "max_lines": 50,
            }
        )

    assert "more line(s) truncated" in result[0].text


@pytest.mark.asyncio
async def test_protocol_stats_empty_output(tmp_path: Path) -> None:
    pcap = tmp_path / "x.pcap"
    pcap.touch()

    with patch("mcp_wireshark.read_tools.run_tshark", AsyncMock(return_value="")):
        result = await handle_protocol_stats(
            {"file_path": str(pcap), "protocol": "io", "variant": "phs"}
        )

    assert "no statistics" in result[0].text.lower()


def test_stats_variants_table_is_well_formed() -> None:
    """Every entry must map to a non-empty -z argument string."""
    for (proto, variant), z_arg in STATS_VARIANTS.items():
        assert proto
        assert variant
        assert z_arg
        assert "," in z_arg
