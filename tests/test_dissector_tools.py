"""Tests for protocol-specific dissector tools."""

from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from mcp_wireshark.dissector_tools import (
    handle_decode_dns,
    handle_decode_goose,
    handle_decode_http,
    handle_decode_protocol,
    handle_decode_tls,
    handle_expert_info,
)


FAKE_TSV_HTTP = (
    "frame.number\tip.src\tip.dst\thttp.request.method\thttp.request.uri\t"
    "http.host\thttp.response.code\thttp.response.phrase\thttp.content_type\n"
    "1\t192.168.1.1\t10.0.0.1\tGET\t/index.html\texample.com\t\t\t\n"
    "2\t10.0.0.1\t192.168.1.1\t\t\t\t200\tOK\ttext/html\n"
)

FAKE_TSV_DNS = (
    "frame.number\tip.src\tip.dst\tdns.flags.response\tdns.qry.name\t"
    "dns.qry.type\tdns.flags.rcode\tdns.a\tdns.aaaa\tdns.cname\n"
    "1\t192.168.1.1\t8.8.8.8\t0\texample.com\t1\t\t\t\t\n"
    "2\t8.8.8.8\t192.168.1.1\t1\texample.com\t1\t0\t93.184.216.34\t\t\n"
)

FAKE_TSV_TLS = (
    "frame.number\tip.src\tip.dst\ttls.handshake.type\ttls.handshake.version\t"
    "tls.handshake.extensions_server_name\ttls.handshake.ciphersuite\tx509ce.dNSName\n"
    "1\t192.168.1.1\t10.0.0.1\t1\t0x0303\texample.com\t0x1301\t\n"
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


@pytest.mark.asyncio
async def test_decode_http_success(tmp_path: Path) -> None:
    pcap = tmp_path / "http.pcap"
    pcap.touch()

    with patch(
        "mcp_wireshark.dissector_tools.run_tshark",
        AsyncMock(return_value=FAKE_TSV_HTTP),
    ):
        result = await handle_decode_http({"file_path": str(pcap)})

    assert len(result) == 1
    assert "HTTP transactions (2 packets)" in result[0].text
    assert "GET" in result[0].text
    assert "200" in result[0].text


@pytest.mark.asyncio
async def test_decode_http_with_filter(tmp_path: Path) -> None:
    pcap = tmp_path / "http.pcap"
    pcap.touch()

    captured: dict[str, list[str]] = {}

    async def fake_tshark(args: list[str], **kwargs) -> str:
        captured["args"] = args
        return FAKE_TSV_HTTP

    with patch("mcp_wireshark.dissector_tools.run_tshark", AsyncMock(side_effect=fake_tshark)):
        await handle_decode_http(
            {"file_path": str(pcap), "display_filter": "ip.addr == 10.0.0.1"}
        )

    filter_idx = captured["args"].index("-Y")
    assert "ip.addr == 10.0.0.1" in captured["args"][filter_idx + 1]


@pytest.mark.asyncio
async def test_decode_http_no_traffic(tmp_path: Path) -> None:
    pcap = tmp_path / "empty.pcap"
    pcap.touch()

    with patch("mcp_wireshark.dissector_tools.run_tshark", AsyncMock(return_value="")):
        result = await handle_decode_http({"file_path": str(pcap)})

    assert "No HTTP traffic" in result[0].text


@pytest.mark.asyncio
async def test_decode_http_file_not_found() -> None:
    result = await handle_decode_http({"file_path": "/nonexistent/file.pcap"})
    assert "not found" in result[0].text.lower() or "error" in result[0].text.lower()


@pytest.mark.asyncio
async def test_decode_dns_success(tmp_path: Path) -> None:
    pcap = tmp_path / "dns.pcap"
    pcap.touch()

    with patch(
        "mcp_wireshark.dissector_tools.run_tshark",
        AsyncMock(return_value=FAKE_TSV_DNS),
    ):
        result = await handle_decode_dns({"file_path": str(pcap)})

    assert "DNS packets (2)" in result[0].text
    assert "example.com" in result[0].text


@pytest.mark.asyncio
async def test_decode_tls_success(tmp_path: Path) -> None:
    pcap = tmp_path / "tls.pcap"
    pcap.touch()

    with patch(
        "mcp_wireshark.dissector_tools.run_tshark",
        AsyncMock(return_value=FAKE_TSV_TLS),
    ):
        result = await handle_decode_tls({"file_path": str(pcap)})

    assert "TLS handshake records (1)" in result[0].text
    assert "example.com" in result[0].text


@pytest.mark.asyncio
async def test_decode_goose_success(tmp_path: Path) -> None:
    pcap = tmp_path / "goose.pcap"
    pcap.touch()

    with patch(
        "mcp_wireshark.dissector_tools.run_tshark",
        AsyncMock(return_value=FAKE_TSV_GOOSE),
    ):
        result = await handle_decode_goose({"file_path": str(pcap)})

    assert "GOOSE messages (1)" in result[0].text
    assert "gocbRef" in result[0].text
    assert "IED1" in result[0].text


@pytest.mark.asyncio
async def test_decode_goose_with_filter(tmp_path: Path) -> None:
    pcap = tmp_path / "goose.pcap"
    pcap.touch()

    captured: dict[str, list[str]] = {}

    async def fake_tshark(args: list[str], **kwargs) -> str:
        captured["args"] = args
        return FAKE_TSV_GOOSE

    with patch("mcp_wireshark.dissector_tools.run_tshark", AsyncMock(side_effect=fake_tshark)):
        await handle_decode_goose(
            {"file_path": str(pcap), "display_filter": "goose.ndsCom == TRUE"}
        )

    filter_idx = captured["args"].index("-Y")
    assert "goose.ndsCom == TRUE" in captured["args"][filter_idx + 1]


@pytest.mark.asyncio
async def test_expert_info_success(tmp_path: Path) -> None:
    pcap = tmp_path / "expert.pcap"
    pcap.touch()

    with patch(
        "mcp_wireshark.dissector_tools.run_tshark",
        AsyncMock(return_value=FAKE_EXPERT),
    ):
        result = await handle_expert_info({"file_path": str(pcap)})

    assert "Expert Info" in result[0].text
    assert "Warning" in result[0].text


@pytest.mark.asyncio
async def test_expert_info_severity_param(tmp_path: Path) -> None:
    pcap = tmp_path / "expert.pcap"
    pcap.touch()

    captured: dict[str, list[str]] = {}

    async def fake_tshark(args: list[str], **kwargs) -> str:
        captured["args"] = args
        return FAKE_EXPERT

    with patch("mcp_wireshark.dissector_tools.run_tshark", AsyncMock(side_effect=fake_tshark)):
        await handle_expert_info({"file_path": str(pcap), "severity": "error"})

    assert "expert,error" in captured["args"]


@pytest.mark.asyncio
async def test_decode_protocol_success(tmp_path: Path) -> None:
    pcap = tmp_path / "sip.pcap"
    pcap.touch()

    fake_output = "sip.Method\tsip.from.uri\n" "INVITE\tsip:alice@example.com\n"

    with patch(
        "mcp_wireshark.dissector_tools.run_tshark",
        AsyncMock(return_value=fake_output),
    ):
        result = await handle_decode_protocol(
            {
                "file_path": str(pcap),
                "protocol_filter": "sip",
                "fields": ["sip.Method", "sip.from.uri"],
            }
        )

    assert "1 packet(s)" in result[0].text
    assert "INVITE" in result[0].text


@pytest.mark.asyncio
async def test_decode_protocol_empty_fields(tmp_path: Path) -> None:
    pcap = tmp_path / "test.pcap"
    pcap.touch()

    result = await handle_decode_protocol(
        {"file_path": str(pcap), "protocol_filter": "sip", "fields": []}
    )

    assert "non-empty" in result[0].text.lower() or "error" in result[0].text.lower()


@pytest.mark.asyncio
async def test_decode_protocol_too_many_fields(tmp_path: Path) -> None:
    pcap = tmp_path / "test.pcap"
    pcap.touch()

    result = await handle_decode_protocol(
        {
            "file_path": str(pcap),
            "protocol_filter": "tcp",
            "fields": [f"field.{i}" for i in range(21)],
        }
    )

    assert "maximum 20" in result[0].text.lower() or "error" in result[0].text.lower()


@pytest.mark.asyncio
async def test_decode_protocol_validates_filter(tmp_path: Path) -> None:
    pcap = tmp_path / "test.pcap"
    pcap.touch()

    result = await handle_decode_protocol(
        {"file_path": str(pcap), "protocol_filter": "tcp; rm -rf /", "fields": ["tcp.port"]}
    )

    assert "error" in result[0].text.lower() or "invalid" in result[0].text.lower()


@pytest.mark.asyncio
async def test_decode_http_packet_count_limit(tmp_path: Path) -> None:
    pcap = tmp_path / "http.pcap"
    pcap.touch()

    many_lines = "frame.number\tip.src\n" + "".join(f"{i}\t10.0.0.{i}\n" for i in range(100))

    with patch(
        "mcp_wireshark.dissector_tools.run_tshark",
        AsyncMock(return_value=many_lines),
    ):
        result = await handle_decode_http({"file_path": str(pcap), "packet_count": 5})

    assert "5 packets" in result[0].text
