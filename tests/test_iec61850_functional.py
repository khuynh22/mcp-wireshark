import shutil
import struct
import subprocess
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.types import TextContent

from scripts.make_iec61850_test_pcaps import build_scenarios, sv_asdu, sv_frame, write_pcap

pytestmark = pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark is required")


@asynccontextmanager
async def _client(env: dict[str, str] | None = None) -> AsyncIterator[ClientSession]:
    server = StdioServerParameters(
        command=sys.executable, args=["-m", "mcp_wireshark.cli"], env=env
    )
    async with stdio_client(server) as (read, write), ClientSession(read, write) as session:
        await session.initialize()
        yield session


async def _analyze(client: ClientSession, capture: Path, protocol: str, **arguments: str) -> str:
    result = await client.call_tool(
        "analyze_iec61850", {"file_path": str(capture), "protocol": protocol, **arguments}
    )
    assert not result.isError
    (content,) = result.content
    assert isinstance(content, TextContent)
    return content.text


@pytest.mark.parametrize(
    ("scenario", "protocol", "expected"),
    [
        ("goose_clean", "goose", "[OK]"),
        ("goose_ttl_violation", "goose", "TTL violation @frame 3"),
        ("sv_multi_asdu", "sv", "ASDUs: 16"),
        ("sv_sync_loss", "sv", "loss of sync @frame 6"),
        ("goose_clean", "sv", "No SV packets found"),
    ],
)
async def test_capture_report(tmp_path: Path, scenario: str, protocol: str, expected: str) -> None:
    capture = tmp_path / f"{scenario}.pcap"
    write_pcap(capture, build_scenarios()[scenario])
    async with _client() as client:
        assert expected in await _analyze(client, capture, protocol)


async def test_sv_partial_rollover_with_corrupt_counter(tmp_path: Path) -> None:
    capture = tmp_path / "rollover.pcap"
    frames = [
        (10.0 + i * 0.00025, sv_frame([sv_asdu(count)])) for i, count in enumerate((50000, 3998, 0))
    ]
    write_pcap(capture, frames)

    async with _client() as client:
        report = await _analyze(client, capture, "sv")

    assert "smpCnt out of range @frame 1: 50000" in report
    assert "3998->0 (~1 dropped)" in report


def _tpkt(pdu: bytes) -> bytes:
    context = bytes.fromhex("020103") + bytes([0xA0, len(pdu)]) + pdu
    presentation = bytes([0x30, len(context)]) + context
    payload = bytes.fromhex("02f08001000100") + bytes([0x61, len(presentation)]) + presentation
    return struct.pack("!BBH", 3, 0, 4 + len(payload)) + payload


def _tcp_packet(payload: bytes, seq: int, ack: int, *, response: bool = False) -> bytes:
    ports = (102, 40000) if response else (40000, 102)
    source, target = (b"\xc0\x00\x02\x01", b"\xc0\x00\x02\x02")
    if response:
        source, target = target, source
    tcp = struct.pack("!HHIIBBHHH", *ports, seq, ack, 0x50, 0x18, 8192, 0, 0)
    ipv4 = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40 + len(payload), 0, 0, 64, 6, 0, source, target)
    ethernet = bytes.fromhex("0200000000020200000000010800")
    return ethernet + ipv4 + tcp + payload


@pytest.mark.parametrize("scenario", ["retransmit", "pipelined", "mixed_response"])
async def test_mms_counts_decoded_pdus(tmp_path: Path, scenario: str) -> None:
    request = _tpkt(bytes.fromhex("a014020100a40f800100a10aa0083006a00480026d75"))
    response = _tpkt(bytes.fromhex("a107020100a402a100"))
    pipelined = scenario != "retransmit"
    if scenario == "mixed_response":
        response = _tpkt(bytes.fromhex("a20a800100a205a003870102"))
    if pipelined:
        request += _tpkt(bytes.fromhex("a014020107a40f800100a10aa0083006a00480026d75"))
        response = _tpkt(bytes.fromhex("a107020107a402a100")) + response

    capture = tmp_path / "mms.pcap"
    # The presentation connect packet binds context 3 to the MMS abstract syntax.
    connect = bytes.fromhex(
        "030000bb02f0800db20506130100160102140200023302000134020001c19c318199a003800101a281918104"
        "00000001820400000001a423300f0201010604520100013004060251013010020103060528ca220201300406"
        "02510188020600615a3058020101a053605180020780a107060528ca220203a20606042bce0f02a303020117"
        "be35283306025101020103a02aa82880027530810203e8820203e8830105a417800101810305fb00820d03ff"
        "ffffffffffffffffffff00"
    )
    connect_packet = _tcp_packet(connect, 1000, 2000)
    request_seq = 1000 + len(connect)
    request_packet = _tcp_packet(request, request_seq, 2000)
    response_packet = _tcp_packet(response, 2000, request_seq + len(request), response=True)
    write_pcap(
        capture,
        [
            (9.0, connect_packet),
            (10.0, request_packet),
            (10.2, request_packet),
            (10.3, response_packet),
        ],
    )
    tshark = shutil.which("tshark")
    assert tshark is not None
    preferences = ("tcp.no_subdissector_on_error: FALSE", "tcp.desegment_tcp_streams: FALSE")
    dissected = subprocess.run(
        [
            tshark,
            "-o",
            preferences[0],
            "-o",
            preferences[1],
            "-r",
            str(capture),
            "-Y",
            "mms.invokeID",
            "-T",
            "fields",
            "-e",
            "frame.number",
            "-e",
            "mms.invokeID",
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert dissected.stdout.splitlines() == (
        ["2\t0,7", "3\t0,7", "4\t7,0"] if pipelined else ["2\t0", "3\t0", "4\t0"]
    )

    (tmp_path / "preferences").write_text("\n".join(preferences) + "\n", encoding="utf-8")
    async with _client({"WIRESHARK_CONFIG_DIR": str(tmp_path)}) as client:
        report = await _analyze(client, capture, "mms")

    assert "packets scanned: 3" in report
    assert "max resp ms: 300" in report
    assert "unpaired request" not in report
    if scenario == "mixed_response":
        assert "[FAIL]" in report
        assert "requests: 2 | responses: 1 | errors: 1" in report
        assert "invokeID 0 (errorClass=7)" in report
    else:
        assert "[OK]" in report
        assert (
            "requests: 2 | responses: 2" if pipelined else "requests: 1 | responses: 1"
        ) in report
