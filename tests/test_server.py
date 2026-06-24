"""Tests for MCP server."""

import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from mcp.types import TextContent

from mcp_wireshark.read_tools import (
    READ_HANDLERS,
    handle_analyze_iec61850,
    handle_display_filter,
    handle_list_interfaces,
    handle_read_pcap,
)
from mcp_wireshark.validation import (
    MAX_DURATION_SECONDS,
    MAX_PACKET_COUNT,
    validate_display_filter,
    validate_file_path,
)
from mcp_wireshark.write_tools import handle_export_json


class TestValidation:
    def test_validate_file_path_valid_pcap(self, tmp_path: Path) -> None:
        """Test validation of valid pcap file path."""
        pcap_file = tmp_path / "test.pcap"
        pcap_file.touch()
        result = validate_file_path(str(pcap_file))
        assert result.suffix == ".pcap"

    def test_validate_file_path_valid_pcapng(self, tmp_path: Path) -> None:
        """Test validation of valid pcapng file path."""
        pcap_file = tmp_path / "test.pcapng"
        pcap_file.touch()
        result = validate_file_path(str(pcap_file))
        assert result.suffix == ".pcapng"

    def test_validate_file_path_invalid_extension(self, tmp_path: Path) -> None:
        """Test rejection of invalid file extension."""
        txt_file = tmp_path / "test.txt"
        txt_file.touch()
        with pytest.raises(ValueError, match="Invalid file extension"):
            validate_file_path(str(txt_file))

    def test_validate_file_path_traversal_attempt(self) -> None:
        """Test rejection of path traversal attempts."""
        with pytest.raises(ValueError, match="Path traversal"):
            validate_file_path("../../../etc/passwd.pcap")

    def test_validate_display_filter_valid(self) -> None:
        """Test validation of valid display filters."""
        valid_filters = [
            "tcp.port == 80",
            "http",
            "ip.addr == 192.168.1.1",
            "tcp.flags.syn == 1",
            'http.request.method == "GET"',
            # Comparison operators and the && / || boolean tokens are
            # legitimate Wireshark syntax and must be accepted.
            "goose.stNum > 0",
            "tcp.window_size < 1024",
            "tcp.flags.syn == 1 && tcp.flags.ack == 0",
            "http.request || http.response",
        ]
        for filter_expr in valid_filters:
            result = validate_display_filter(filter_expr)
            assert result == filter_expr

    def test_validate_display_filter_injection_attempts(self) -> None:
        """Test rejection of shell-injection attempts in display filters.

        tshark is always invoked via ``create_subprocess_exec`` with an
        explicit argv, so most characters that would matter in a shell are
        irrelevant here. We still reject the ones that could break out of an
        argv element if the value ever did reach a shell.
        """
        dangerous_filters = [
            "tcp; rm -rf /",
            "http`whoami`",
            "tcp$(id)",
            "x${HOME}y",
            "tcp\nrm -rf /",
        ]
        for filter_expr in dangerous_filters:
            with pytest.raises(ValueError, match="Invalid character"):
                validate_display_filter(filter_expr)

    def test_validate_display_filter_too_long(self) -> None:
        """Test rejection of overly long display filters."""
        long_filter = "a" * 1001
        with pytest.raises(ValueError, match="too long"):
            validate_display_filter(long_filter)

    def test_validate_display_filter_empty(self) -> None:
        """Test handling of empty display filter."""
        result = validate_display_filter("")
        assert result == ""


class TestSecurityConstants:
    """Tests for security constants."""

    def test_max_packet_count_reasonable(self) -> None:
        """Test that max packet count is set to a reasonable value."""
        assert MAX_PACKET_COUNT == 10000
        assert MAX_PACKET_COUNT > 0

    def test_max_duration_reasonable(self) -> None:
        """Test that max duration is set to a reasonable value."""
        assert MAX_DURATION_SECONDS == 300  # 5 minutes
        assert MAX_DURATION_SECONDS > 0


@pytest.mark.asyncio
async def test_list_interfaces() -> None:
    """Test listing network interfaces."""
    result = await handle_list_interfaces()

    assert isinstance(result, list)
    assert len(result) > 0
    assert isinstance(result[0], TextContent)
    assert result[0].type == "text"


@pytest.mark.asyncio
async def test_read_pcap_nonexistent() -> None:
    """Test reading from a nonexistent pcap file."""
    result = await handle_read_pcap({"file_path": "/nonexistent/file.pcap", "packet_count": 10})

    assert isinstance(result, list)
    assert len(result) > 0
    assert isinstance(result[0], TextContent)
    assert "not found" in result[0].text.lower() or "error" in result[0].text.lower()


@pytest.mark.asyncio
async def test_read_pcap_invalid_args() -> None:
    """Test read_pcap with invalid arguments."""
    result = await handle_read_pcap({"file_path": ""})

    assert isinstance(result, list)
    assert len(result) > 0


# Regression tests for the filter+count interaction bug fixed in 0.3.1.
# tshark's -c counts raw frames before -Y is applied, so combining the two
# silently dropped matches outside the first N frames. The fix: omit -c when
# a filter is set, slice the JSON output in Python.


def _fake_packets(n: int) -> str:
    """JSON shape tshark produces."""
    return json.dumps(
        [
            {"_index": "p", "_source": {"layers": {"frame": {"frame.number": str(i)}}}}
            for i in range(1, n + 1)
        ]
    )


@pytest.mark.asyncio
async def test_read_pcap_omits_dash_c_when_filter_set(tmp_path: Path) -> None:
    """When a filter is set, tshark's -c flag must not be passed."""
    pcap = tmp_path / "t.pcap"
    pcap.touch()

    captured: dict[str, list[str]] = {}

    async def fake_run_tshark(
        args: list[str], timeout: int = 30, input_data: str | None = None  # noqa: ARG001
    ) -> str:
        captured["args"] = args
        return _fake_packets(3)

    with patch("mcp_wireshark.read_tools.run_tshark", AsyncMock(side_effect=fake_run_tshark)):
        await handle_read_pcap(
            {"file_path": str(pcap), "packet_count": 10, "display_filter": "dns"}
        )

    assert "-Y" in captured["args"], "filter should be passed via -Y"
    assert "-c" not in captured["args"], "regression: -c must not appear with -Y"


@pytest.mark.asyncio
async def test_read_pcap_keeps_dash_c_without_filter(tmp_path: Path) -> None:
    """When no filter is set, -c is the right way to bound output."""
    pcap = tmp_path / "t.pcap"
    pcap.touch()

    captured: dict[str, list[str]] = {}

    async def fake_run_tshark(
        args: list[str], timeout: int = 30, input_data: str | None = None  # noqa: ARG001
    ) -> str:
        captured["args"] = args
        return _fake_packets(5)

    with patch("mcp_wireshark.read_tools.run_tshark", AsyncMock(side_effect=fake_run_tshark)):
        await handle_read_pcap({"file_path": str(pcap), "packet_count": 7})

    assert "-c" in captured["args"]
    assert captured["args"][captured["args"].index("-c") + 1] == "7"


@pytest.mark.asyncio
async def test_display_filter_slices_in_python(tmp_path: Path) -> None:
    """display_filter must omit -c and cap results in Python."""
    pcap = tmp_path / "t.pcap"
    pcap.touch()

    captured: dict[str, list[str]] = {}

    async def fake_run_tshark(
        args: list[str], timeout: int = 30, input_data: str | None = None  # noqa: ARG001
    ) -> str:
        captured["args"] = args
        return _fake_packets(50)  # tshark returns more than user asked for

    with patch("mcp_wireshark.read_tools.run_tshark", AsyncMock(side_effect=fake_run_tshark)):
        result = await handle_display_filter(
            {"file_path": str(pcap), "filter": "dns", "packet_count": 5}
        )

    assert "-c" not in captured["args"], "regression: -c must not appear with filter"
    assert "Found 5 packet(s)" in result[0].text


@pytest.mark.asyncio
async def test_export_json_writes_capped_count(tmp_path: Path) -> None:
    """export_json with a filter must cap the file at packet_count entries."""
    pcap = tmp_path / "t.pcap"
    pcap.touch()
    out = tmp_path / "out.json"

    async def fake_run_tshark(
        args: list[str], timeout: int = 30, input_data: str | None = None  # noqa: ARG001
    ) -> str:
        assert "-c" not in args, "regression: -c must not appear with filter"
        return _fake_packets(20)

    with patch("mcp_wireshark.write_tools.run_tshark", AsyncMock(side_effect=fake_run_tshark)):
        result = await handle_export_json(
            {
                "file_path": str(pcap),
                "output_path": str(out),
                "packet_count": 5,
                "display_filter": "dns",
            }
        )

    assert "Exported 5 packet(s)" in result[0].text
    written = json.loads(out.read_text())
    assert len(written) == 5


# --------------------------------------------------------------------------- #
# analyze_iec61850 — handler wiring, validation, and tshark arg construction
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_analyze_iec61850_registered() -> None:
    assert READ_HANDLERS.get("analyze_iec61850") is handle_analyze_iec61850


@pytest.mark.asyncio
async def test_analyze_iec61850_rejects_bad_protocol(tmp_path: Path) -> None:
    pcap = tmp_path / "t.pcap"
    pcap.touch()
    result = await handle_analyze_iec61850({"file_path": str(pcap), "protocol": "ftp"})
    text = result[0].text
    assert "goose" in text
    assert "must be" in text or "one of" in text


@pytest.mark.asyncio
async def test_analyze_iec61850_file_not_found() -> None:
    result = await handle_analyze_iec61850({"file_path": "/nope/x.pcap", "protocol": "goose"})
    assert "not found" in result[0].text.lower() or "error" in result[0].text.lower()


@pytest.mark.asyncio
async def test_analyze_iec61850_builds_field_args_and_formats(tmp_path: Path) -> None:
    pcap = tmp_path / "t.pcap"
    pcap.touch()
    captured: dict[str, list[str]] = {}

    tsv = (
        "frame.number\tframe.time_epoch\teth.dst\tgoose.gocbRef\tgoose.stNum\t"
        "goose.sqNum\tgoose.timeAllowedtoLive\tgoose.ndsCom\tgoose.simulation\n"
        "1\t0.0\t01:0c:cd:01:00:01\tIED1/LLN0$GO$g\t1\t47\t2000\t0\t0\n"
        "2\t0.5\t01:0c:cd:01:00:01\tIED1/LLN0$GO$g\t1\t51\t2000\t0\t0\n"
    )

    async def fake_run_tshark(
        args: list[str], timeout: int = 30, input_data: str | None = None  # noqa: ARG001
    ) -> str:
        captured["args"] = args
        return tsv

    with patch("mcp_wireshark.read_tools.run_tshark", AsyncMock(side_effect=fake_run_tshark)):
        result = await handle_analyze_iec61850(
            {"file_path": str(pcap), "protocol": "goose", "filter": "goose.stNum > 0"}
        )

    args = captured["args"]
    assert "-T" in args
    assert args[args.index("-T") + 1] == "fields"
    assert "-e" in args
    assert "goose.stNum" in args  # field columns passed
    yi = args.index("-Y")
    assert args[yi + 1] == "(goose) and (goose.stNum > 0)"
    assert "[FAIL]" in result[0].text
    assert "sqNum gap" in result[0].text


@pytest.mark.asyncio
async def test_analyze_iec61850_no_packets(tmp_path: Path) -> None:
    pcap = tmp_path / "t.pcap"
    pcap.touch()

    async def fake_run_tshark(
        args: list[str], timeout: int = 30, input_data: str | None = None  # noqa: ARG001
    ) -> str:
        return ""  # tshark found nothing

    with patch("mcp_wireshark.read_tools.run_tshark", AsyncMock(side_effect=fake_run_tshark)):
        result = await handle_analyze_iec61850({"file_path": str(pcap), "protocol": "sv"})
    assert "No SV packets" in result[0].text or "no sv packets" in result[0].text.lower()
