"""Tests for MCP server."""

import pytest
from mcp.types import TextContent

from mcp_wireshark.server import (
    handle_list_interfaces,
    handle_read_pcap,
)


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
