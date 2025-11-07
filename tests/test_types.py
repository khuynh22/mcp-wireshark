"""Tests for type definitions."""

from mcp_wireshark.types import InterfaceInfo, PacketInfo, ProtocolStats, TCPStream


def test_packet_info_type() -> None:
    """Test PacketInfo type."""
    packet: PacketInfo = {
        "number": 1,
        "timestamp": "2024-01-01",
        "source": "192.168.1.1",
        "destination": "192.168.1.2",
        "protocol": "TCP",
        "length": 100,
        "info": "Test packet",
        "layers": {},
    }
    assert packet["number"] == 1
    assert packet["protocol"] == "TCP"


def test_interface_info_type() -> None:
    """Test InterfaceInfo type."""
    interface: InterfaceInfo = {
        "name": "eth0",
        "description": "Ethernet adapter",
        "addresses": ["192.168.1.1"],
    }
    assert interface["name"] == "eth0"


def test_protocol_stats_type() -> None:
    """Test ProtocolStats type."""
    stats: ProtocolStats = {
        "protocol": "TCP",
        "count": 100,
        "bytes": 50000,
        "percentage": 75.5,
    }
    assert stats["protocol"] == "TCP"
    assert stats["count"] == 100


def test_tcp_stream_type() -> None:
    """Test TCPStream type."""
    stream: TCPStream = {
        "stream_id": 0,
        "packets": [],
        "client_to_server": "GET / HTTP/1.1",
        "server_to_client": "HTTP/1.1 200 OK",
    }
    assert stream["stream_id"] == 0
