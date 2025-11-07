"""Tests for utility functions."""

from mcp_wireshark.utils import check_wireshark_installed, parse_packet_json


def test_check_wireshark_installed() -> None:
    """Test checking for Wireshark installation."""
    result = check_wireshark_installed()
    assert "tshark" in result
    assert "dumpcap" in result
    assert isinstance(result["tshark"], (str, type(None)))
    assert isinstance(result["dumpcap"], (str, type(None)))


def test_parse_packet_json_basic() -> None:
    """Test parsing basic packet JSON."""
    packet_json = {
        "_source": {
            "layers": {
                "frame": {
                    "frame.number": "1",
                    "frame.time": "2024-01-01 00:00:00",
                    "frame.len": "100",
                },
                "ip": {
                    "ip.src": "192.168.1.1",
                    "ip.dst": "192.168.1.2",
                },
                "tcp": {},
            }
        }
    }

    result = parse_packet_json(packet_json)

    assert result["number"] == 1
    assert result["timestamp"] == "2024-01-01 00:00:00"
    assert result["length"] == 100
    assert result["source"] == "192.168.1.1"
    assert result["destination"] == "192.168.1.2"
    assert result["protocol"] == "TCP"


def test_parse_packet_json_udp() -> None:
    """Test parsing UDP packet JSON."""
    packet_json = {
        "_source": {
            "layers": {
                "frame": {
                    "frame.number": "2",
                    "frame.time": "2024-01-01 00:00:01",
                    "frame.len": "200",
                },
                "ip": {
                    "ip.src": "10.0.0.1",
                    "ip.dst": "10.0.0.2",
                },
                "udp": {},
            }
        }
    }

    result = parse_packet_json(packet_json)

    assert result["protocol"] == "UDP"
    assert result["source"] == "10.0.0.1"


def test_parse_packet_json_ipv6() -> None:
    """Test parsing IPv6 packet JSON."""
    packet_json = {
        "_source": {
            "layers": {
                "frame": {
                    "frame.number": "3",
                    "frame.time": "2024-01-01 00:00:02",
                    "frame.len": "150",
                },
                "ipv6": {
                    "ipv6.src": "fe80::1",
                    "ipv6.dst": "fe80::2",
                },
                "icmpv6": {},
            }
        }
    }

    result = parse_packet_json(packet_json)

    assert result["source"] == "fe80::1"
    assert result["destination"] == "fe80::2"
