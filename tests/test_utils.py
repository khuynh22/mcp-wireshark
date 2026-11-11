"""Tests for utility functions."""

import subprocess
import sys
from unittest.mock import patch

import pytest

from mcp_wireshark.utils import check_wireshark_installed, parse_packet_json, stream_tshark


async def test_stream_tshark_drains_stderr_while_reading_stdout() -> None:
    script = "import sys; sys.stderr.write('a' * 300000); print('packets')"
    chunks: list[bytes] = []
    with patch("mcp_wireshark.utils.shutil.which", return_value=sys.executable):
        await stream_tshark(["-c", script], chunks.append, timeout=5)
    assert b"".join(chunks).strip() == b"packets"


async def test_stream_tshark_times_out_waiting_for_output() -> None:
    with (
        patch("mcp_wireshark.utils.shutil.which", return_value=sys.executable),
        pytest.raises(subprocess.TimeoutExpired),
    ):
        await stream_tshark(["-c", "import time; time.sleep(30)"], lambda _: None, timeout=1)


async def test_stream_tshark_stops_process_on_parser_failure() -> None:
    def reject_output(_: bytes) -> None:
        raise ValueError("parser rejected output")

    script = "import time; print('bad packet', flush=True); time.sleep(30)"
    with (
        patch("mcp_wireshark.utils.shutil.which", return_value=sys.executable),
        pytest.raises(ValueError, match="parser rejected output"),
    ):
        await stream_tshark(["-c", script], reject_output, timeout=5)


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
