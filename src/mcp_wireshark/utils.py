"""Utility functions for Wireshark integration."""

import asyncio
import platform
import shutil
import subprocess
from typing import Any

from .types import PacketInfo


class WiresharkNotFoundError(Exception):
    """Raised when tshark or dumpcap is not found."""


def check_wireshark_installed() -> dict[str, str | None]:
    """
    Check if Wireshark tools are installed.

    Returns:
        Dictionary with paths to tshark and dumpcap (None if not found)
    """
    return {
        "tshark": shutil.which("tshark"),
        "dumpcap": shutil.which("dumpcap"),
    }


async def run_tshark(args: list[str], timeout: int = 30, input_data: str | None = None) -> str:
    """
    Run tshark command asynchronously.

    Args:
        args: Command arguments
        timeout: Timeout in seconds
        input_data: Optional stdin data

    Returns:
        Command output

    Raises:
        WiresharkNotFoundError: If tshark is not found
        subprocess.TimeoutExpired: If command times out
    """
    tshark_path = shutil.which("tshark")
    if not tshark_path:
        raise WiresharkNotFoundError("tshark not found. Please install Wireshark/tshark.")

    cmd = [tshark_path] + args

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        stdin=asyncio.subprocess.PIPE if input_data else None,
    )

    try:
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(input=input_data.encode() if input_data else None),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        raise subprocess.TimeoutExpired(cmd, timeout)

    if proc.returncode != 0:
        error_msg = stderr.decode() if stderr else "Unknown error"
        raise RuntimeError(f"tshark failed: {error_msg}")

    return stdout.decode()


async def run_dumpcap(args: list[str], timeout: int = 30) -> str:
    """
    Run dumpcap command asynchronously.

    Args:
        args: Command arguments
        timeout: Timeout in seconds

    Returns:
        Command output

    Raises:
        WiresharkNotFoundError: If dumpcap is not found
    """
    dumpcap_path = shutil.which("dumpcap")
    if not dumpcap_path:
        # Fallback to tshark if dumpcap not available
        return await run_tshark(args, timeout)

    cmd = [dumpcap_path] + args

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        raise subprocess.TimeoutExpired(cmd, timeout)

    if proc.returncode != 0:
        error_msg = stderr.decode() if stderr else "Unknown error"
        raise RuntimeError(f"dumpcap failed: {error_msg}")

    return stdout.decode()


def parse_packet_json(packet_json: dict[str, Any]) -> PacketInfo:
    """
    Parse packet JSON from tshark into PacketInfo.

    Args:
        packet_json: Raw packet JSON from tshark

    Returns:
        Parsed packet information
    """
    layers = packet_json.get("_source", {}).get("layers", {})
    frame = layers.get("frame", {})

    # Extract basic info
    info: PacketInfo = {
        "number": int(frame.get("frame.number", 0)),
        "timestamp": frame.get("frame.time", ""),
        "length": int(frame.get("frame.len", 0)),
        "protocol": "",
        "source": "",
        "destination": "",
        "info": "",
        "layers": layers,
    }

    # Try to extract protocol info
    if "ip" in layers:
        ip_layer = layers["ip"]
        info["source"] = ip_layer.get("ip.src", "")
        info["destination"] = ip_layer.get("ip.dst", "")
    elif "ipv6" in layers:
        ipv6_layer = layers["ipv6"]
        info["source"] = ipv6_layer.get("ipv6.src", "")
        info["destination"] = ipv6_layer.get("ipv6.dst", "")

    # Get highest layer protocol
    if "tcp" in layers:
        info["protocol"] = "TCP"
    elif "udp" in layers:
        info["protocol"] = "UDP"
    elif "icmp" in layers:
        info["protocol"] = "ICMP"
    elif "arp" in layers:
        info["protocol"] = "ARP"
    else:
        # Use frame protocols field
        protocols = frame.get("frame.protocols", "")
        if protocols:
            info["protocol"] = protocols.split(":")[-1].upper()

    return info


def get_os_specific_interface_cmd() -> list[str]:
    """Get OS-specific command for listing interfaces."""
    system = platform.system()
    if system == "Windows":
        return ["-D"]
    return ["-D"]
