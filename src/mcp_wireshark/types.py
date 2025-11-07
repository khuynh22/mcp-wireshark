"""Type definitions for MCP Wireshark."""

from typing import Any, TypedDict


class PacketInfo(TypedDict, total=False):
    """Information about a captured packet."""

    number: int
    timestamp: str
    source: str
    destination: str
    protocol: str
    length: int
    info: str
    layers: dict[str, Any]


class InterfaceInfo(TypedDict):
    """Information about a network interface."""

    name: str
    description: str
    addresses: list[str]


class ProtocolStats(TypedDict):
    """Statistics for a protocol."""

    protocol: str
    count: int
    bytes: int
    percentage: float


class TCPStream(TypedDict):
    """TCP stream data."""

    stream_id: int
    packets: list[PacketInfo]
    client_to_server: str
    server_to_client: str
