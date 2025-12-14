"""MCP Wireshark server package.

A Model Context Protocol (MCP) server for Wireshark/tshark integration.
Provides AI tools and IDEs with network packet capture and analysis capabilities.
"""

__version__ = "0.1.1"
__author__ = "Khang Nguyen Huynh"
__license__ = "MIT"

from .server import app
from .types import InterfaceInfo, PacketInfo, ProtocolStats, TCPStream
from .utils import WiresharkNotFoundError, check_wireshark_installed

__all__ = [
    "InterfaceInfo",
    "PacketInfo",
    "ProtocolStats",
    "TCPStream",
    "WiresharkNotFoundError",
    "__version__",
    "app",
    "check_wireshark_installed",
]
