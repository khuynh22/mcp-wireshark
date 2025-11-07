# API Documentation

## Server Module

The `mcp_wireshark.server` module provides the main MCP server implementation.

### Functions

#### `list_tools() -> list[Tool]`

Returns a list of available MCP tools.

**Returns:**
- List of Tool objects defining available operations

#### `call_tool(name: str, arguments: Any) -> list[TextContent]`

Handle tool execution requests.

**Parameters:**
- `name`: Name of the tool to execute
- `arguments`: Dictionary of tool-specific arguments

**Returns:**
- List of TextContent objects with results

### Tool Handlers

#### `handle_list_interfaces() -> list[TextContent]`

List all available network interfaces.

**Returns:**
- List of available network interfaces with their descriptions

#### `handle_live_capture(arguments: dict[str, Any]) -> list[TextContent]`

Capture live network traffic.

**Arguments:**
- `interface` (str): Network interface name
- `duration` (int, optional): Capture duration in seconds (default: 10)
- `packet_count` (int, optional): Maximum packets to capture
- `display_filter` (str, optional): Wireshark display filter

**Returns:**
- Captured packet information

#### `handle_read_pcap(arguments: dict[str, Any]) -> list[TextContent]`

Read packets from a pcap file.

**Arguments:**
- `file_path` (str): Path to .pcap or .pcapng file
- `packet_count` (int, optional): Maximum packets to read (default: 100)
- `display_filter` (str, optional): Wireshark display filter

**Returns:**
- Packet information from file

#### `handle_display_filter(arguments: dict[str, Any]) -> list[TextContent]`

Apply display filter to pcap file.

**Arguments:**
- `file_path` (str): Path to .pcap or .pcapng file
- `filter` (str): Wireshark display filter expression
- `packet_count` (int, optional): Maximum packets to return (default: 100)

**Returns:**
- Filtered packet information

#### `handle_stats_by_proto(arguments: dict[str, Any]) -> list[TextContent]`

Generate protocol statistics.

**Arguments:**
- `file_path` (str): Path to .pcap or .pcapng file

**Returns:**
- Protocol hierarchy statistics

#### `handle_follow_tcp(arguments: dict[str, Any]) -> list[TextContent]`

Follow a TCP stream.

**Arguments:**
- `file_path` (str): Path to .pcap or .pcapng file
- `stream_id` (int, optional): TCP stream ID (default: 0)

**Returns:**
- TCP stream conversation data

#### `handle_export_json(arguments: dict[str, Any]) -> list[TextContent]`

Export packets to JSON format.

**Arguments:**
- `file_path` (str): Path to .pcap or .pcapng file
- `output_path` (str): Path for JSON output
- `packet_count` (int, optional): Maximum packets to export (default: 1000)
- `display_filter` (str, optional): Wireshark display filter

**Returns:**
- Export status message

## Utils Module

The `mcp_wireshark.utils` module provides utility functions for Wireshark integration.

### Functions

#### `check_wireshark_installed() -> dict[str, str | None]`

Check if Wireshark tools are installed.

**Returns:**
- Dictionary with paths to tshark and dumpcap (None if not found)

#### `run_tshark(args: list[str], timeout: int = 30) -> str`

Run tshark command asynchronously.

**Parameters:**
- `args`: Command arguments
- `timeout`: Timeout in seconds

**Returns:**
- Command output

**Raises:**
- `WiresharkNotFoundError`: If tshark is not found
- `subprocess.TimeoutExpired`: If command times out

#### `run_dumpcap(args: list[str], timeout: int = 30) -> str`

Run dumpcap command asynchronously.

**Parameters:**
- `args`: Command arguments
- `timeout`: Timeout in seconds

**Returns:**
- Command output

**Raises:**
- `WiresharkNotFoundError`: If dumpcap is not found

#### `parse_packet_json(packet_json: dict[str, Any]) -> PacketInfo`

Parse packet JSON from tshark into PacketInfo.

**Parameters:**
- `packet_json`: Raw packet JSON from tshark

**Returns:**
- Parsed packet information

## Types Module

The `mcp_wireshark.types` module defines type structures for packet data.

### TypedDict Classes

#### `PacketInfo`

Information about a captured packet.

**Fields:**
- `number` (int): Packet number
- `timestamp` (str): Packet timestamp
- `source` (str): Source address
- `destination` (str): Destination address
- `protocol` (str): Protocol name
- `length` (int): Packet length in bytes
- `info` (str): Packet info string
- `layers` (dict): Protocol layer details

#### `InterfaceInfo`

Information about a network interface.

**Fields:**
- `name` (str): Interface name
- `description` (str): Interface description
- `addresses` (list[str]): IP addresses

#### `ProtocolStats`

Statistics for a protocol.

**Fields:**
- `protocol` (str): Protocol name
- `count` (int): Packet count
- `bytes` (int): Total bytes
- `percentage` (float): Percentage of total traffic

#### `TCPStream`

TCP stream data.

**Fields:**
- `stream_id` (int): Stream identifier
- `packets` (list[PacketInfo]): Packets in stream
- `client_to_server` (str): Client-side data
- `server_to_client` (str): Server-side data

## Exceptions

### `WiresharkNotFoundError`

Raised when tshark or dumpcap is not found on the system.
