# MCP Wireshark

An MCP (Model Context Protocol) server that integrates Wireshark/tshark with AI tools and IDEs. Capture live network traffic, parse .pcap files, apply display filters, follow TCP streams, and export to JSON—all accessible through Claude Desktop, VS Code, or the command-line interface.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

> **� New to this project?** Start here: **[Getting Started Guide](docs/GETTING_STARTED.md)** - Complete setup, publishing, and contribution guide!

📚 **[Quick Start](docs/QUICKSTART.md)** | 📖 **[API Docs](docs/API.md)** | 🤝 **[Contributing](CONTRIBUTING.md)** | 🚀 **[Publishing](docs/PUBLISHING.md)** | 💻 **[Dev Setup](docs/DEVELOPMENT.md)**

## Features

- 🔍 **List Network Interfaces**: Discover all available network interfaces for packet capture
- 📡 **Live Capture**: Capture real-time network traffic from any interface
- 📂 **Read PCAP Files**: Analyze existing .pcap and .pcapng files
- 🔎 **Display Filters**: Apply Wireshark's powerful display filters
- 📊 **Protocol Statistics**: Generate detailed protocol statistics
- 🔗 **Follow TCP Streams**: Extract and analyze TCP stream payloads
- 💾 **Export to JSON**: Export packet data in JSON format for further analysis

## Prerequisites

- Python 3.10 or higher
- Wireshark/tshark installed on your system

### Installing Wireshark/tshark

**macOS** (using Homebrew):
```bash
brew install wireshark
```

**Ubuntu/Debian**:
```bash
sudo apt-get update
sudo apt-get install tshark
```

**Windows**:
Download and install from [Wireshark Downloads](https://www.wireshark.org/download.html)

**Note**: On Linux, you may need to add your user to the `wireshark` group to capture packets without root:
```bash
sudo usermod -aG wireshark $USER
sudo chmod +x /usr/bin/dumpcap
```

## Installation

Install from PyPI:

```bash
pip install mcp-wireshark
```

Or install from source:

```bash
git clone https://github.com/khuynh22/mcp-wireshark.git
cd mcp-wireshark
pip install -e .
```

## Usage

### As an MCP Server

#### Claude Desktop

Add to your Claude Desktop configuration file:

**macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
**Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
**Linux**: `~/.config/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "wireshark": {
      "command": "mcp-wireshark",
      "args": [],
      "env": {}
    }
  }
}
```

#### VS Code

Add to your VS Code settings.json:

```json
{
  "mcp.servers": {
    "wireshark": {
      "command": "mcp-wireshark",
      "args": [],
      "env": {}
    }
  }
}
```

### Command Line

Run the MCP server:

```bash
mcp-wireshark
```

The server will communicate using stdio (standard input/output) following the MCP protocol.

## Available Tools

### 1. list_interfaces

List all available network interfaces for packet capture.

**Example**:
```
Use the list_interfaces tool to see available network interfaces
```

### 2. live_capture

Capture live network traffic from a specified interface.

**Parameters**:
- `interface` (required): Network interface name (e.g., "eth0", "Wi-Fi")
- `duration` (optional): Capture duration in seconds (default: 10)
- `packet_count` (optional): Maximum number of packets to capture
- `display_filter` (optional): Wireshark display filter to apply

**Example**:
```
Capture packets from eth0 for 30 seconds with filter "tcp.port == 80"
```

### 3. read_pcap

Read and analyze packets from a .pcap or .pcapng file.

**Parameters**:
- `file_path` (required): Path to the .pcap or .pcapng file
- `packet_count` (optional): Maximum number of packets to read (default: 100)
- `display_filter` (optional): Wireshark display filter to apply

**Example**:
```
Read the first 50 packets from capture.pcap
```

### 4. display_filter

Apply a Wireshark display filter to a pcap file.

**Parameters**:
- `file_path` (required): Path to the .pcap or .pcapng file
- `filter` (required): Wireshark display filter expression
- `packet_count` (optional): Maximum number of packets to return (default: 100)

**Example**:
```
Filter packets from capture.pcap where tcp.port == 443
```

### 5. stats_by_proto

Generate protocol statistics from a pcap file.

**Parameters**:
- `file_path` (required): Path to the .pcap or .pcapng file

**Example**:
```
Generate protocol statistics for capture.pcap
```

### 6. follow_tcp

Follow a TCP stream and extract payload data.

**Parameters**:
- `file_path` (required): Path to the .pcap or .pcapng file
- `stream_id` (optional): TCP stream ID to follow (default: 0)

**Example**:
```
Follow TCP stream 0 from capture.pcap
```

### 7. export_json

Export packets from a pcap file to JSON format.

**Parameters**:
- `file_path` (required): Path to the .pcap or .pcapng file
- `output_path` (required): Path to save the JSON output
- `packet_count` (optional): Maximum number of packets to export (default: 1000)
- `display_filter` (optional): Wireshark display filter to apply

**Example**:
```
Export first 500 HTTP packets from capture.pcap to output.json
```

## Common Display Filters

Here are some useful Wireshark display filters:

- `tcp.port == 80` - HTTP traffic
- `tcp.port == 443` - HTTPS traffic
- `http` - All HTTP packets
- `dns` - DNS queries and responses
- `ip.addr == 192.168.1.1` - Traffic to/from specific IP
- `tcp.flags.syn == 1` - TCP SYN packets
- `http.request.method == "GET"` - HTTP GET requests
- `tcp.stream eq 0` - Packets from TCP stream 0

For more filters, see the [Wireshark Display Filter Reference](https://www.wireshark.org/docs/dfref/).

## Cross-Platform Support

mcp-wireshark is designed to work across multiple platforms:

- **macOS**: Full support with Homebrew-installed Wireshark
- **Linux**: Full support with apt/yum-installed tshark
- **Windows**: Full support with official Wireshark installer

The tool uses `dumpcap` when available (recommended for non-root captures) and falls back to `tshark` when needed.

## Development

Want to contribute? See our comprehensive guides:

- **[Development Setup Guide](docs/DEVELOPMENT.md)** - Complete environment setup for contributors
- **[Publishing Guide](docs/PUBLISHING.md)** - How to publish to PyPI
- **[Contributing Guide](CONTRIBUTING.md)** - Contribution guidelines and workflow

### Quick Start for Developers

```bash
# Clone and setup
git clone https://github.com/khuynh22/mcp-wireshark.git
cd mcp-wireshark
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -e ".[dev]"

# Run quality checks
pytest                    # Run tests
black src tests          # Format code
ruff check src tests     # Lint
mypy src                 # Type check
```

## Examples

See the [examples](examples/) directory for sample scripts and usage patterns.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Built on top of [Wireshark/tshark](https://www.wireshark.org/)
- Uses [pyshark](https://github.com/KimiNewt/pyshark) for Python integration
- Implements the [Model Context Protocol](https://modelcontextprotocol.io/)

## Support

For issues, questions, or contributions, please visit the [GitHub repository](https://github.com/khuynh22/mcp-wireshark).
