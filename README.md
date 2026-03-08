# mcp-wireshark
<!-- mcp-name: io.github.khuynh22/mcp-wireshark -->

> Community-maintained. Not affiliated with Wireshark or Anthropic.

An MCP server that exposes Wireshark/tshark capabilities to AI tools and IDEs. Capture live traffic, analyze `.pcap` files, apply display filters, follow TCP/UDP streams, and export to JSON — all via Claude Desktop, VS Code Copilot, or any MCP-compatible client.

[![PyPI version](https://badge.fury.io/py/mcp-wireshark.svg)](https://badge.fury.io/py/mcp-wireshark)
[![CI](https://github.com/khuynh22/mcp-wireshark/actions/workflows/ci.yml/badge.svg)](https://github.com/khuynh22/mcp-wireshark/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

## Prerequisites

- Python 3.10+
- [Wireshark/tshark](https://www.wireshark.org/download.html) installed and on `PATH`

**Linux:** add your user to the `wireshark` group for non-root capture:
```bash
sudo usermod -aG wireshark $USER
```

## Installation

```bash
pip install mcp-wireshark
```

Or with `uv`:
```bash
uvx mcp-wireshark
```

## Configuration

### Claude Desktop

`~/Library/Application Support/Claude/claude_desktop_config.json` (macOS)
`%APPDATA%\Claude\claude_desktop_config.json` (Windows)

```json
{
  "mcpServers": {
    "wireshark": {
      "command": "mcp-wireshark"
    }
  }
}
```

### VS Code

`.vscode/mcp.json` in your workspace:

```json
{
  "servers": {
    "wireshark": {
      "command": "mcp-wireshark"
    }
  }
}
```

On Windows, if tshark isn't on `PATH`, add it explicitly:
```json
{
  "servers": {
    "wireshark": {
      "command": "mcp-wireshark",
      "env": { "PATH": "C:\\Program Files\\Wireshark;${env:PATH}" }
    }
  }
}
```

## Tools

| Tool | Description |
|------|-------------|
| `check_installation` | Verify tshark is installed and show version |
| `list_interfaces` | List available network interfaces |
| `live_capture` | Capture live traffic from an interface |
| `read_pcap` | Read packets from a `.pcap`/`.pcapng` file |
| `display_filter` | Apply a Wireshark display filter to a pcap file |
| `summarize_pcap` | High-level summary: packet count, duration, top protocols, top talkers |
| `stats_by_proto` | Protocol hierarchy statistics |
| `follow_tcp` | Extract payload from a TCP stream |
| `follow_udp` | Extract payload from a UDP stream |
| `export_json` | Export packets to a JSON file |

### Quick examples

```
List my network interfaces
Capture 30 seconds of traffic on eth0 filtered to tcp.port == 443
Read the first 100 packets from /tmp/capture.pcap
Summarize /tmp/capture.pcap
Follow TCP stream 0 from /tmp/capture.pcap
Export HTTP packets from /tmp/capture.pcap to /tmp/http.json
```

### Useful display filters

```
tcp.port == 80          HTTP
tcp.port == 443         HTTPS
dns                     All DNS
http.request            HTTP requests only
ip.addr == 10.0.0.1    Traffic to/from specific IP
tcp.flags.syn == 1      TCP SYN packets
```

## Development

```bash
git clone https://github.com/khuynh22/mcp-wireshark.git
cd mcp-wireshark
python -m venv venv && source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -e ".[dev]"

pytest                   # run tests
black src tests          # format
ruff check src tests     # lint
mypy src                 # type check
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines.

## License

MIT — see [LICENSE](LICENSE).
