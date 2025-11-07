# Quick Start Guide

This guide will help you get started with mcp-wireshark quickly.

## Installation

### 1. Install Wireshark/tshark

**macOS:**
```bash
brew install wireshark
```

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install tshark
```

**Windows:**
Download and install from [Wireshark Downloads](https://www.wireshark.org/download.html)

### 2. Install mcp-wireshark

```bash
pip install mcp-wireshark
```

## Using with Claude Desktop

1. Locate your Claude Desktop configuration file:
   - **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
   - **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
   - **Linux**: `~/.config/Claude/claude_desktop_config.json`

2. Add the following configuration:

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

3. Restart Claude Desktop

4. You can now use Wireshark tools directly in Claude! Try asking:
   - "List all network interfaces available for packet capture"
   - "Read the first 10 packets from my capture.pcap file"
   - "Show me protocol statistics from network_traffic.pcap"

## Using with VS Code

1. Install the MCP extension for VS Code

2. Add to your VS Code settings.json:

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

3. Use the MCP tools through your AI assistant in VS Code

## Basic CLI Usage

### List Network Interfaces

Create a simple Python script:

```python
import asyncio
from mcp_wireshark.server import handle_list_interfaces

async def main():
    interfaces = await handle_list_interfaces()
    for content in interfaces:
        print(content.text)

asyncio.run(main())
```

### Read a PCAP File

```python
import asyncio
from mcp_wireshark.server import handle_read_pcap

async def main():
    result = await handle_read_pcap({
        "file_path": "capture.pcap",
        "packet_count": 10
    })
    for content in result:
        print(content.text)

asyncio.run(main())
```

### Apply a Display Filter

```python
import asyncio
from mcp_wireshark.server import handle_display_filter

async def main():
    result = await handle_display_filter({
        "file_path": "capture.pcap",
        "filter": "http",
        "packet_count": 20
    })
    for content in result:
        print(content.text)

asyncio.run(main())
```

## Common Display Filters

Here are some useful Wireshark display filters to get started:

- `tcp.port == 80` - HTTP traffic
- `tcp.port == 443` - HTTPS traffic
- `http` - All HTTP packets
- `dns` - DNS queries and responses
- `ip.addr == 192.168.1.1` - Traffic to/from specific IP
- `tcp.flags.syn == 1` - TCP SYN packets
- `icmp` - ICMP packets (ping)

## Creating Sample Capture Files

If you don't have a pcap file to test with, you can create one:

### Using tshark
```bash
tshark -i eth0 -w sample.pcap -c 100
```

### Using tcpdump (Linux/macOS)
```bash
sudo tcpdump -i eth0 -w sample.pcap -c 100
```

### Using Wireshark GUI
1. Open Wireshark
2. Select your network interface
3. Start capture
4. Stop after capturing some packets
5. Save as .pcap or .pcapng file

## Troubleshooting

### Permission Issues

If you get permission errors when capturing:

**Linux:**
```bash
sudo usermod -aG wireshark $USER
sudo chmod +x /usr/bin/dumpcap
# Log out and back in for group changes to take effect
```

**macOS:**
- Install with Homebrew which handles permissions
- Or grant permissions in System Preferences → Security & Privacy

**Windows:**
- Run as Administrator
- Or configure WinPcap/Npcap permissions during installation

### tshark not found

Make sure Wireshark/tshark is in your PATH:

```bash
which tshark  # Linux/macOS
where tshark  # Windows
```

If not found, add the Wireshark installation directory to your PATH.

## Next Steps

- Check out the [examples](../examples/) directory for more usage patterns
- Read the [API documentation](API.md) for detailed tool descriptions
- See the [README](../README.md) for comprehensive documentation

## Getting Help

If you encounter issues:

1. Check the [troubleshooting section](#troubleshooting) above
2. Review existing [GitHub issues](https://github.com/khuynh22/mcp-wireshark/issues)
3. Create a new issue with:
   - Your OS and Python version
   - Error messages
   - Steps to reproduce

## Tips

- Start with small pcap files (< 1000 packets) for testing
- Use display filters to narrow down results
- TCP stream analysis works best with complete captures
- Export to JSON for further processing with other tools
