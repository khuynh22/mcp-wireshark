# Examples

This directory contains example scripts demonstrating various features of mcp-wireshark.

## Prerequisites

Before running these examples, ensure you have:

1. Installed mcp-wireshark: `pip install mcp-wireshark`
2. Wireshark/tshark installed on your system
3. A sample .pcap file for testing (or create one using live_capture)

## Available Examples

### basic_usage.py

Demonstrates basic functionality:
- Listing network interfaces
- Reading packets from a pcap file
- Generating protocol statistics

```bash
python basic_usage.py
```

### filter_export.py

Shows filtering and export capabilities:
- Applying display filters
- Exporting filtered packets to JSON

```bash
python filter_export.py
```

### live_capture_demo.py

Demonstrates live packet capture:
- Capturing packets from a network interface
- Applying filters during capture

```bash
python live_capture_demo.py
```

### tcp_stream_analysis.py

Shows TCP stream analysis:
- Following TCP streams
- Extracting conversation data

```bash
python tcp_stream_analysis.py
```

## Creating Sample Pcap Files

You can create sample pcap files using:

1. **Wireshark GUI**: Capture packets and save as .pcap
2. **tshark**: `tshark -i eth0 -w example.pcap -c 100`
3. **tcpdump**: `tcpdump -i eth0 -w example.pcap -c 100`

Or use the live_capture tool from mcp-wireshark.

## Note

These examples import directly from the source code. In a production environment, you would use the MCP protocol to communicate with the server.
