# mcp-wireshark

> Community-maintained MCP server for [Wireshark](https://www.wireshark.org/) / `tshark`. Not affiliated with Wireshark or Anthropic.

Give your AI assistant direct access to packet captures. Ask Claude to summarize a `.pcap`, follow a TCP stream, filter for a specific protocol, or capture live traffic — all without leaving the chat.

[![PyPI version](https://badge.fury.io/py/mcp-wireshark.svg)](https://badge.fury.io/py/mcp-wireshark)
[![CI](https://github.com/khuynh22/mcp-wireshark/actions/workflows/ci.yml/badge.svg)](https://github.com/khuynh22/mcp-wireshark/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

---

## Quick start with Claude Code

```bash
pip install mcp-wireshark
claude mcp add --transport stdio --scope user mcp-wireshark -- mcp-wireshark
```

That's it. Open Claude Code and try:

> "Summarize ./capture.pcap and tell me which IPs talked the most."

`--scope user` makes the server available across every Claude Code project. Drop the flag to install it for the current project only. See [`claude mcp` docs](https://code.claude.com/docs/en/mcp) for more.

### Verify the install

```bash
claude mcp list
```

You should see `mcp-wireshark` listed. Inside Claude Code, ask:

> "Run check_installation."

If `tshark` is on your `PATH`, it returns the version. If not, see [troubleshooting](#troubleshooting).

---

## Tools

The server exposes 10 tools, split cleanly between **read tools** (safe, no side effects) and **write tools** (capture traffic or write files). Both groups are annotated with the standard MCP `readOnlyHint` so any compliant client can surface the distinction.

### Read tools

Safe to call freely — they only inspect state.

| Tool | What it does |
|------|--------------|
| `check_installation` | Verify tshark is installed and show version |
| `list_interfaces` | List network interfaces available to capture from |
| `read_pcap` | Read packets from a `.pcap` / `.pcapng` file (preview + total count) |
| `display_filter` | Apply a Wireshark display filter to a pcap |
| `summarize_pcap` | High-level summary: I/O stats, protocol hierarchy, top talkers |
| `stats_by_proto` | Protocol hierarchy statistics |
| `follow_tcp` | Reassemble a TCP stream and return its payload |
| `follow_udp` | Reassemble a UDP stream and return its payload |

### Write tools

These create files or capture live traffic. Compliant clients may prompt before invoking.

| Tool | What it does |
|------|--------------|
| `live_capture` | Capture live traffic from an interface (capped at 5 minutes / 10k packets) |
| `export_json` | Export packets from a pcap to a JSON file at a path you choose |

---

## Example prompts

Drop these into Claude Code as-is:

```
List my network interfaces.
Summarize ./traffic.pcap.
From ./traffic.pcap, show me only HTTP requests.
Follow TCP stream 0 in ./traffic.pcap and tell me what protocol is in it.
Capture 30 seconds of traffic on Wi-Fi filtered to tcp.port == 443.
Export every DNS packet from ./traffic.pcap to ./dns.json.
```

### Useful display filters

| Filter | Matches |
|--------|---------|
| `tcp.port == 80` | HTTP |
| `tcp.port == 443` | HTTPS |
| `dns` | All DNS |
| `http.request` | HTTP requests only |
| `ip.addr == 10.0.0.1` | Traffic to/from a specific host |
| `tcp.flags.syn == 1 && tcp.flags.ack == 0` | TCP SYN packets only |

For substation engineers analyzing IEC 61850 traffic:

| Filter | Matches |
|--------|---------|
| `goose` | All GOOSE messages |
| `goose.stNum > 0` | GOOSE messages with state changes |
| `mms` | All MMS traffic |
| `sv` | Sampled Values |

---

## Other clients

Anything that speaks MCP works. The package installs an `mcp-wireshark` binary on `PATH`.

<details>
<summary><b>Claude Desktop</b></summary>

Edit `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "wireshark": {
      "command": "mcp-wireshark"
    }
  }
}
```
</details>

<details>
<summary><b>VS Code (Copilot / GitHub Copilot Chat)</b></summary>

Create `.vscode/mcp.json` in your workspace:

```json
{
  "servers": {
    "wireshark": {
      "command": "mcp-wireshark"
    }
  }
}
```
</details>

<details>
<summary><b>Cursor / Windsurf / others</b></summary>

Use the same stdio invocation: `command: mcp-wireshark`. No transport flags.
</details>

---

## Prerequisites

- Python **3.10+**
- [Wireshark](https://www.wireshark.org/download.html) installed; `tshark` reachable on `PATH`

Install with `pip` or `uv`:

```bash
pip install mcp-wireshark
# or
uvx mcp-wireshark
```

---

## Troubleshooting

<details>
<summary><b>tshark not found on Windows</b></summary>

Add Wireshark to your **system** `PATH`:

1. Press `Win+R` → run `sysdm.cpl` → **Advanced** → **Environment Variables**
2. Edit `Path` → add `C:\Program Files\Wireshark`
3. Restart your terminal and Claude Code, then re-run `check_installation`

(Avoid passing `PATH` through `claude mcp add --env` — values are taken literally, no `%PATH%` expansion.)
</details>

<details>
<summary><b>Permission denied capturing on Linux</b></summary>

Add yourself to the `wireshark` group, then log out and back in:

```bash
sudo usermod -aG wireshark $USER
```
</details>

<details>
<summary><b>"No packets captured" from live_capture</b></summary>

- Confirm the interface name from `list_interfaces` (Wireshark uses different names than `ifconfig`/`ip`)
- On macOS, you may need to install ChmodBPF (ships with the Wireshark `.dmg`)
- Check that no display filter is excluding everything
</details>

---

## Development

```bash
git clone https://github.com/khuynh22/mcp-wireshark.git
cd mcp-wireshark
python -m venv venv && source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -e ".[dev]"

pytest                   # tests
black src tests          # format
ruff check src tests     # lint
mypy src                 # type check
```

The codebase is organized so new tools land in one of two clearly-scoped files:

- **`src/mcp_wireshark/read_tools.py`** — anything that just inspects state
- **`src/mcp_wireshark/write_tools.py`** — anything that captures traffic or writes files

`server.py` only contains routing. See [CLAUDE.md](CLAUDE.md) and [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

Every file path is validated (`..` rejected, extension allow-listed). Every display filter is checked for shell metacharacters. tshark is always invoked via `asyncio.create_subprocess_exec`, never `shell=True`. Hard caps: 10k packets per call, 5 min per live capture. See [SECURITY.md](SECURITY.md).

## License

MIT — see [LICENSE](LICENSE).
