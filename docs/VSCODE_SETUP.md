# VS Code MCP Setup Guide

Complete guide to set up and test MCP Wireshark in VS Code.

## Prerequisites

1. **VS Code**: Latest version
2. **GitHub Copilot Extension**: Installed and activated
3. **MCP Support**: VS Code with MCP support (check if you have `mcp.servers` settings available)
4. **MCP Wireshark**: Installed in your virtual environment

## Step 1: Ensure MCP Wireshark is Installed

```powershell
# Activate your virtual environment
cd C:\src\mcp-wireshark
.\venv\Scripts\Activate.ps1

# Install in editable mode
pip install -e .

# Verify installation
mcp-wireshark --help
```

## Step 2: Configure VS Code MCP Settings

### Create `.vscode/mcp.json` (Recommended)

MCP server configurations should be in a separate `mcp.json` file in your workspace's `.vscode` folder.

1. Create `.vscode/mcp.json` in your workspace
2. Add the MCP server configuration:

```json
{
    "servers": {
        "wireshark": {
            "command": "C:\\src\\mcp-wireshark\\venv\\Scripts\\mcp-wireshark.exe",
            "args": [],
            "env": {
                "PATH": "C:\\Program Files\\Wireshark;${env:PATH}"
            }
        }
    }
}
```

**Important**: Use `"servers"` (not `"mcp.servers"` or `"mcpServers"`) as the root key in `mcp.json`.

### Alternative: Workspace Settings

You can also use `.vscode/settings.json`, but `mcp.json` is the preferred approach:

```json
{
    "mcp.servers": {
        "wireshark": {
            "command": "C:\\src\\mcp-wireshark\\venv\\Scripts\\mcp-wireshark.exe",
            "args": [],
            "env": {
                "PATH": "C:\\Program Files\\Wireshark;${env:PATH}"
            }
        }
    }
}
```

### Configuration Options

Adjust the `command` path based on your setup:

**Option A: Virtual Environment (Recommended)**

```json
"command": "C:\\src\\mcp-wireshark\\venv\\Scripts\\mcp-wireshark.exe"
```

**Option B: Python Module Execution**

```json
"command": "python",
"args": ["-m", "mcp_wireshark.cli"],
"cwd": "${workspaceFolder}"
```

**Option C: Global Installation**

```json
"command": "mcp-wireshark"
```

## Step 3: Restart VS Code

After adding the configuration:

1. Save the settings file
2. **Reload VS Code**: Press `Ctrl+Shift+P` → "Developer: Reload Window"

## Step 4: Test the MCP Server

### Method 1: Using Copilot Chat

1. Open Copilot Chat (`Ctrl+Shift+I` or click the chat icon)
2. Try these commands:

```
@wireshark list network interfaces
```

```
@wireshark what interfaces are available for packet capture?
```

```
@wireshark read the file C:\path\to\capture.pcap
```

### Method 2: Check MCP Status

1. Press `Ctrl+Shift+P`
2. Type "MCP" to see available MCP commands
3. Look for "MCP: Show Server Status" or similar

## Step 5: Verify Server is Running

### Check Logs

1. Open Output Panel: `Ctrl+Shift+U`
2. Select "MCP" or "MCP Wireshark" from the dropdown
3. Look for connection messages

### Manual Test

Run the server manually to see if it starts:

```powershell
# In your terminal
cd C:\src\mcp-wireshark
.\venv\Scripts\Activate.ps1
python -m mcp_wireshark.cli
```

You should see the server waiting for input (it uses stdio).

## Troubleshooting

### Issue: "mcp-wireshark not found"

**Solution**: Use the full path to the executable in `.vscode/mcp.json`:

```json
{
    "servers": {
        "wireshark": {
            "command": "C:\\src\\mcp-wireshark\\venv\\Scripts\\mcp-wireshark.exe"
        }
    }
}
```

### Issue: "tshark not found"

**Solution**: Add Wireshark to PATH in the env section of `.vscode/mcp.json`:

```json
{
    "servers": {
        "wireshark": {
            "command": "C:\\src\\mcp-wireshark\\venv\\Scripts\\mcp-wireshark.exe",
            "env": {
                "PATH": "C:\\Program Files\\Wireshark;${env:PATH}"
            }
        }
    }
}
```

### Issue: Server not appearing in Copilot

**Solutions**:

1. Verify VS Code has MCP support (update to latest version)
2. Check if GitHub Copilot extension supports MCP
3. Restart VS Code completely
4. Check Output panel for errors

### Issue: Permission errors during capture

**Solution**: Run VS Code as Administrator (right-click VS Code → "Run as administrator")

### Issue: Server crashes or doesn't respond

**Debug steps**:

1. Test the server manually in terminal
2. Check VS Code Output panel for error messages
3. Verify all dependencies are installed: `pip list | grep -E "mcp|pyshark"`
4. Try with a simpler configuration (minimal env variables)

## Advanced Configuration

### Debug Mode

Add verbose logging in `.vscode/mcp.json`:

```json
{
    "servers": {
        "wireshark": {
            "command": "python",
            "args": ["-m", "mcp_wireshark.cli", "--debug"],
            "cwd": "C:\\src\\mcp-wireshark",
            "env": {
                "PATH": "C:\\Program Files\\Wireshark;${env:PATH}",
                "PYTHONUNBUFFERED": "1"
            }
        }
    }
}
```

### Multiple Environments

You can configure different servers for different projects in `.vscode/mcp.json`:

```json
{
    "servers": {
        "wireshark-dev": {
            "command": "C:\\src\\mcp-wireshark\\venv\\Scripts\\python.exe",
            "args": ["-m", "mcp_wireshark.cli"],
            "cwd": "C:\\src\\mcp-wireshark",
            "env": {
                "PATH": "C:\\Program Files\\Wireshark;${env:PATH}"
            }
        },
        "wireshark-prod": {
            "command": "mcp-wireshark",
            "args": [],
            "env": {
                "PATH": "C:\\Program Files\\Wireshark;${env:PATH}"
            }
        }
    }
}
```

## Testing Examples

Once configured, you can ask Copilot:

### Basic Commands

-   "List available network interfaces"
-   "Show me the network interfaces I can capture from"

### Reading PCAP Files

-   "Read packets from C:\captures\test.pcap"
-   "Analyze the first 50 packets in C:\captures\network.pcap"
-   "Show HTTP traffic from C:\captures\web.pcap"

### Filtering

-   "Filter TCP port 443 packets from C:\captures\test.pcap"
-   "Show only DNS packets from C:\captures\network.pcap"

### Live Capture (Requires Admin)

-   "Capture packets from Ethernet for 10 seconds"
-   "Capture HTTP traffic from Wi-Fi interface"

### Analysis

-   "Generate protocol statistics for C:\captures\test.pcap"
-   "Follow TCP stream 0 from C:\captures\test.pcap"
-   "Export packets to JSON from C:\captures\test.pcap"

## Example Workflow

```
User: @wireshark list interfaces

Copilot: [Calls list_interfaces tool]
Found 9 network interface(s):
1. \Device\NPF_{...} (Ethernet)
2. \Device\NPF_{...} (Wi-Fi)
...

User: @wireshark capture 20 packets from Ethernet with filter "tcp port 80"

Copilot: [Calls live_capture tool with parameters]
Captured 20 packets from interface 'Ethernet'
[Shows packet preview]
```

## Notes

-   **MCP in VS Code** is relatively new - ensure you have the latest VS Code and Copilot extensions
-   **stdio protocol**: The MCP server uses standard input/output, so it won't show a GUI
-   **Permissions**: Live packet capture requires elevated permissions on Windows
-   **PATH**: Wireshark/tshark must be accessible - add to system PATH or specify in env

## Resources

-   [Model Context Protocol Documentation](https://modelcontextprotocol.io/)
-   [VS Code MCP Documentation](https://code.visualstudio.com/docs/copilot/mcp)
-   [MCP Wireshark GitHub](https://github.com/khuynh22/mcp-wireshark)

## Getting Help

If you encounter issues:

1. Check the VS Code Output panel (MCP logs)
2. Test the server manually in terminal
3. Verify Wireshark/tshark is installed and in PATH
4. Open an issue on GitHub with error messages and configuration
