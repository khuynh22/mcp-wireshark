"""MCP server entry point. Tools live in read_tools.py and write_tools.py."""

from typing import Any

from mcp.server import Server
from mcp.types import TextContent, Tool

from .dissector_tools import DISSECTOR_HANDLERS, DISSECTOR_TOOLS
from .read_tools import READ_HANDLERS, READ_TOOLS
from .utils import WiresharkNotFoundError, check_wireshark_installed
from .validation import (
    MAX_DURATION_SECONDS,
    MAX_PACKET_COUNT,
    validate_display_filter,
    validate_file_path,
)
from .write_tools import WRITE_HANDLERS, WRITE_TOOLS

app = Server("mcp-wireshark")


__all__ = [
    "MAX_DURATION_SECONDS",
    "MAX_PACKET_COUNT",
    "app",
    "main",
    "validate_display_filter",
    "validate_file_path",
]


@app.list_tools()
async def list_tools() -> list[Tool]:
    """Return all available MCP tools, read tools first then write tools."""
    return [*READ_TOOLS, *DISSECTOR_TOOLS, *WRITE_TOOLS]


@app.call_tool()
async def call_tool(name: str, arguments: Any) -> list[TextContent]:
    """Route a tool call to the appropriate handler."""
    try:
        tools = check_wireshark_installed()
        if not tools["tshark"]:
            return [
                TextContent(
                    type="text",
                    text="Error: tshark not found. Please install Wireshark/tshark.",
                )
            ]

        if name in READ_HANDLERS:
            return await READ_HANDLERS[name](arguments)
        if name in DISSECTOR_HANDLERS:
            return await DISSECTOR_HANDLERS[name](arguments)
        if name in WRITE_HANDLERS:
            return await WRITE_HANDLERS[name](arguments)

        return [TextContent(type="text", text=f"Unknown tool: {name}")]

    except WiresharkNotFoundError as e:
        return [TextContent(type="text", text=f"Error: {e}")]
    except Exception as e:
        return [TextContent(type="text", text=f"Error: {e}")]


async def main() -> None:
    """Run the MCP server over stdio."""
    from mcp.server.stdio import stdio_server

    async with stdio_server() as (read_stream, write_stream):
        await app.run(
            read_stream,
            write_stream,
            app.create_initialization_options(),
        )
