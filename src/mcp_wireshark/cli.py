"""Command-line interface for mcp-wireshark."""

import asyncio
import sys


def main() -> None:
    """Main entry point for the CLI."""
    from .server import main as server_main

    try:
        asyncio.run(server_main())
    except KeyboardInterrupt:
        print("\nShutting down MCP Wireshark server...", file=sys.stderr)
        sys.exit(0)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
