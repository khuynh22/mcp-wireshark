# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2025-12-12

### Added

- MCP server manifest (`mcp-server.json`) for marketplace compatibility
- Security policy documentation (`SECURITY.md`)
- Code of Conduct (`CODE_OF_CONDUCT.md`)
- Input validation and sanitization for file paths and display filters
- Security constants for resource limits (max packet count, max duration)
- Enhanced package exports in `__init__.py`
- MCP server entry point in `pyproject.toml`
- Additional PyPI badges in README
- Python 3.13 support in classifiers

### Security

- Added path traversal prevention
- Added display filter injection protection
- Limited file extensions to `.pcap`, `.pcapng`, `.cap`
- Maximum packet count limited to 10,000
- Maximum capture duration limited to 300 seconds

## [0.1.0] - 2025-11-04

### Added

- Initial release of mcp-wireshark
- MCP server implementation with 7 tools:
  - `list_interfaces` - List available network interfaces
  - `live_capture` - Capture live network traffic
  - `read_pcap` - Read and analyze .pcap/.pcapng files
  - `display_filter` - Apply Wireshark display filters
  - `stats_by_proto` - Generate protocol statistics
  - `follow_tcp` - Follow TCP streams
  - `export_json` - Export packets to JSON format
- CLI interface via `mcp-wireshark` command
- Comprehensive documentation:
  - README with usage examples
  - Quick Start Guide
  - API documentation
  - Contributing guidelines
- MCP configuration examples for:
  - Claude Desktop
  - VS Code
- Example scripts demonstrating all features
- Test suite with pytest
- Type hints throughout (mypy validated)
- CI/CD workflows for GitHub Actions
- Cross-platform support (Linux, macOS, Windows)
- MIT License

### Technical Details

- Uses tshark/pyshark for packet analysis
- Prefers dumpcap over tshark for non-root captures
- Full async/await support
- Python 3.10+ support
- Pip-installable package
