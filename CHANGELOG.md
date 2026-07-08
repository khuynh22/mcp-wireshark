# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.5.0] - 2026-07-07

### Added

- `analyze_iec61850` — read-only health analyzer for IEC 61850 captures. Per-source `OK`/`WARN`/`FAIL` triage: GOOSE (`sqNum`/`stNum` gaps, `timeAllowedtoLive` violations, state-change storms, `ndsCom`/simulation flags), SV (`smpCnt` discontinuity, loss of time sync, `confRev` changes), and MMS (error/reject PDUs, unpaired requests, slow responses). Scans the full capture via `tshark -T fields` but returns a bounded report, so it is safe on high-rate SV streams. Handles multi-ASDU SV frames (one row per ASDU). Field names verified against tshark 4.6.5.

### Fixed

- `mcp.json`, `mcp-server.json`, and `server.json` tool lists and versions were stale (missing up to 7 tools); all three now list the full tool set and are version-bumped by the release workflow.
- GitHub release notes previously rendered an empty PR reference; the release workflow now uses the PR metadata resolved in its label-check job.

## [0.4.0] - 2026-05-26

### Added

- `expert_info` — tshark expert analysis: warnings, errors, and notes grouped by severity.
- `decode_protocol` — extract protocol fields as a TSV table, with curated defaults for HTTP, DNS, TLS, GOOSE, MMS, SV, SIP, and ICMP, or arbitrary fields for any other protocol.
- `protocol_stats` — aggregate `-z` reports: protocol hierarchy, conversations, endpoints, HTTP/DNS/SMB statistics.

_(Backfilled: this release shipped on 2026-05-26 without a changelog entry.)_

## [0.3.1] - 2026-05-09

### Fixed

- `read_pcap`, `display_filter`, `export_json`, and `live_capture` previously combined `tshark`'s `-c <count>` flag with `-Y <filter>`, but `-c` is applied to **raw** frames before the filter runs. Calls like `display_filter(filter="dns", packet_count=10)` would silently return zero packets if no DNS frames appeared in the first 10 raw frames of the pcap. The handlers now omit `-c` whenever a filter is set and slice the JSON output in Python instead, so `packet_count` always means "first N matching packets" — matching what users (and LLM callers) expect.

## [0.3.0] - 2026-05-09

### Added

- `ToolAnnotations` on every tool (`readOnlyHint`, `destructiveHint`, etc.) so MCP clients can surface side-effect risk before invocation
- `read_tools.py` — read-only tools: `check_installation`, `list_interfaces`, `read_pcap`, `display_filter`, `summarize_pcap`, `stats_by_proto`, `follow_tcp`, `follow_udp`
- `write_tools.py` — tools that capture traffic or write files: `live_capture`, `export_json`
- `validation.py` — shared `validate_file_path()`, `validate_display_filter()`, security constants

### Changed

- `server.py` reduced to server instance + dict-based router; all handler logic moved into `read_tools.py` / `write_tools.py`
- README rewritten around Claude Code adoption: verified `claude mcp add` install command, separate Read/Write tool tables, copy-paste prompt examples
- `CLAUDE.md` architecture section and `/add-tool` skill updated for the read/write split
- `mcp.json` tools reordered: read tools first, write tools last

### Migration

No tool names, schemas, or output formats changed. Internal Python imports of handler functions (`from mcp_wireshark.server import handle_*`) must be updated to `from mcp_wireshark.read_tools import handle_*` (or `write_tools` for `live_capture` / `export_json`). The public `app` export and `__version__` are unchanged.

## [0.1.1] - 2025-12-14

### Added

- MCP Registry support with `server.json` for official registry publishing
- MCP server manifest (`mcp-server.json`) for marketplace compatibility
- Security policy documentation (`SECURITY.md`)
- Code of Conduct (`CODE_OF_CONDUCT.md`)
- Input validation and sanitization for file paths and display filters
- Security constants for resource limits (max packet count, max duration)
- Enhanced package exports in `__init__.py`
- MCP server entry point in `pyproject.toml`
- Additional PyPI badges in README
- Python 3.13 support in classifiers
- Unofficial/community disclaimer in documentation and package metadata
- `__version__` variable in `__init__.py` for version tracking

### Security

- Added path traversal prevention
- Added display filter injection protection
- Limited file extensions to `.pcap`, `.pcapng`, `.cap`
- Maximum packet count limited to 10,000
- Maximum capture duration limited to 300 seconds

### Fixed

- Fixed missing `__version__` variable that prevented auto-release CI workflow from updating version

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
