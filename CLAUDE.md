# CLAUDE.md — mcp-wireshark

Project instructions for Claude Code. Read this before making any changes.

## Purpose

This is an MCP server that gives AI assistants (Claude, Copilot, etc.) direct access to Wireshark/tshark. The primary audience is **IEC 61850 engineers** who need to analyze substation network traffic (GOOSE, MMS, Sampled Values) and the broader network/security community. Every design decision should serve two goals:

1. **Token efficiency** — MCP tool responses are fed directly into an LLM context window. Bloated output burns tokens and degrades reasoning quality.
2. **Correctness and safety** — tshark is run as a subprocess with user-supplied arguments. Input validation is critical.

---

## Architecture

```
src/mcp_wireshark/
  server.py   — Tool schemas (list_tools) + call routing (call_tool) + handlers
  utils.py    — run_tshark(), run_dumpcap(), parse_packet_json(), WiresharkNotFoundError
  types.py    — TypedDicts: PacketInfo, InterfaceInfo, ProtocolStats, TCPStream
  cli.py      — Entry point: asyncio.run(server.main())
  __init__.py — Public API + __version__
tests/
  test_server.py  — Validation logic + handler integration tests
  test_utils.py   — run_tshark mocking
  conftest.py     — Shared fixtures
```

**Adding a tool is always 4 steps:**
1. Add `Tool(...)` entry in `list_tools()` in server.py
2. Add `if name == "tool_name": return await handle_tool_name(arguments)` in `call_tool()`
3. Write `async def handle_tool_name(arguments) -> list[TextContent]` in server.py
4. Add tests in `tests/test_server.py`

Use the `/add-tool` skill to scaffold this automatically.

---

## Code Conventions

- **Line length**: 100 chars (black + ruff configured)
- **Types**: All functions must be fully typed. No `Any` in public signatures unless unavoidable.
- **Async**: All handlers are `async`. Use `asyncio.gather()` for parallel tshark calls.
- **Error handling**: Handlers catch all exceptions and return `TextContent` with error text — never raise to the MCP layer.
- **Validation**: Every `file_path` argument goes through `validate_file_path()`. Every display filter goes through `validate_display_filter()`. No exceptions.
- **No shell=True**: Always use `asyncio.create_subprocess_exec()` with an explicit list. Never `shell=True`.

---

## Token Efficiency Rules

These rules exist because every byte of MCP tool output consumes user context.

- **Preview only**: For packet lists, return at most 5 packets in full JSON. Always include a count.
- **Summarize, don't dump**: `summarize_pcap` exists precisely for this — use stats, not raw packet JSON.
- **Trim stderr**: Never include tshark stderr in success responses.
- **No redundant fields**: When constructing response text, omit empty/zero/null fields.
- **Streaming is not available**: tshark output is collected in full before returning. Keep timeouts tight.

---

## IEC 61850 Domain Knowledge

IEC 61850 is the international standard for substation automation. Engineers use it to protect electrical grids. The key protocols captured in pcap files:

| Protocol | tshark filter | Description |
|----------|--------------|-------------|
| GOOSE | `goose` | Fast protection messages, multicast, sub-millisecond timing |
| MMS | `mms` | Client-server communication for reading/writing data objects |
| Sampled Values | `sv` | High-speed current/voltage samples from merging units |
| GSSE | `gsse` | Generic Substation Status Events (older, deprecated) |
| PRP/HSR | `prp` or `hsr` | Redundancy protocols common in IEC 61850 networks |

**Common IEC 61850 display filters:**
```
goose                              All GOOSE messages
goose.stNum > 0                    GOOSE with state changes
mms                                All MMS traffic
sv                                 Sampled Values
goose && eth.dst[0] == 01         GOOSE multicast only
goose.timeAllowedtoLive < 1000    Fast GOOSE (< 1ms TTL)
mms.confirmed_RequestPDU          MMS requests only
```

**When adding IEC 61850 features:**
- GOOSE timestamps are in UTC with microsecond precision — preserve them
- GOOSE `stNum` (state number) increments on state changes; `sqNum` (sequence) increments every retransmit. Both matter for analysis.
- MMS uses ASN.1 encoding — tshark decodes it but field names can be verbose
- Sampled Values are high-volume (up to 4000 packets/second per IED) — always apply packet count limits

---

## Security Model

- `validate_file_path()`: Rejects `..`, enforces `.pcap`/`.pcapng`/`.cap` extensions
- `validate_display_filter()`: Rejects shell metacharacters (`;`, `&&`, `|`, backticks, `$()`, etc.), max 1000 chars
- `MAX_PACKET_COUNT = 10000`: Hard cap on all packet operations
- `MAX_DURATION_SECONDS = 300`: Hard cap on live capture
- All subprocess calls use explicit argument lists, never `shell=True`

Do not weaken these constraints. If a user scenario requires more packets, increase the constant with justification in the PR, not per-call overrides.

---

## Quality Checks

Always run before committing:

```bash
black src tests          # format
ruff check src tests     # lint
mypy src                 # type check
pytest                   # tests
```

Or use the `/validate` skill which runs all four.

---

## Versioning

- Follows semver: `MAJOR.MINOR.PATCH`
- **Patch**: bug fixes, security fixes, no new tools
- **Minor**: new tools, new optional parameters, README changes
- **Major**: removing tools, changing required params, breaking output format changes

**You never touch version numbers manually.** The CI does it automatically:

1. Add a label to the PR before merging: `release:patch`, `release:minor`, or `release:major`
2. Merge — `auto-release.yml` bumps all three version locations (`pyproject.toml`, `__init__.py`, `mcp.json`), tags, publishes to PyPI, and creates a GitHub Release

If no label is added, the PR merges without a release. Use the `/release` skill to decide which label to apply.

---

## What NOT to Do

- Do not add `pyshark` back — this project calls tshark directly for full control and no dependency on libpcap Python bindings
- Do not use `shell=True` in any subprocess call
- Do not return raw full JSON for more than 5 packets in a single tool response
- Do not add tools that duplicate existing tshark functionality without a clear LLM-usability benefit
- Do not skip `validate_file_path()` for any handler that accepts a file path
- Do not commit without running the full quality check suite
