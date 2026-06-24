# Design: `analyze_iec61850` — IEC 61850 health analyzer

**Date:** 2026-06-23
**Status:** Approved (pending spec review)
**Type:** New read-only MCP tool (MINOR release)
**Verified against:** tshark (Wireshark) 4.6.5

## 1. Purpose

Add a single read-only MCP tool, `analyze_iec61850`, that triages substation
network captures for the protocols the project's primary audience cares about:
**GOOSE**, **Sampled Values (SV)**, and **MMS**. Today the server can *extract*
IEC 61850 fields (`decode_protocol`) but cannot *analyze* them — there is no
detection of `stNum`/`sqNum` gaps, `timeAllowedtoLive` violations, `smpCnt`
discontinuities, lost time sync, or MMS errors. This tool closes that gap and is
the project's clearest differentiator versus a generic tshark wrapper.

The output is consumed directly by an LLM context window, so it must be compact,
scannable, and worst-first.

## 2. Scope

In scope (v1):

- One tool, `analyze_iec61850(file_path, protocol, filter?)`, dispatching to
  three internal analyzers by `protocol` ∈ {`goose`, `sv`, `mms`}.
- Per-source health triage with `OK` / `WARN` / `FAIL` verdicts.
- Plain-text report (no JSON block) for token efficiency.

Out of scope (v1, possible later):

- Tunable thresholds exposed as parameters (storm window, MMS slow threshold are
  fixed, documented defaults).
- GSSE, PRP/HSR, R-GOOSE/R-SV (routable variants).
- A machine-readable JSON companion block.

## 3. Architecture & data flow

The MCP glue (schema, validation, tshark I/O, formatting hand-off) lives in
`read_tools.py` following the project's 4-step "adding a tool" convention. The
**analysis logic lives in a new pure module** `src/mcp_wireshark/iec61850.py`
that imports no MCP types and never shells out — it consumes already-parsed rows
and returns dataclasses. This keeps `read_tools.py` (already ~900 lines) from
ballooning and makes the domain logic unit-testable without tshark.

```
read_tools.py
  Tool("analyze_iec61850", …)                 # appended to READ_TOOLS
  handle_analyze_iec61850(arguments)           # registered in READ_HANDLERS
     ├─ validate_file_path(file_path)          # + existence check
     ├─ if filter: validate_display_filter(filter)
     ├─ base = BASE_FILTERS[protocol]
     │  combined = f"({base}) and ({filter})" if filter else base
     ├─ args = ["-r", path, "-Y", combined, "-T", "fields",
     │          *("-e", c for c in FIELD_SETS[protocol]),
     │          "-E", "header=y", "-E", "separator=\t", "-E", "quote=n"]
     ├─ run_tshark(args, timeout=120)
     ├─ parse TSV → list[dict[str, str]]       # one dict per packet, header-keyed
     └─ dispatch → iec61850.analyze_<proto>(rows) → ProtocolReport
        → iec61850.format_report(protocol, file_path, report) → TextContent

iec61850.py   (pure; tshark-free; fully unit-testable)
  FIELD_SETS:   dict[str, list[str]]           # -e columns per protocol
  BASE_FILTERS: {"goose":"goose", "sv":"sv", "mms":"mms"}
  STORM_COUNT = 3 ; STORM_WINDOW_MS = 100
  MMS_SLOW_MS = 1000
  MAX_STREAMS_SHOWN = 20 ; MAX_ANOMALIES_PER_STREAM = 10
  SEVERITY_ORDER = {"FAIL": 0, "WARN": 1, "OK": 2}

  @dataclass Anomaly:        severity: str; frame: int | None; message: str
  @dataclass StreamReport:   stream_id: str; label: str; verdict: str;
                             metrics: dict[str, str]; anomalies: list[Anomaly]
  @dataclass ProtocolReport: streams_analyzed: int; packets_scanned: int;
                             streams: list[StreamReport]

  analyze_goose(rows) -> ProtocolReport
  analyze_sv(rows)    -> ProtocolReport
  analyze_mms(rows)   -> ProtocolReport
  format_report(protocol, file_path, report) -> str
```

## 4. High-volume handling

SV runs up to ~4000 packets/sec per IED; a 60 s capture can exceed 240k packets.
`-T fields` emits only the few needed columns (tiny per packet), so the analyzer
scans **all** rows in Python to catch any discontinuity. The existing
`MAX_PACKET_COUNT = 10000` governs **per-packet JSON output** in other tools; it
does **not** bound this analyzer's internal field-row scan, because the tool
returns only a bounded text report, never per-packet JSON. The scan is bounded
instead by the `run_tshark` `timeout=120`. No security constant is weakened or
added. If tshark output is unexpectedly enormous the timeout trips and the
handler returns an error string.

## 5. Verified field sets (tshark 4.6.5)

### GOOSE — `FIELD_SETS["goose"]`
```
frame.number          frame.time_epoch        eth.dst
goose.gocbRef         goose.stNum             goose.sqNum
goose.timeAllowedtoLive  goose.ndsCom         goose.simulation
```
Group key: `goose.gocbRef`. (`goose.timeAllowedtoLive` is `FT_INT32`,
milliseconds; `goose.ndsCom` / `goose.simulation` are `FT_BOOLEAN`.)

### SV — `FIELD_SETS["sv"]`
```
frame.number   frame.time_epoch   eth.dst
sv.svID        sv.smpCnt          sv.smpSynch   sv.confRev   sv.smpRate
```
Group key: `sv.svID`. (`sv.smpCnt`/`sv.confRev`/`sv.smpRate` are `FT_UINT32`;
`sv.smpSynch` is `FT_INT32`.)

### MMS — `FIELD_SETS["mms"]`
```
frame.number   frame.time_epoch   tcp.stream   ip.src   ip.dst
mms.invokeID   mms.originalInvokeID
mms.confirmedServiceRequest   mms.confirmedServiceResponse
mms.errorClass                mms.rejectReason
```
Group key: `tcp.stream`. PDU classification by which marker column is non-empty:

| Marker non-empty | PDU type |
|---|---|
| `mms.confirmedServiceRequest`  | request |
| `mms.confirmedServiceResponse` | success response |
| `mms.errorClass`               | error response |
| `mms.rejectReason`             | reject |

Pair request↔response by `mms.invokeID` within a `tcp.stream`; for reject/error
PDUs that omit `invokeID`, fall back to `mms.originalInvokeID`.

> Implementation note: a single TCP segment can carry multiple MMS PDUs, in which
> case `-T fields` repeats values for that frame. The exact extraction (and any
> `-E occurrence=` handling) will be confirmed via TDD against a sample capture
> before the detection logic is locked. Because analyzers consume parsed rows,
> the column list can change without touching detection.

## 6. Anomaly detection semantics

Frame references come from `frame.number`; timing from `frame.time_epoch`
(float seconds). Verdict per stream = `FAIL` if any error-class anomaly, else
`WARN` if any soft anomaly, else `OK`.

### GOOSE (group by `gocbRef`, ordered by frame)
- **sqNum gap** — `FAIL`. Consecutive packets where `sqNum` jumps by >1 *without*
  a `stNum` change → missed retransmits. Message: `sqNum gap @frame N: a→b (k missed)`.
  On a `stNum` change, `sqNum` resets to 0 — that reset is normal, never flagged.
- **stNum regression** — `FAIL`. `stNum` decreases (excluding 32-bit rollover) →
  out-of-order / possible replay.
- **TTL violation** — `FAIL`. Inter-arrival gap between consecutive packets in a
  stream exceeds *that packet's own* `goose.timeAllowedtoLive` (ms). Self-describing;
  no global threshold. Message: `TTL violation @frame N: gap X ms > timeAllowedtoLive Y ms`.
- **State-change storm** — `WARN`. ≥ `STORM_COUNT` (3) `stNum` changes within
  `STORM_WINDOW_MS` (100 ms) → flapping.
- **ndsCom / simulation flag set** — `WARN`. Publisher needs commissioning, or
  simulated data is on the wire.
- Metrics: `stNum changes`, `sqNum max`, `pkts`.

### SV (group by `svID`; two-pass)
Pass 1 establishes the rollover modulus per stream. The robust default is
inferred from the data: `modulus = max_smpCnt + 1` (e.g. 4000 @ 50 Hz,
4800 @ 60 Hz). `sv.smpRate`, when present, is used only as a sanity cross-check
on the inferred modulus (logged, not authoritative — its units vary by vendor).
Pass 2 checks continuity with `expected_next = (cur + 1) % modulus`.
- **smpCnt discontinuity** — `FAIL`. Observed next ≠ expected and not a valid
  rollover (high→low near modulus) → dropped samples. Message:
  `smpCnt discontinuity @frame N: a→b (~k dropped)`.
- **Loss of sync** — `FAIL`. `smpSynch` drops from synced (1 local / 2 global) to
  0 mid-stream → lost time reference.
- **Unsynchronized throughout** — `WARN`. `smpSynch == 0` for the whole stream.
- **confRev change** — `WARN`. Configuration revision changes mid-capture →
  dataset redefined.
- Metrics: `samples`, `smpSynch`, `confRev`, `pkts`.

### MMS (group by `tcp.stream`; pair by `invokeID`)
- **Error / reject PDU** — `FAIL`. `mms.errorClass` or `mms.rejectReason` present →
  server returned an error or rejected a request. Message includes the class/reason.
- **Unpaired request** — `WARN`. A request `invokeID` with no matching response by
  end of capture (could also be a truncated capture — hence `WARN`, not `FAIL`).
- **Slow response** — `WARN`. Response time > `MMS_SLOW_MS` (1000 ms). Message:
  `slow response @frame N: invokeID K took X ms`.
- Metrics: `requests`, `responses`, `errors`, `max resp ms`. Label = `src → dst`.

## 7. Output contract

```
=== IEC 61850 GOOSE health: substation.pcap ===
Streams analyzed: 3 | packets scanned: 48,210

[FAIL] IED1/LLN0$GO$gcb01   (dst 01:0c:cd:01:00:01)
  stNum changes: 4 | sqNum max: 218 | pkts: 16,402
  • sqNum gap @frame 1102: 47→51 (3 missed)
  • TTL violation @frame 880: gap 2.1 ms > timeAllowedtoLive 2.0 ms
  • storm: 4 stNum changes in 12 ms @frames 1200–1240

[WARN] IED3/LLN0$GO$gcb03   (dst 01:0c:cd:01:00:03)
  stNum changes: 0 | sqNum max: 90 | pkts: 88
  • ndsCom set (publisher needs commissioning)

[OK]   IED2/LLN0$GO$gcb02   (dst 01:0c:cd:01:00:02)
  stNum changes: 0 | sqNum max: 5901 | pkts: 31,808
```

Rules:
- Header line, then `Streams analyzed: N | packets scanned: M`.
- Sort streams **worst-first**: `FAIL` > `WARN` > `OK`; tiebreak by anomaly count
  descending.
- Show at most `MAX_STREAMS_SHOWN` (20). If more,
  footer: `… {k} more stream(s) truncated (showing worst {shown} of {total})`.
- Per stream: `[VERDICT] {stream_id}   ({label})`, then the metrics line, then up
  to `MAX_ANOMALIES_PER_STREAM` (10) anomaly bullets; if more,
  `• … {k} more anomalies`.
- `OK` streams render the metrics line only (no bullets).
- Empty result → `No {PROTO} packets found in {file}[ matching filter '{f}']`.

## 8. Input schema

```json
{
  "type": "object",
  "properties": {
    "file_path": { "type": "string", "description": "Path to the .pcap/.pcapng file" },
    "protocol":  { "type": "string", "enum": ["goose", "sv", "mms"],
                   "description": "IEC 61850 protocol to analyze" },
    "filter":    { "type": "string",
                   "description": "Optional display filter ANDed with the protocol filter to scope to one gocbRef/svID/host" }
  },
  "required": ["file_path", "protocol"]
}
```

Annotation: `_read_only("Analyze IEC 61850 health")` (`readOnlyHint=True`,
`openWorldHint=False`).

## 9. Security & validation

- `validate_file_path(file_path)` + existence check (reject `..`, enforce
  `.pcap`/`.pcapng`/`.cap`) — no exceptions.
- `protocol` must be in `{goose, sv, mms}`; otherwise return an error
  `TextContent` (never raise to the MCP layer).
- If `filter` is supplied: `validate_display_filter(filter)`, then combine as
  `(base) and (filter)`.
- All subprocess calls via `run_tshark` with an explicit argument list. No
  `shell=True`.
- No security constant is weakened or added (see §4).
- Handler catches all exceptions and returns error `TextContent` per project
  convention.

## 10. Testing

`tests/test_iec61850.py` (new) — pure unit tests feeding synthetic parsed rows
(no tshark):
- GOOSE: clean→OK; sqNum gap→FAIL; sqNum reset on stNum change→not flagged;
  stNum regression→FAIL; TTL violation→FAIL; storm→WARN; ndsCom/simulation→WARN.
- SV: clean→OK; smpCnt gap→FAIL; rollover (max→0)→not flagged; sync 2→0→FAIL;
  smpSynch==0 throughout→WARN; confRev change→WARN.
- MMS: clean pair→OK; error PDU→FAIL; reject→FAIL; unpaired request→WARN; slow
  response→WARN; pairing by invokeID across a tcp.stream.
- `format_report`: worst-first ordering, stream cap + truncation footer, anomaly
  cap + "more anomalies" line, OK collapse.

`tests/test_server.py` (extend) — handler integration with `run_tshark` mocked to
return canned TSV: assert report text, `READ_HANDLERS` registration, and
validation paths (bad protocol, file-not-found, path traversal rejected, bad
filter rejected).

## 11. Deliverables checklist

- `src/mcp_wireshark/iec61850.py` — analyzers + formatter + dataclasses.
- `read_tools.py` — `Tool` entry in `READ_TOOLS`, `handle_analyze_iec61850`,
  `READ_HANDLERS` registration.
- `tests/test_iec61850.py` + `tests/test_server.py` additions.
- README read-tools table, `mcp.json` tool list, `docs/API.md`, and
  `CHANGELOG.md` `[Unreleased]` updated.
- Pass `black` / `ruff` / `mypy` / `pytest` (the `/validate` skill).
- PR labeled `release:minor` (new tool — see CLAUDE.md versioning).
