# Functional Test Plan — `analyze_iec61850` (PR #23)

Functional (black-box) verification of the `analyze_iec61850` MCP tool against real
tshark, using captures with known, deterministic ground truth. Complements the 76
unit/integration tests, which mock tshark.

**Status legend:** every case below was executed against tshark 4.6.5 on 2026-07-06;
the *Expected* column is the verified actual output. Review findings #1 (multi-ASDU
SV) and #2 (MMS response markers) are fixed on this branch; S6 and M3 were XFAIL
before those fixes and now PASS.

---

## 1. Prerequisites

- Wireshark/tshark ≥ 4.6 on `PATH` (`tshark --version`).
- This repo on branch `feat/iec61850-analyzer` (the tool exists only on the PR branch —
  the released PyPI server does not have it).
- A working Python env. Note: the repo's `.venv` is broken ("Could not find platform
  independent libraries"). Use:

  ```powershell
  $env:UV_PROJECT_ENVIRONMENT = "$env:TEMP\mcp-wireshark-venv"
  uv run --extra dev pytest -q        # sanity: 76 passed
  ```

## 2. Test assets ("the packages")

### 2.1 Generated captures — deterministic fault injection

```powershell
uv run python scripts/make_iec61850_test_pcaps.py testdata
```

Writes 13 pcaps to `testdata/` (gitignored via `*.pcap`). Each file injects exactly
one fault, so the expected verdict is unambiguous. Frames are hand-built BER and
verified to dissect fully in tshark 4.6.5 (`goose.*` and `sv.*` fields all populate).

### 2.2 Real-world captures — public domain (ITI/ICS-Security-Tools)

```powershell
cd testdata
$base = 'https://raw.githubusercontent.com/ITI/ICS-Security-Tools/master/pcaps/IEC61850'
Invoke-WebRequest "$base/Sample_File_MMS_and_GOOSE.pcap"                        -OutFile mms_and_goose_real.pcap
Invoke-WebRequest "$base/MMS%20-%20Specific%20Commands/iec61850_read.pcap"      -OutFile mms_read_real.pcap
Invoke-WebRequest "$base/MMS%20-%20Specific%20Commands/iec61850_get_name_list.pcap" -OutFile mms_getnamelist_real.pcap
Invoke-WebRequest "$base/GOOSE/Sample_File_GOOSE.pcap"                          -OutFile goose_real.pcap
```

More MMS service captures (cancel, kill, takeControl, …) live in the same
`MMS - Specific Commands/` directory if deeper MMS coverage is wanted.

## 3. How to invoke

**Via MCP (the real deal):** point your MCP client at this checkout, e.g. in
`claude_desktop_config.json` / `.mcp.json`:

```json
{ "mcpServers": { "mcp-wireshark-dev": {
    "command": "uv",
    "args": ["run", "--directory", "D:/src/mcp-wireshark", "mcp-wireshark"] } } }
```

then prompt: *"Analyze `testdata/goose_sqnum_gap.pcap` for GOOSE health"* and confirm
the client calls `analyze_iec61850 {file_path, protocol: "goose"}`.

**Direct handler (faster iteration):**

```python
import asyncio
from mcp_wireshark.read_tools import handle_analyze_iec61850
r = asyncio.run(handle_analyze_iec61850(
    {"file_path": "testdata/goose_sqnum_gap.pcap", "protocol": "goose"}))
print(r[0].text)
```

## 4. Test matrix — GOOSE (generated)

| ID | Capture | Expected (verified) |
|----|---------|---------------------|
| G1 | `goose_clean.pcap` — steady retransmits + one legitimate state change (sqNum reset) | `[OK]`, `stNum changes: 1`, no anomalies. The sqNum reset at the stNum change is **not** flagged |
| G2 | `goose_sqnum_gap.pcap` — sqNum 47→51 | `[FAIL]` · `sqNum gap @frame 4: 47->51 (3 missed)` |
| G3 | `goose_stnum_regression.pcap` — stNum 5→3 | `[FAIL]` · `stNum regression @frame 4: 5->3` |
| G4 | `goose_ttl_violation.pcap` — 5 s silence, TAL 2000 ms | `[FAIL]` · `TTL violation @frame 3: gap 5000.0 ms > timeAllowedtoLive 2000 ms` |
| G5 | `goose_storm.pcap` — 4 stNum changes in 15 ms | `[WARN]` · `storm: 3 stNum changes within 100 ms @frames 2-4` |
| G6 | `goose_flags.pcap` — ndsCom=1, simulation=1 | `[WARN]` · both `ndsCom set …` and `simulation flag set …` bullets |
| G7 | `goose_multistream.pcap` — gcb01 clean, gcb02 has gap | 2 streams; `[FAIL] …gcb02` listed **before** `[OK] …gcb01` (worst-first) |

## 5. Test matrix — Sampled Values (generated)

| ID | Capture | Expected (verified) |
|----|---------|---------------------|
| S1 | `sv_clean.pcap` — smpCnt 3990…3999→0…9, smpSynch=2 | `[OK]`; the 3999→0 rollover is **not** flagged |
| S2 | `sv_dropout.pcap` — smpCnt 9→30 | `[FAIL]` · `smpCnt discontinuity @frame 11: 9->30 (~20 dropped)` |
| S3 | `sv_sync_loss.pcap` — smpSynch 2→0 mid-stream | `[FAIL]` · `loss of sync @frame 6: smpSynch 2->0` |
| S4 | `sv_unsynced.pcap` — smpSynch=0 throughout | `[WARN]` · `smpSynch=0 throughout (samples not time-synchronized)` |
| S5 | `sv_confrev_change.pcap` — confRev 1→2 | `[WARN]` · `confRev change @frame 6: 1->2 (dataset redefined)` |
| S6 | `sv_multi_asdu.pcap` — healthy stream, 2 ASDUs/frame | `[OK] MU01` · `smpCnt max: 15 | smpSynch: 2 (global) | … | ASDUs: 16`; header reports `packets scanned: 8` (frames). Regression test for review finding #1 — comma-joined multi-occurrence fields are expanded to one row per ASDU |

## 6. Test matrix — MMS (real captures)

| ID | Capture / protocol | Expected (verified) |
|----|--------------------|---------------------|
| M1 | `mms_read_real.pcap` `mms` | `[OK]` tcp.stream 0 · `requests: 1 | responses: 2 | errors: 0 | max resp ms: 25` (the capture contains a duplicated response frame; both are counted) |
| M2 | `mms_and_goose_real.pcap` `mms` | `[FAIL]` tcp.stream 14 · `error PDU @frame 126: invokeID 303731 (errorClass=7)` |
| M3 | `mms_getnamelist_real.pcap` `mms` | `[OK]` tcp.stream 0 · `requests: 1 | responses: 2 | errors: 0 | max resp ms: 13`. Regression test for review finding #2 — the GetNameList response dissects with `mms.confirmedServiceResponse` empty and is now classified via `mms.confirmed_ResponsePDU_element` |
| M4 | `mms_and_goose_real.pcap` `goose` | 3 gocbRef streams; `[WARN]` storm on `…Q01…gcb_A` (real state-change burst in this capture), two single-packet `[OK]` streams |
| M5 | `goose_real.pcap` `goose` | 3 streams, all `[WARN]` storm (capture genuinely contains chatter bursts); demonstrates behavior on 451-packet real traffic |

## 7. Edge / negative cases (all verified)

| ID | Call | Expected (verified) |
|----|------|---------------------|
| E1 | `protocol: "ftp"` | `Error: 'protocol' must be one of goose, mms, sv.` |
| E2 | missing file | `Error: File not found: …` |
| E3 | `file_path: "README.md"` | `Error … Invalid file extension. Allowed: .pcapng, .pcap, .cap` |
| E4 | `file_path: "../secrets/x.pcap"` | `Error … Path traversal not allowed` |
| E5 | `filter: "goose; rm -rf"` | `Error … Invalid character in display filter: ;` |
| E6 | `goose_multistream.pcap` + `filter: goose.gocbRef contains "gcb02"` | Only the gcb02 stream analyzed (`Streams analyzed: 1`), still `[FAIL]` with its gap |
| E7 | `sv` protocol against a GOOSE-only capture | `No SV packets found in …` |

Caution on E6-style filters: only scope by stream identity (`gocbRef`/`svID`/host).
Filtering on sequence fields (e.g. `goose.sqNum > 10`) removes intermediate packets
and manufactures false gap/TTL anomalies.

## 8. Not yet covered (candidates for follow-up)

- **Truncation caps at MCP level**: a capture with >20 streams / >10 anomalies per
  stream (unit-tested in `test_iec61850.py`, not yet exercised end-to-end).
- **Soak/perf**: a full-rate SV capture (4000 pkt/s × 60 s ≈ 240k frames) to observe
  scan time vs the 120 s timeout and memory footprint (rows are fully materialized).
- **MMS deep coverage**: run the remaining `MMS - Specific Commands/*.pcap` service
  types (cancel, kill, takeControl…) — cheap to add with the download block above.
- **stNum 32-bit rollover** GOOSE case (rollover is exempted in code, not exercised).
- **Multiple MMS PDUs in one TCP segment** (pipelined requests): field occurrences
  are comma-joined per frame and cannot be re-paired from `-T fields` output alone;
  such frames may still misclassify. Not observed in the sample captures.

## 9. Pass criteria

PR functionally passes when all cases G1–G7, S1–S6, M1–M5, and E1–E7 match the
tables above. (Verified in full on 2026-07-06 against tshark 4.6.5.)
