"""Pure IEC 61850 health analysis — GOOSE, SV, and MMS.

This module is tshark-free and imports no MCP types. It consumes rows already
parsed from ``tshark -T fields`` output and returns plain dataclasses, so the
detection logic can be unit-tested without any subprocess. The MCP glue lives
in ``read_tools.py``.
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass

# --- Tunable thresholds (fixed, documented defaults; not exposed as params) ---
STORM_COUNT = 3  # >= this many stNum changes ...
STORM_WINDOW_MS = 100  # ... within this window => GOOSE state-change storm
MMS_SLOW_MS = 1000  # MMS response slower than this => WARN
MAX_STREAMS_SHOWN = 20  # cap rendered per-source blocks
MAX_ANOMALIES_PER_STREAM = 10  # cap anomalies listed per block
SEVERITY_ORDER = {"FAIL": 0, "WARN": 1, "OK": 2}

# tshark display filter used to select each protocol's frames.
BASE_FILTERS: dict[str, str] = {"goose": "goose", "sv": "sv", "mms": "mms"}

# ``-e`` columns extracted per protocol. Verified against tshark 4.6.5.
FIELD_SETS: dict[str, list[str]] = {
    "goose": [
        "frame.number",
        "frame.time_epoch",
        "eth.dst",
        "goose.gocbRef",
        "goose.stNum",
        "goose.sqNum",
        "goose.timeAllowedtoLive",
        "goose.ndsCom",
        "goose.simulation",
    ],
    "sv": [
        "frame.number",
        "frame.time_epoch",
        "eth.dst",
        "sv.svID",
        "sv.smpCnt",
        "sv.smpSynch",
        "sv.confRev",
        "sv.smpRate",
    ],
    "mms": [
        "frame.number",
        "frame.time_epoch",
        "tcp.stream",
        "ip.src",
        "ip.dst",
        "mms.invokeID",
        "mms.originalInvokeID",
        "mms.confirmedServiceRequest",
        "mms.confirmedServiceResponse",
        "mms.errorClass",
        "mms.rejectReason",
    ],
}


@dataclass
class Anomaly:
    """A single detected issue. ``severity`` is ``"FAIL"`` or ``"WARN"``."""

    severity: str
    frame: int | None
    message: str


@dataclass
class StreamReport:
    """Per-source result. ``verdict`` is ``"OK"``/``"WARN"``/``"FAIL"``."""

    stream_id: str
    label: str
    verdict: str
    metrics: dict[str, str]
    anomalies: list[Anomaly]


@dataclass
class ProtocolReport:
    """Aggregate result for one protocol over one capture."""

    streams_analyzed: int
    packets_scanned: int
    streams: list[StreamReport]


def _int(value: str, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _float(value: str, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _truthy(value: str) -> bool:
    """tshark renders FT_BOOLEAN fields as ``"1"``/``"0"`` under -T fields."""
    return value.strip().lower() in {"1", "true"}


def parse_field_rows(tsv_text: str, columns: list[str]) -> list[dict[str, str]]:
    """Parse ``tshark -T fields -E header=y`` TSV into a list of dicts.

    The first non-empty line is the header (discarded — we key by ``columns``).
    Each data line is split on tab and zipped with ``columns``; rows with fewer
    fields than ``columns`` are padded with ``""``. Blank lines are skipped.
    """
    lines = [ln for ln in tsv_text.splitlines() if ln.strip() != ""]
    if len(lines) <= 1:
        return []
    rows: list[dict[str, str]] = []
    for line in lines[1:]:  # skip header
        parts = line.split("\t")
        if len(parts) < len(columns):
            parts = parts + [""] * (len(columns) - len(parts))
        rows.append({col: parts[i] for i, col in enumerate(columns)})
    return rows


def _verdict(anomalies: list[Anomaly]) -> str:
    if any(a.severity == "FAIL" for a in anomalies):
        return "FAIL"
    if any(a.severity == "WARN" for a in anomalies):
        return "WARN"
    return "OK"


def _group_by(rows: list[dict[str, str]], key: str) -> dict[str, list[dict[str, str]]]:
    """Group rows by a column value, preserving capture order within groups."""
    groups: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        groups[row.get(key, "")].append(row)
    return groups


def _detect_goose_storm(change_events: list[tuple[int, float]]) -> Anomaly | None:
    """Flag the first window of >= STORM_COUNT stNum changes within the window."""
    window_s = STORM_WINDOW_MS / 1000.0
    for i in range(len(change_events)):
        j = i
        while j < len(change_events) and change_events[j][1] - change_events[i][1] <= window_s:
            j += 1
        count = j - i
        if count >= STORM_COUNT:
            return Anomaly(
                "WARN",
                change_events[i][0],
                f"storm: {count} stNum changes within {STORM_WINDOW_MS} ms "
                f"@frames {change_events[i][0]}-{change_events[j - 1][0]}",
            )
    return None


def analyze_goose(rows: list[dict[str, str]]) -> ProtocolReport:
    """Detect GOOSE liveness/sequence anomalies, grouped by gocbRef."""
    groups = _group_by(rows, "goose.gocbRef")
    streams: list[StreamReport] = []

    for gocb, group in groups.items():
        anomalies: list[Anomaly] = []
        change_events: list[tuple[int, float]] = []
        st_changes = 0
        sq_max = 0
        nds_seen = sim_seen = False

        for idx, row in enumerate(group):
            frame = _int(row["frame.number"])
            st = _int(row["goose.stNum"])
            sq = _int(row["goose.sqNum"])
            sq_max = max(sq_max, sq)
            nds_seen = nds_seen or _truthy(row["goose.ndsCom"])
            sim_seen = sim_seen or _truthy(row["goose.simulation"])

            if idx > 0:
                prev = group[idx - 1]
                pst = _int(prev["goose.stNum"])
                psq = _int(prev["goose.sqNum"])
                pt = _float(prev["frame.time_epoch"])
                t = _float(row["frame.time_epoch"])
                ptal = _int(prev["goose.timeAllowedtoLive"])

                if st == pst and sq - psq > 1:
                    missed = sq - psq - 1
                    anomalies.append(
                        Anomaly(
                            "FAIL",
                            frame,
                            f"sqNum gap @frame {frame}: {psq}->{sq} ({missed} missed)",
                        )
                    )
                if st < pst and (pst - st) < 2**31:  # ignore 32-bit rollover
                    anomalies.append(
                        Anomaly("FAIL", frame, f"stNum regression @frame {frame}: {pst}->{st}")
                    )
                if st > pst:
                    st_changes += 1
                    change_events.append((frame, t))
                gap_ms = (t - pt) * 1000.0
                if ptal > 0 and gap_ms > ptal:
                    anomalies.append(
                        Anomaly(
                            "FAIL",
                            frame,
                            f"TTL violation @frame {frame}: gap {gap_ms:.1f} ms > "
                            f"timeAllowedtoLive {ptal} ms",
                        )
                    )

        storm = _detect_goose_storm(change_events)
        if storm is not None:
            anomalies.append(storm)
        if nds_seen:
            anomalies.append(Anomaly("WARN", None, "ndsCom set (publisher needs commissioning)"))
        if sim_seen:
            anomalies.append(
                Anomaly("WARN", None, "simulation flag set (simulated data on the wire)")
            )

        label = f"dst {group[0].get('eth.dst', '')}"
        metrics = {
            "stNum changes": str(st_changes),
            "sqNum max": str(sq_max),
            "pkts": str(len(group)),
        }
        streams.append(StreamReport(gocb, label, _verdict(anomalies), metrics, anomalies))

    return ProtocolReport(len(streams), len(rows), streams)


_SMPSYNCH = {0: "none", 1: "local", 2: "global"}


def analyze_sv(rows: list[dict[str, str]]) -> ProtocolReport:
    """Detect Sampled Values continuity / sync anomalies, grouped by svID."""
    groups = _group_by(rows, "sv.svID")
    streams: list[StreamReport] = []

    for svid, group in groups.items():
        anomalies: list[Anomaly] = []
        counts = [_int(r["sv.smpCnt"]) for r in group]
        modulus = max(counts) + 1 if counts else 1

        synch_values = {_int(r["sv.smpSynch"]) for r in group}
        for idx, row in enumerate(group):
            frame = _int(row["frame.number"])
            cnt = _int(row["sv.smpCnt"])
            synch = _int(row["sv.smpSynch"])
            confrev = _int(row["sv.confRev"])
            if idx > 0:
                prev = group[idx - 1]
                pcnt = _int(prev["sv.smpCnt"])
                psynch = _int(prev["sv.smpSynch"])
                pconf = _int(prev["sv.confRev"])
                expected = (pcnt + 1) % modulus
                if cnt != expected:
                    dropped = (cnt - expected) % modulus
                    anomalies.append(
                        Anomaly(
                            "FAIL",
                            frame,
                            f"smpCnt discontinuity @frame {frame}: {pcnt}->{cnt} "
                            f"(~{dropped} dropped)",
                        )
                    )
                if psynch in (1, 2) and synch == 0:
                    anomalies.append(
                        Anomaly("FAIL", frame, f"loss of sync @frame {frame}: smpSynch {psynch}->0")
                    )
                if confrev != pconf:
                    anomalies.append(
                        Anomaly(
                            "WARN",
                            frame,
                            f"confRev change @frame {frame}: {pconf}->{confrev} "
                            "(dataset redefined)",
                        )
                    )

        if synch_values == {0}:
            anomalies.append(
                Anomaly("WARN", None, "smpSynch=0 throughout (samples not time-synchronized)")
            )

        last_synch = _int(group[-1]["sv.smpSynch"])
        metrics = {
            "smpCnt max": str(max(counts) if counts else 0),
            "smpSynch": f"{last_synch} ({_SMPSYNCH.get(last_synch, '?')})",
            "confRev": group[0].get("sv.confRev", ""),
            "pkts": str(len(group)),
        }
        label = f"dst {group[0].get('eth.dst', '')}"
        streams.append(StreamReport(svid, label, _verdict(anomalies), metrics, anomalies))

    return ProtocolReport(len(streams), len(rows), streams)


def _mms_kind(row: dict[str, str]) -> str:
    """Classify an MMS PDU by which marker column is populated."""
    if row.get("mms.confirmedServiceRequest", ""):
        return "req"
    if row.get("mms.confirmedServiceResponse", ""):
        return "resp"
    if row.get("mms.errorClass", ""):
        return "error"
    if row.get("mms.rejectReason", ""):
        return "reject"
    return "other"


def analyze_mms(rows: list[dict[str, str]]) -> ProtocolReport:
    """Detect MMS request/response anomalies, grouped by TCP stream."""
    groups = _group_by(rows, "tcp.stream")
    streams: list[StreamReport] = []

    for stream_id, group in groups.items():
        anomalies: list[Anomaly] = []
        pending: dict[int, deque[tuple[int, float]]] = defaultdict(deque)
        req_count = resp_count = err_count = 0
        max_rt_ms = 0.0
        label = ""

        for row in group:
            frame = _int(row["frame.number"])
            t = _float(row["frame.time_epoch"])
            kind = _mms_kind(row)
            if kind == "req":
                req_count += 1
                if not label:
                    label = f"{row.get('ip.src', '')} -> {row.get('ip.dst', '')}"
                pending[_int(row["mms.invokeID"])].append((frame, t))
            elif kind == "resp":
                resp_count += 1
                invoke = _int(row["mms.invokeID"])
                queue = pending.get(invoke)
                if queue:
                    _, req_t = queue.popleft()
                    rt_ms = (t - req_t) * 1000.0
                    max_rt_ms = max(max_rt_ms, rt_ms)
                    if rt_ms > MMS_SLOW_MS:
                        anomalies.append(
                            Anomaly(
                                "WARN",
                                frame,
                                f"slow response @frame {frame}: invokeID {invoke} "
                                f"took {rt_ms:.0f} ms",
                            )
                        )
            elif kind in ("error", "reject"):
                err_count += 1
                invoke = _int(row["mms.invokeID"]) or _int(row["mms.originalInvokeID"])
                queue = pending.get(invoke)
                if queue:
                    queue.popleft()
                detail = (
                    f"errorClass={row['mms.errorClass']}"
                    if kind == "error"
                    else f"reason={row['mms.rejectReason']}"
                )
                anomalies.append(
                    Anomaly(
                        "FAIL", frame, f"{kind} PDU @frame {frame}: invokeID {invoke} ({detail})"
                    )
                )

        for invoke, queue in pending.items():
            for frame, _ in queue:
                anomalies.append(
                    Anomaly(
                        "WARN",
                        frame,
                        f"unpaired request @frame {frame}: invokeID {invoke} (no response)",
                    )
                )

        metrics = {
            "requests": str(req_count),
            "responses": str(resp_count),
            "errors": str(err_count),
            "max resp ms": f"{max_rt_ms:.0f}",
        }
        streams.append(
            StreamReport(
                f"tcp.stream {stream_id}",
                label or group[0].get("ip.src", ""),
                _verdict(anomalies),
                metrics,
                anomalies,
            )
        )

    return ProtocolReport(len(streams), len(rows), streams)


def format_report(protocol: str, file_path: str, report: ProtocolReport) -> str:
    """Render a ProtocolReport as a compact, worst-first text report."""
    lines = [
        f"=== IEC 61850 {protocol.upper()} health: {file_path} ===",
        f"Streams analyzed: {report.streams_analyzed} | "
        f"packets scanned: {report.packets_scanned:,}",
        "",
    ]

    ordered = sorted(
        report.streams, key=lambda s: (SEVERITY_ORDER.get(s.verdict, 3), -len(s.anomalies))
    )
    shown = ordered[:MAX_STREAMS_SHOWN]

    for stream in shown:
        lines.append(f"[{stream.verdict}] {stream.stream_id}   ({stream.label})")
        lines.append("  " + " | ".join(f"{k}: {v}" for k, v in stream.metrics.items()))
        if stream.verdict != "OK":
            for anomaly in stream.anomalies[:MAX_ANOMALIES_PER_STREAM]:
                lines.append(f"  • {anomaly.message}")
            extra = len(stream.anomalies) - MAX_ANOMALIES_PER_STREAM
            if extra > 0:
                lines.append(f"  • … {extra} more anomalies")
        lines.append("")

    hidden = len(ordered) - len(shown)
    if hidden > 0:
        lines.append(
            f"… {hidden} more stream(s) truncated "
            f"(showing worst {len(shown)} of {len(ordered)})"
        )

    return "\n".join(lines).rstrip() + "\n"
