"""Incremental IEC 61850 health analysis for GOOSE, SV, and MMS."""

from __future__ import annotations

from collections import defaultdict, deque
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field

STORM_COUNT = 3
STORM_WINDOW_MS = 100
MMS_SLOW_MS = 1000
MAX_STREAMS_SHOWN = 20
MAX_ANOMALIES_PER_STREAM = 10
SEVERITY_ORDER = {"FAIL": 0, "WARN": 1, "OK": 2}
SV_COUNTER_MODULUS = 2**16
LEGACY_SV_RATES = {4000, 4800}

BASE_FILTERS: dict[str, str] = {
    "goose": "goose",
    "sv": "sv",
    "mms": (
        "mms and not (tcp.analysis.retransmission or tcp.analysis.fast_retransmission "
        "or tcp.analysis.spurious_retransmission)"
    ),
}

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
        "eth.dst",
        "sv.svID",
        "sv.smpCnt",
        "sv.smpSynch",
        "sv.confRev",
        "sv.smpRate",
        "sv.smpMod",
    ],
}


@dataclass
class Anomaly:
    severity: str
    frame: int | None
    message: str


@dataclass
class StreamReport:
    stream_id: str
    label: str
    verdict: str
    metrics: dict[str, str]
    anomalies: list[Anomaly]
    anomaly_count: int | None = None

    @property
    def total_anomalies(self) -> int:
        return len(self.anomalies) if self.anomaly_count is None else self.anomaly_count


@dataclass
class ProtocolReport:
    streams_analyzed: int
    packets_scanned: int
    streams: list[StreamReport]


@dataclass
class _Findings:
    verdict: str = "OK"
    count: int = 0
    preview: list[Anomaly] = field(default_factory=list)

    def add(self, severity: str, frame: int | None, message: str) -> None:
        self.count += 1
        if SEVERITY_ORDER[severity] < SEVERITY_ORDER[self.verdict]:
            self.verdict = severity
        if len(self.preview) < MAX_ANOMALIES_PER_STREAM:
            self.preview.append(Anomaly(severity, frame, message))

    def report(self, stream_id: str, label: str, metrics: dict[str, str]) -> StreamReport:
        return StreamReport(stream_id, label, self.verdict, metrics, self.preview, self.count)


def _int(value: str, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _float(value: str) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _truthy(value: str) -> bool:
    """Accept both numeric and textual true values from tshark."""
    return value.strip().lower() in {"1", "true"}


@dataclass
class _GooseStorm:
    candidates: deque[tuple[int, float]] = field(default_factory=deque)
    start: tuple[int, float] | None = None
    end_frame: int = 0
    count: int = 0
    complete: bool = False

    def add(self, frame: int, time: float) -> None:
        if self.complete:
            return
        window = STORM_WINDOW_MS / 1000
        if self.start is None:
            while self.candidates and time - self.candidates[0][1] > window:
                self.candidates.popleft()
            self.candidates.append((frame, time))
            if len(self.candidates) == STORM_COUNT:
                self.start = self.candidates[0]
                self.end_frame = frame
                self.count = STORM_COUNT
                self.candidates.clear()
        elif time - self.start[1] <= window:
            self.count += 1
            self.end_frame = frame
        else:
            self.complete = True


@dataclass
class _GooseStream:
    label: str
    findings: _Findings = field(default_factory=_Findings)
    storm: _GooseStorm = field(default_factory=_GooseStorm)
    previous: tuple[int, int, float, int] | None = None
    packets: int = 0
    st_changes: int = 0
    sq_max: int = 0
    nds_seen: bool = False
    sim_seen: bool = False

    def add(self, row: dict[str, str]) -> None:
        frame = _int(row["frame.number"])
        time = _float(row["frame.time_epoch"])
        st = _int(row["goose.stNum"])
        sq = _int(row["goose.sqNum"])
        self.packets += 1
        self.sq_max = max(self.sq_max, sq)
        self.nds_seen |= _truthy(row["goose.ndsCom"])
        self.sim_seen |= _truthy(row["goose.simulation"])

        if self.previous is not None:
            pst, psq, pt, ptal = self.previous
            if st == pst and sq - psq > 1:
                self.findings.add(
                    "FAIL", frame, f"sqNum gap @frame {frame}: {psq}->{sq} ({sq - psq - 1} missed)"
                )
            if st < pst and pst - st < 2**31:
                self.findings.add("FAIL", frame, f"stNum regression @frame {frame}: {pst}->{st}")
            if st > pst:
                self.st_changes += 1
                self.storm.add(frame, time)
            gap_ms = (time - pt) * 1000
            if ptal > 0 and gap_ms > ptal:
                self.findings.add(
                    "FAIL",
                    frame,
                    f"TTL violation @frame {frame}: gap {gap_ms:.1f} ms > timeAllowedtoLive {ptal} ms",
                )

        self.previous = st, sq, time, _int(row["goose.timeAllowedtoLive"])

    def report(self, stream_id: str) -> StreamReport:
        if self.storm.start is not None:
            frame, _ = self.storm.start
            self.findings.add(
                "WARN",
                frame,
                f"storm: {self.storm.count} stNum changes within {STORM_WINDOW_MS} ms "
                f"@frames {frame}-{self.storm.end_frame}",
            )
        if self.nds_seen:
            self.findings.add("WARN", None, "ndsCom set (publisher needs commissioning)")
        if self.sim_seen:
            self.findings.add("WARN", None, "simulation flag set (simulated data on the wire)")

        return self.findings.report(
            stream_id,
            self.label,
            {
                "stNum changes": str(self.st_changes),
                "sqNum max": str(self.sq_max),
                "pkts": str(self.packets),
            },
        )


_SMPSYNCH = {0: "none", 1: "local", 2: "global"}


def _sv_asdus(row: dict[str, str]) -> Iterator[dict[str, str]]:
    if "," not in row["sv.smpCnt"]:
        yield row
        return

    counts = row["sv.smpCnt"].split(",")
    columns = {key: value.split(",") for key, value in row.items() if key.startswith("sv.")}
    same_stream = len(set(columns["sv.svID"])) == 1
    for index in range(len(counts)):
        asdu = row.copy()
        for key, parts in columns.items():
            if len(parts) == len(counts):
                asdu[key] = parts[index]
            elif key in {"sv.smpRate", "sv.smpMod"} and not (same_stream and len(set(parts)) == 1):
                # tshark omits empty optional occurrences, so their positions can be ambiguous.
                asdu[key] = "?"
        yield asdu


def _sv_modulus(row: dict[str, str]) -> int | None:
    rate = _int(row.get("sv.smpRate", ""))
    if not 0 < rate < SV_COUNTER_MODULUS:
        return None
    mode = row.get("sv.smpMod", "")
    # IEC 61850-9-2 Table 14 leaves resets to the SV profile. Use a one-second
    # cycle for samples/second and the common 9-2LE rates sent without a mode.
    if mode == "1" or (not mode and rate in LEGACY_SV_RATES):
        return rate
    return None


@dataclass
class _SVStream:
    label: str
    first_confrev: str
    findings: _Findings = field(default_factory=_Findings)
    previous_count: int | None = None
    previous_confrev: int | None = None
    modulus: int | None = None
    asdus: int = 0
    max_count: int = 0
    synch: int = 0
    ever_synced: bool = False

    def add(self, row: dict[str, str]) -> None:
        frame = _int(row["frame.number"])
        cnt = _int(row["sv.smpCnt"], default=-1)
        synch = _int(row["sv.smpSynch"])
        confrev = _int(row["sv.confRev"])
        changed = self.previous_confrev is not None and self.previous_confrev != confrev
        if changed:
            self.modulus = None
        self.modulus = _sv_modulus(row) or self.modulus

        self.add_count(frame, cnt)
        if self.synch in (1, 2) and synch == 0:
            self.findings.add(
                "FAIL", frame, f"loss of sync @frame {frame}: smpSynch {self.synch}->0"
            )
        if changed:
            self.findings.add(
                "WARN",
                frame,
                f"confRev change @frame {frame}: {self.previous_confrev}->{confrev} (dataset redefined)",
            )
        self.asdus += 1
        self.previous_confrev = confrev
        self.synch = synch
        self.ever_synced |= synch != 0

    def add_count(self, frame: int, cnt: int) -> None:
        limit = self.modulus or SV_COUNTER_MODULUS
        if not 0 <= cnt < limit:
            value = str(cnt) if cnt >= 0 else "missing or invalid"
            self.findings.add(
                "FAIL",
                frame,
                f"smpCnt out of range @frame {frame}: {value} (expected 0 to {limit - 1})",
            )
            return

        prev = self.previous_count
        self.previous_count = cnt
        self.max_count = max(self.max_count, cnt)
        if prev is None or prev >= limit:
            return
        if cnt == (prev + 1) % limit or (self.modulus is None and cnt == 0 and prev > 0):
            return

        if cnt == prev:
            detail = "duplicate counter"
        elif self.modulus is not None:
            detail = f"~{(cnt - prev - 1) % limit} dropped"
        elif cnt > prev:
            detail = f"~{cnt - prev - 1} dropped"
        else:
            detail = "drop count unknown without sample rate"
        self.findings.add(
            "FAIL", frame, f"smpCnt discontinuity @frame {frame}: {prev}->{cnt} ({detail})"
        )

    def report(self, stream_id: str) -> StreamReport:
        if not self.ever_synced:
            self.findings.add("WARN", None, "smpSynch=0 throughout (samples not time-synchronized)")
        return self.findings.report(
            stream_id,
            self.label,
            {
                "smpCnt max": str(self.max_count),
                "smpSynch": f"{self.synch} ({_SMPSYNCH.get(self.synch, '?')})",
                "confRev": self.first_confrev,
                "ASDUs": str(self.asdus),
            },
        )


@dataclass
class _MMSStream:
    first_source: str
    findings: _Findings = field(default_factory=_Findings)
    pending: dict[tuple[str, str, int], deque[tuple[int, float]]] = field(
        default_factory=lambda: defaultdict(deque)
    )
    label: str = ""
    requests: int = 0
    responses: int = 0
    errors: int = 0
    max_rt_ms: float = 0.0

    def add(self, row: dict[str, str]) -> None:
        frame = _int(row["frame.number"])
        time = _float(row["frame.time_epoch"])
        kind = row.get("mms.kind", "")
        invoke_text = row.get("mms.invokeID", "") or row.get("mms.originalInvokeID", "")
        invoke = _int(invoke_text, default=-1)
        if kind == "req":
            self.requests += 1
            if not self.label:
                self.label = f"{row['ip.src']} -> {row['ip.dst']}"
            if invoke < 0:
                self.findings.add(
                    "WARN", frame, f"unpaired request @frame {frame}: missing invokeID"
                )
            else:
                self.pending[(row["ip.src"], row.get("tcp.srcport", ""), invoke)].append(
                    (frame, time)
                )
            return

        key = (row["ip.dst"], row.get("tcp.dstport", ""), invoke)
        queue = self.pending.get(key)
        req_time = None
        if queue and kind in {"resp", "error", "reject"}:
            _, req_time = queue.popleft()
            if not queue:
                del self.pending[key]

        if kind == "resp":
            self.responses += 1
            if req_time is not None:
                rt_ms = (time - req_time) * 1000
                self.max_rt_ms = max(self.max_rt_ms, rt_ms)
                if rt_ms > MMS_SLOW_MS:
                    self.findings.add(
                        "WARN",
                        frame,
                        f"slow response @frame {frame}: invokeID {invoke} took {rt_ms:.0f} ms",
                    )
        elif kind in {"error", "reject", "cancel error"}:
            self.errors += 1
            if kind == "reject":
                detail = f"reason={row.get('mms.rejectReason') or 'unknown'}"
            else:
                detail = f"errorClass={row.get('mms.errorClass') or 'unknown'}"
            identifier = str(invoke) if invoke >= 0 else "missing"
            self.findings.add(
                "FAIL", frame, f"{kind} PDU @frame {frame}: invokeID {identifier} ({detail})"
            )

    def report(self, stream_id: str) -> StreamReport:
        for (_, _, invoke), queue in self.pending.items():
            for frame, _ in queue:
                self.findings.add(
                    "WARN",
                    frame,
                    f"unpaired request @frame {frame}: invokeID {invoke} (no response)",
                )

        return self.findings.report(
            f"tcp.stream {stream_id}",
            self.label or self.first_source,
            {
                "requests": str(self.requests),
                "responses": str(self.responses),
                "errors": str(self.errors),
                "max resp ms": f"{self.max_rt_ms:.0f}",
            },
        )


_Stream = _GooseStream | _SVStream | _MMSStream
_STREAM_TYPES: dict[str, tuple[str, Callable[[dict[str, str]], _Stream]]] = {
    "goose": ("goose.gocbRef", lambda row: _GooseStream(f"dst {row['eth.dst']}")),
    "sv": ("sv.svID", lambda row: _SVStream(f"dst {row['eth.dst']}", row["sv.confRev"])),
    "mms": ("tcp.stream", lambda row: _MMSStream(row["ip.src"])),
}


class CaptureAnalysis:
    def __init__(self, protocol: str) -> None:
        self.group_field, self.make_stream = _STREAM_TYPES[protocol]
        self.streams: dict[str, _Stream] = {}
        self.packets_scanned = 0

    def add_frame(self, rows: Iterable[dict[str, str]]) -> None:
        self.packets_scanned += 1
        for row in rows:
            stream_id = row.get(self.group_field, "")
            stream = self.streams.get(stream_id)
            if stream is None:
                stream = self.streams[stream_id] = self.make_stream(row)
            stream.add(row)

    def add_field_frame(self, row: dict[str, str]) -> None:
        self.add_frame(_sv_asdus(row) if self.group_field == "sv.svID" else (row,))

    def finish(self) -> ProtocolReport:
        streams = [stream.report(stream_id) for stream_id, stream in self.streams.items()]
        return ProtocolReport(len(streams), self.packets_scanned, streams)


def _analyze_rows(protocol: str, rows: Iterable[dict[str, str]]) -> ProtocolReport:
    analysis = CaptureAnalysis(protocol)
    for row in rows:
        analysis.add_field_frame(row)
    return analysis.finish()


def analyze_goose(rows: Iterable[dict[str, str]]) -> ProtocolReport:
    return _analyze_rows("goose", rows)


def analyze_sv(rows: Iterable[dict[str, str]]) -> ProtocolReport:
    return _analyze_rows("sv", rows)


def analyze_mms(rows: Iterable[dict[str, str]]) -> ProtocolReport:
    return _analyze_rows("mms", rows)


def format_report(protocol: str, file_path: str, report: ProtocolReport) -> str:
    """Render a ProtocolReport as a compact, worst-first text report."""
    lines = [
        f"=== IEC 61850 {protocol.upper()} health: {file_path} ===",
        f"Streams analyzed: {report.streams_analyzed} | packets scanned: {report.packets_scanned:,}",
        "",
    ]

    ordered = sorted(
        report.streams, key=lambda s: (SEVERITY_ORDER.get(s.verdict, 3), -s.total_anomalies)
    )
    shown = ordered[:MAX_STREAMS_SHOWN]

    for stream in shown:
        lines.append(f"[{stream.verdict}] {stream.stream_id}   ({stream.label})")
        lines.append("  " + " | ".join(f"{k}: {v}" for k, v in stream.metrics.items()))
        if stream.verdict != "OK":
            for anomaly in stream.anomalies[:MAX_ANOMALIES_PER_STREAM]:
                lines.append(f"  • {anomaly.message}")
            extra = stream.total_anomalies - MAX_ANOMALIES_PER_STREAM
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
