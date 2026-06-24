"""Unit tests for the pure IEC 61850 analysis module (no tshark)."""

from mcp_wireshark.iec61850 import (
    BASE_FILTERS,
    FIELD_SETS,
    MAX_STREAMS_SHOWN,
    Anomaly,
    ProtocolReport,
    StreamReport,
    analyze_goose,
    analyze_mms,
    analyze_sv,
    format_report,
    parse_field_rows,
)


# --------------------------------------------------------------------------- #
# Task 1 — scaffolding + TSV parser
# --------------------------------------------------------------------------- #
def test_field_sets_cover_three_protocols() -> None:
    assert set(FIELD_SETS) == {"goose", "sv", "mms"}
    assert set(BASE_FILTERS) == {"goose", "sv", "mms"}
    assert "goose.stNum" in FIELD_SETS["goose"]
    assert "goose.sqNum" in FIELD_SETS["goose"]
    assert "goose.timeAllowedtoLive" in FIELD_SETS["goose"]


def test_parse_field_rows_skips_header_and_keys_by_columns() -> None:
    cols = ["frame.number", "goose.stNum", "goose.sqNum"]
    tsv = "frame.number\tgoose.stNum\tgoose.sqNum\n1\t5\t0\n2\t5\t1\n"
    rows = parse_field_rows(tsv, cols)
    assert rows == [
        {"frame.number": "1", "goose.stNum": "5", "goose.sqNum": "0"},
        {"frame.number": "2", "goose.stNum": "5", "goose.sqNum": "1"},
    ]


def test_parse_field_rows_pads_short_rows_and_ignores_blank_lines() -> None:
    cols = ["a", "b", "c"]
    tsv = "a\tb\tc\nx\ty\n\n"  # second row missing 'c', trailing blank
    rows = parse_field_rows(tsv, cols)
    assert rows == [{"a": "x", "b": "y", "c": ""}]


def test_parse_field_rows_empty_input() -> None:
    assert parse_field_rows("", ["a"]) == []


# --------------------------------------------------------------------------- #
# Task 2 — GOOSE analyzer
# --------------------------------------------------------------------------- #
def _goose(frame, t, st, sq, tal="2000", nds="0", sim="0", gocb="IED1/LLN0$GO$g"):
    return {
        "frame.number": str(frame),
        "frame.time_epoch": str(t),
        "eth.dst": "01:0c:cd:01:00:01",
        "goose.gocbRef": gocb,
        "goose.stNum": str(st),
        "goose.sqNum": str(sq),
        "goose.timeAllowedtoLive": str(tal),
        "goose.ndsCom": nds,
        "goose.simulation": sim,
    }


def test_goose_clean_stream_is_ok() -> None:
    rows = [_goose(1, 0.0, 1, 0), _goose(2, 0.5, 1, 1), _goose(3, 1.0, 1, 2)]
    rep = analyze_goose(rows)
    assert rep.streams_analyzed == 1
    s = rep.streams[0]
    assert s.verdict == "OK"
    assert s.anomalies == []


def test_goose_sqnum_reset_on_state_change_not_flagged() -> None:
    rows = [_goose(1, 0.0, 1, 5), _goose(2, 0.5, 2, 0), _goose(3, 1.0, 2, 1)]
    rep = analyze_goose(rows)
    assert rep.streams[0].verdict == "OK"


def test_goose_sqnum_gap_is_fail() -> None:
    rows = [_goose(1, 0.0, 1, 47), _goose(2, 0.5, 1, 51)]  # 48,49,50 missing
    rep = analyze_goose(rows)
    s = rep.streams[0]
    assert s.verdict == "FAIL"
    assert any("sqNum gap" in a.message and "3 missed" in a.message for a in s.anomalies)


def test_goose_ttl_violation_is_fail() -> None:
    rows = [_goose(1, 0.0, 1, 0, tal="2000"), _goose(2, 3.0, 1, 1, tal="2000")]
    rep = analyze_goose(rows)
    s = rep.streams[0]
    assert s.verdict == "FAIL"
    assert any("TTL violation" in a.message for a in s.anomalies)


def test_goose_storm_is_warn() -> None:
    rows = [
        _goose(1, 0.000, 1, 0),
        _goose(2, 0.004, 2, 0),
        _goose(3, 0.008, 3, 0),
        _goose(4, 0.012, 4, 0),
    ]
    rep = analyze_goose(rows)
    s = rep.streams[0]
    assert any(a.severity == "WARN" and "storm" in a.message for a in s.anomalies)


def test_goose_ndscom_is_warn() -> None:
    rows = [_goose(1, 0.0, 1, 0, nds="1"), _goose(2, 0.5, 1, 1, nds="1")]
    rep = analyze_goose(rows)
    assert rep.streams[0].verdict == "WARN"
    assert any("ndsCom" in a.message for a in rep.streams[0].anomalies)


# --------------------------------------------------------------------------- #
# Task 3 — SV analyzer
# --------------------------------------------------------------------------- #
def _sv(frame, cnt, synch="2", confrev="1", svid="SV01", smprate="4000"):
    return {
        "frame.number": str(frame),
        "frame.time_epoch": str(frame * 0.00025),
        "eth.dst": "01:0c:cd:04:00:01",
        "sv.svID": svid,
        "sv.smpCnt": str(cnt),
        "sv.smpSynch": str(synch),
        "sv.confRev": str(confrev),
        "sv.smpRate": str(smprate),
    }


def test_sv_clean_increment_is_ok() -> None:
    rows = [_sv(i, i - 1) for i in range(1, 11)]  # smpCnt 0..9
    rep = analyze_sv(rows)
    assert rep.streams[0].verdict == "OK"


def test_sv_rollover_not_flagged() -> None:
    rows = [_sv(1, 3998), _sv(2, 3999), _sv(3, 0), _sv(4, 1)]
    rep = analyze_sv(rows)
    assert rep.streams[0].verdict == "OK"


def test_sv_smpcnt_discontinuity_is_fail() -> None:
    rows = [_sv(1, 10), _sv(2, 20)]  # 9 dropped
    rep = analyze_sv(rows)
    s = rep.streams[0]
    assert s.verdict == "FAIL"
    assert any("discontinuity" in a.message for a in s.anomalies)


def test_sv_loss_of_sync_is_fail() -> None:
    rows = [_sv(1, 0, synch="2"), _sv(2, 1, synch="0")]
    rep = analyze_sv(rows)
    s = rep.streams[0]
    assert s.verdict == "FAIL"
    assert any("sync" in a.message.lower() for a in s.anomalies)


def test_sv_unsynced_throughout_is_warn() -> None:
    rows = [_sv(1, 0, synch="0"), _sv(2, 1, synch="0"), _sv(3, 2, synch="0")]
    rep = analyze_sv(rows)
    assert rep.streams[0].verdict == "WARN"


def test_sv_confrev_change_is_warn() -> None:
    rows = [_sv(1, 0, confrev="1"), _sv(2, 1, confrev="2")]
    rep = analyze_sv(rows)
    s = rep.streams[0]
    assert s.verdict == "WARN"
    assert any("confRev" in a.message for a in s.anomalies)


# --------------------------------------------------------------------------- #
# Task 4 — MMS analyzer
# --------------------------------------------------------------------------- #
def _mms(frame, t, invoke="", kind="", stream="0", src="10.0.0.5", dst="10.0.0.9"):
    row = {
        "frame.number": str(frame),
        "frame.time_epoch": str(t),
        "tcp.stream": stream,
        "ip.src": src,
        "ip.dst": dst,
        "mms.invokeID": invoke,
        "mms.originalInvokeID": "",
        "mms.confirmedServiceRequest": "",
        "mms.confirmedServiceResponse": "",
        "mms.errorClass": "",
        "mms.rejectReason": "",
    }
    if kind == "req":
        row["mms.confirmedServiceRequest"] = "5"
    elif kind == "resp":
        row["mms.confirmedServiceResponse"] = "5"
    elif kind == "error":
        row["mms.errorClass"] = "3"
        row["mms.originalInvokeID"] = invoke
    elif kind == "reject":
        row["mms.rejectReason"] = "1"
        row["mms.originalInvokeID"] = invoke
    return row


def test_mms_clean_pair_is_ok() -> None:
    rows = [_mms(1, 0.0, invoke="1", kind="req"), _mms(2, 0.05, invoke="1", kind="resp")]
    rep = analyze_mms(rows)
    assert rep.streams[0].verdict == "OK"


def test_mms_error_pdu_is_fail() -> None:
    rows = [_mms(1, 0.0, invoke="2", kind="req"), _mms(2, 0.05, invoke="2", kind="error")]
    rep = analyze_mms(rows)
    s = rep.streams[0]
    assert s.verdict == "FAIL"
    assert any("error" in a.message.lower() for a in s.anomalies)


def test_mms_reject_is_fail() -> None:
    rows = [_mms(1, 0.0, invoke="3", kind="req"), _mms(2, 0.01, invoke="3", kind="reject")]
    rep = analyze_mms(rows)
    assert rep.streams[0].verdict == "FAIL"


def test_mms_unpaired_request_is_warn() -> None:
    rows = [_mms(1, 0.0, invoke="9", kind="req")]
    rep = analyze_mms(rows)
    s = rep.streams[0]
    assert s.verdict == "WARN"
    assert any("unpaired" in a.message.lower() for a in s.anomalies)


def test_mms_slow_response_is_warn() -> None:
    rows = [_mms(1, 0.0, invoke="4", kind="req"), _mms(2, 2.0, invoke="4", kind="resp")]
    rep = analyze_mms(rows)
    s = rep.streams[0]
    assert s.verdict == "WARN"
    assert any("slow response" in a.message for a in s.anomalies)


# --------------------------------------------------------------------------- #
# Task 5 — formatter
# --------------------------------------------------------------------------- #
def _stream(sid, verdict, n_anom=0):
    anomalies = [Anomaly("FAIL", i, f"issue {i}") for i in range(n_anom)]
    return StreamReport(sid, f"label-{sid}", verdict, {"pkts": "10"}, anomalies)


def test_format_report_orders_worst_first() -> None:
    rep = ProtocolReport(
        3, 30, [_stream("a", "OK"), _stream("b", "FAIL", 1), _stream("c", "WARN", 1)]
    )
    text = format_report("goose", "f.pcap", rep)
    assert text.index("[FAIL]") < text.index("[WARN]") < text.index("[OK]")
    assert "=== IEC 61850 GOOSE health: f.pcap ===" in text
    assert "Streams analyzed: 3" in text


def test_format_report_ok_block_has_no_bullets() -> None:
    rep = ProtocolReport(1, 10, [_stream("a", "OK")])
    text = format_report("sv", "f.pcap", rep)
    assert "[OK]" in text
    assert "•" not in text


def test_format_report_caps_anomalies() -> None:
    rep = ProtocolReport(1, 100, [_stream("a", "FAIL", n_anom=15)])
    text = format_report("mms", "f.pcap", rep)
    assert "more anomalies" in text
    assert text.count("•") == 11  # 10 anomalies + 1 "more" line


def test_format_report_caps_streams() -> None:
    streams = [_stream(f"s{i}", "FAIL", 1) for i in range(MAX_STREAMS_SHOWN + 5)]
    rep = ProtocolReport(len(streams), 999, streams)
    text = format_report("goose", "f.pcap", rep)
    assert "more stream(s) truncated" in text
    assert text.count("[FAIL]") == MAX_STREAMS_SHOWN
