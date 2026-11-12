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
)


# --------------------------------------------------------------------------- #
# Task 1 — scaffolding + TSV parser
# --------------------------------------------------------------------------- #
def test_field_sets_cover_goose_and_sv() -> None:
    assert set(FIELD_SETS) == {"goose", "sv"}
    assert set(BASE_FILTERS) == {"goose", "sv", "mms"}
    assert "goose.stNum" in FIELD_SETS["goose"]
    assert "goose.sqNum" in FIELD_SETS["goose"]
    assert "goose.timeAllowedtoLive" in FIELD_SETS["goose"]


# --------------------------------------------------------------------------- #
# Task 2 — GOOSE analyzer
# --------------------------------------------------------------------------- #
def _goose(frame, t, st, sq, *, tal="2000", nds="0", sim="0", gocb="IED1/LLN0$GO$g"):
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
def _sv(frame, cnt, *, synch="2", confrev="1", svid="SV01", smprate="4000"):
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


def test_sv_missing_sample_at_rollover_uses_sample_rate() -> None:
    rows = [_sv(1, 3997), _sv(2, 3998), _sv(3, 0), _sv(4, 1)]
    report = analyze_sv(rows).streams[0]
    assert report.verdict == "FAIL"
    assert "3998->0 (~1 dropped)" in report.anomalies[0].message


def test_sv_corrupt_counter_does_not_change_rollover_modulus() -> None:
    rows = [_sv(1, 50000), _sv(2, 3998), _sv(3, 0)]
    report = analyze_sv(rows).streams[0]
    assert "out of range" in report.anomalies[0].message
    assert "3998->0 (~1 dropped)" in report.anomalies[1].message


def test_sv_rate_in_samples_per_second_sets_rollover() -> None:
    rows = [
        dict(_sv(i, count, smprate="14400"), **{"sv.smpMod": "1"})
        for i, count in enumerate((14398, 0), 1)
    ]
    report = analyze_sv(rows).streams[0]
    assert "14398->0 (~1 dropped)" in report.anomalies[0].message


def test_sv_rate_in_samples_per_period_is_not_a_counter_limit() -> None:
    rows = [
        dict(_sv(i, count, smprate="80"), **{"sv.smpMod": "0"})
        for i, count in enumerate((4798, 4799, 0), 1)
    ]
    assert analyze_sv(rows).streams[0].verdict == "OK"


def test_sv_counts_omitted_anomalies_without_retaining_them() -> None:
    rows = (_sv(i, i * 2) for i in range(1, 102))
    report = analyze_sv(rows)
    assert report.packets_scanned == 101
    assert len(report.streams[0].anomalies) == 10
    assert "90 more anomalies" in format_report("sv", "test.pcap", report)


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


def test_sv_multi_asdu_frame_expanded_per_asdu() -> None:
    # tshark -T fields joins multi-occurrence values with commas: a healthy
    # 2-ASDU frame yields sv.smpCnt "0,1". Must expand to one row per ASDU,
    # not parse as garbage.
    rows = [
        {
            "frame.number": str(frame),
            "frame.time_epoch": str(frame * 0.0005),
            "eth.dst": "01:0c:cd:04:00:01",
            "sv.svID": "MU01,MU01",
            "sv.smpCnt": f"{2 * i},{2 * i + 1}",
            "sv.smpSynch": "2,2",
            "sv.confRev": "1,1",
            "sv.smpRate": "4000,4000",
        }
        for i, frame in enumerate(range(1, 5))
    ]
    rep = analyze_sv(rows)
    assert rep.streams_analyzed == 1
    s = rep.streams[0]
    assert s.stream_id == "MU01"
    assert s.verdict == "OK"
    assert s.metrics["smpCnt max"] == "7"
    assert s.metrics["ASDUs"] == "8"  # 4 frames x 2 ASDUs
    assert rep.packets_scanned == 4  # frames, not ASDUs


def test_sv_multi_asdu_dropout_detected() -> None:
    # smpCnt pairs (0,1) then (6,7): samples 2-5 lost inside a multi-ASDU stream.
    def frame(n: int, c0: int) -> dict[str, str]:
        return {
            "frame.number": str(n),
            "frame.time_epoch": str(n * 0.0005),
            "eth.dst": "01:0c:cd:04:00:01",
            "sv.svID": "MU01,MU01",
            "sv.smpCnt": f"{c0},{c0 + 1}",
            "sv.smpSynch": "2,2",
            "sv.confRev": "1,1",
            "sv.smpRate": "4000,4000",
        }

    rep = analyze_sv([frame(1, 0), frame(2, 6)])
    s = rep.streams[0]
    assert s.verdict == "FAIL"
    assert any("discontinuity" in a.message for a in s.anomalies)


# --------------------------------------------------------------------------- #
# Task 4 — MMS analyzer
# --------------------------------------------------------------------------- #
def _mms(frame, t, *, invoke="", kind="", stream="0", src="10.0.0.5", dst="10.0.0.9"):
    if kind in {"resp", "error", "reject"}:
        src, dst = dst, src
    row = {
        "frame.number": str(frame),
        "frame.time_epoch": str(t),
        "tcp.stream": stream,
        "ip.src": src,
        "ip.dst": dst,
        "mms.invokeID": invoke,
        "mms.originalInvokeID": "",
        "mms.kind": kind,
        "mms.errorClass": "",
        "mms.rejectReason": "",
    }
    if kind == "error":
        row["mms.errorClass"] = "3"
        row["mms.originalInvokeID"] = invoke
    elif kind == "reject":
        row["mms.invokeID"] = ""
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
    report = rep.streams[0]
    assert report.verdict == "FAIL"
    assert len(report.anomalies) == 1
    assert "invokeID 3" in report.anomalies[0].message


def test_mms_zero_invoke_id_takes_precedence_over_original_id() -> None:
    error = _mms(2, 0.05, invoke="0", kind="error")
    error["mms.originalInvokeID"] = "7"
    rows = [_mms(1, 0.0, invoke="0", kind="req"), error]
    report = analyze_mms(rows).streams[0]
    assert len(report.anomalies) == 1
    assert "invokeID 0" in report.anomalies[0].message


def test_mms_missing_id_does_not_pair_with_zero() -> None:
    rows = [
        _mms(1, 0.0, kind="req"),
        _mms(2, 1.0, invoke="0", kind="req"),
        _mms(3, 1.05, invoke="0", kind="resp"),
    ]
    report = analyze_mms(rows).streams[0]
    assert report.metrics["max resp ms"] == "50"
    assert len(report.anomalies) == 1
    assert "missing invokeID" in report.anomalies[0].message


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


def test_mms_pairs_same_id_independently_in_each_direction() -> None:
    request = _mms(1, 0.0, invoke="0", kind="req")
    reverse_request = _mms(
        2, 1.0, invoke="0", kind="req", src=request["ip.dst"], dst=request["ip.src"]
    )
    response = _mms(3, 1.05, invoke="0", kind="resp", src=request["ip.dst"], dst=request["ip.src"])
    report = analyze_mms([request, reverse_request, response]).streams[0]
    assert report.metrics["max resp ms"] == "50"
    assert [anomaly.frame for anomaly in report.anomalies] == [1]


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
