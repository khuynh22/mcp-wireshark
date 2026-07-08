"""Generate synthetic IEC 61850 test captures for analyze_iec61850 functional testing.

Writes classic little-endian pcap files containing hand-crafted GOOSE (Ethertype
0x88B8) and Sampled Values (Ethertype 0x88BA) frames with known, deterministic
faults injected. Each output file exercises exactly one detection path of the
analyze_iec61850 tool, so expected verdicts are unambiguous.

Usage:
    python scripts/make_iec61850_test_pcaps.py [output_dir]   # default: testdata/

Requires only the Python standard library. Verify dissection with:
    tshark -r testdata/goose_clean.pcap -T fields -e goose.stNum -e goose.sqNum
"""

from __future__ import annotations

import struct
import sys
from pathlib import Path

# --------------------------------------------------------------------------- #
# pcap container (classic format, microsecond resolution, LINKTYPE_ETHERNET)
# --------------------------------------------------------------------------- #

PCAP_GLOBAL_HEADER = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)


def write_pcap(path: Path, frames: list[tuple[float, bytes]]) -> None:
    """Write (timestamp, frame bytes) pairs as a classic pcap file."""
    with path.open("wb") as f:
        f.write(PCAP_GLOBAL_HEADER)
        for ts, data in frames:
            padded = data + b"\x00" * max(0, 60 - len(data))  # Ethernet minimum size
            sec = int(ts)
            usec = round((ts - sec) * 1_000_000)
            f.write(struct.pack("<IIII", sec, usec, len(padded), len(padded)))
            f.write(padded)


# --------------------------------------------------------------------------- #
# Minimal BER encoding helpers
# --------------------------------------------------------------------------- #


def ber_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + ber_len(len(value)) + value


def ber_uint(value: int) -> bytes:
    """Minimal-length two's-complement encoding of a non-negative INTEGER."""
    body = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
    if body[0] & 0x80:
        body = b"\x00" + body
    return body


# --------------------------------------------------------------------------- #
# GOOSE frame builder
# --------------------------------------------------------------------------- #

GOOSE_DST = bytes.fromhex("010ccd010001")
GOOSE_SRC = bytes.fromhex("0030a7112233")
GOOSE_ETHERTYPE = b"\x88\xb8"


def goose_frame(
    st_num: int,
    sq_num: int,
    tal_ms: int = 2000,
    gocb: str = "IED1PROT/LLN0$GO$gcb01",
    ndscom: bool = False,
    simulation: bool = False,
    t_epoch: float = 0.0,
    appid: int = 0x0001,
) -> bytes:
    secs = int(t_epoch)
    frac = int((t_epoch - secs) * (1 << 24))
    utc_time = struct.pack(">I", secs) + frac.to_bytes(3, "big") + b"\x0a"

    pdu_fields = b"".join(
        [
            tlv(0x80, gocb.encode()),  # [0] gocbRef
            tlv(0x81, ber_uint(tal_ms)),  # [1] timeAllowedtoLive
            tlv(0x82, (gocb + "$ds").encode()),  # [2] datSet
            tlv(0x83, b"goID1"),  # [3] goID
            tlv(0x84, utc_time),  # [4] t (UtcTime)
            tlv(0x85, ber_uint(st_num)),  # [5] stNum
            tlv(0x86, ber_uint(sq_num)),  # [6] sqNum
            tlv(0x87, b"\xff" if simulation else b"\x00"),  # [7] simulation
            tlv(0x88, ber_uint(1)),  # [8] confRev
            tlv(0x89, b"\xff" if ndscom else b"\x00"),  # [9] ndsCom
            tlv(0x8A, ber_uint(1)),  # [10] numDatSetEntries
            tlv(0xAB, tlv(0x83, b"\x00")),  # [11] allData: one boolean
        ]
    )
    apdu = tlv(0x61, pdu_fields)
    payload = struct.pack(">HHHH", appid, len(apdu) + 8, 0, 0) + apdu
    return GOOSE_DST + GOOSE_SRC + GOOSE_ETHERTYPE + payload


# --------------------------------------------------------------------------- #
# Sampled Values frame builder (IEC 61850-9-2 / 9-2LE shape)
# --------------------------------------------------------------------------- #

SV_DST = bytes.fromhex("010ccd040001")
SV_SRC = bytes.fromhex("0030a7445566")
SV_ETHERTYPE = b"\x88\xba"


def sv_asdu(
    smp_cnt: int,
    sv_id: str = "MU01",
    conf_rev: int = 1,
    smp_synch: int = 2,
    smp_rate: int | None = 4000,
) -> bytes:
    fields = [
        tlv(0x80, sv_id.encode()),  # [0] svID
        tlv(0x82, struct.pack(">H", smp_cnt)),  # [2] smpCnt (2-byte)
        tlv(0x83, struct.pack(">I", conf_rev)),  # [3] confRev (4-byte)
        tlv(0x85, bytes([smp_synch])),  # [5] smpSynch (1-byte)
    ]
    if smp_rate is not None:
        fields.append(tlv(0x86, struct.pack(">H", smp_rate)))  # [6] smpRate
    fields.append(tlv(0x87, b"\x00" * 64))  # [7] sample: 8 x (int32 + quality)
    return tlv(0x30, b"".join(fields))


def sv_frame(asdus: list[bytes], appid: int = 0x4000) -> bytes:
    sav_pdu = tlv(
        0x60,
        tlv(0x80, ber_uint(len(asdus))) + tlv(0xA2, b"".join(asdus)),  # noASDU + seqOfASDU
    )
    payload = struct.pack(">HHHH", appid, len(sav_pdu) + 8, 0, 0) + sav_pdu
    return SV_DST + SV_SRC + SV_ETHERTYPE + payload


# --------------------------------------------------------------------------- #
# Scenario definitions — one injected fault per file
# --------------------------------------------------------------------------- #


def goose_steady(
    n: int,
    start_t: float = 100.0,
    st: int = 1,
    sq0: int = 0,
    interval: float = 1.0,
    tal: int = 2000,
    gocb: str = "IED1PROT/LLN0$GO$gcb01",
    ndscom: bool = False,
    simulation: bool = False,
) -> list[tuple[float, bytes]]:
    """n retransmissions of the same state: sqNum increments, stNum fixed."""
    return [
        (
            start_t + i * interval,
            goose_frame(st, sq0 + i, tal_ms=tal, gocb=gocb, ndscom=ndscom, simulation=simulation),
        )
        for i in range(n)
    ]


def build_scenarios() -> dict[str, list[tuple[float, bytes]]]:
    s: dict[str, list[tuple[float, bytes]]] = {}

    # -- GOOSE ----------------------------------------------------------------
    # Clean: 10 steady retransmits, then a state change with sqNum reset to 0.
    clean = goose_steady(10)
    clean += [
        (110.0, goose_frame(2, 0)),
        (110.5, goose_frame(2, 1)),
        (111.5, goose_frame(2, 2)),
    ]
    s["goose_clean"] = clean

    # sqNum gap: 47 -> 51 with stNum constant (3 messages lost).
    gap = goose_steady(3, sq0=45)  # 45,46,47
    gap += [(103.0, goose_frame(1, 51)), (104.0, goose_frame(1, 52))]
    s["goose_sqnum_gap"] = gap

    # stNum regression: 5 -> 3 (device reboot / spoof indicator).
    reg = goose_steady(3, st=5)
    reg += [(103.0, goose_frame(3, 0)), (104.0, goose_frame(3, 1))]
    s["goose_stnum_regression"] = reg

    # TTL violation: TAL=2000 ms but 5 s of silence between retransmits.
    ttl = [
        (100.0, goose_frame(1, 0)),
        (101.0, goose_frame(1, 1)),
        (106.0, goose_frame(1, 2)),  # 5000 ms gap > 2000 ms TAL
        (107.0, goose_frame(1, 3)),
    ]
    s["goose_ttl_violation"] = ttl

    # Storm: 4 state changes within 15 ms (chattering relay).
    storm = [
        (100.000, goose_frame(1, 0)),
        (100.005, goose_frame(2, 0)),
        (100.010, goose_frame(3, 0)),
        (100.015, goose_frame(4, 0)),
        (100.515, goose_frame(4, 1)),
    ]
    s["goose_storm"] = storm

    # Flags: ndsCom + simulation set throughout.
    s["goose_flags"] = goose_steady(4, ndscom=True, simulation=True)

    # Two publishers: gcb01 clean, gcb02 has a sqNum gap. Tests grouping +
    # worst-first ordering in one capture.
    multi = goose_steady(5, gocb="IED1PROT/LLN0$GO$gcb01")
    bad = goose_steady(2, start_t=100.2, sq0=10, gocb="IED2PROT/LLN0$GO$gcb02", tal=5000)
    bad += [(102.2, goose_frame(1, 20, tal_ms=5000, gocb="IED2PROT/LLN0$GO$gcb02"))]
    s["goose_multistream"] = sorted(multi + bad, key=lambda fr: fr[0])

    # -- Sampled Values ---------------------------------------------------------
    t0 = 200.0
    dt = 0.00025  # 4000 samples/s

    # Clean: smpCnt 3990..3999 then rollover to 0..9, synced throughout.
    counts = list(range(3990, 4000)) + list(range(10))
    s["sv_clean"] = [(t0 + i * dt, sv_frame([sv_asdu(c)])) for i, c in enumerate(counts)]

    # Dropout: 0..9 then 30 (20 samples lost).
    counts = list(range(10)) + [30, 31, 32]
    s["sv_dropout"] = [(t0 + i * dt, sv_frame([sv_asdu(c)])) for i, c in enumerate(counts)]

    # Sync loss: smpSynch 2 (global) -> 0 (none) mid-stream.
    frames = [(t0 + i * dt, sv_frame([sv_asdu(i, smp_synch=2)])) for i in range(5)]
    frames += [(t0 + (5 + i) * dt, sv_frame([sv_asdu(5 + i, smp_synch=0)])) for i in range(5)]
    s["sv_sync_loss"] = frames

    # Unsynchronized throughout: smpSynch=0 on every frame.
    s["sv_unsynced"] = [(t0 + i * dt, sv_frame([sv_asdu(i, smp_synch=0)])) for i in range(10)]

    # confRev change mid-stream (dataset redefined).
    frames = [(t0 + i * dt, sv_frame([sv_asdu(i, conf_rev=1)])) for i in range(5)]
    frames += [(t0 + (5 + i) * dt, sv_frame([sv_asdu(5 + i, conf_rev=2)])) for i in range(5)]
    s["sv_confrev_change"] = frames

    # Multi-ASDU: healthy stream, 2 ASDUs per frame (smpCnt 0,1 / 2,3 / ...).
    # Exercises tshark multi-occurrence field aggregation in the tool's parser.
    s["sv_multi_asdu"] = [
        (t0 + i * 2 * dt, sv_frame([sv_asdu(2 * i), sv_asdu(2 * i + 1)])) for i in range(8)
    ]

    return s


def main() -> None:
    out_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("testdata")
    out_dir.mkdir(parents=True, exist_ok=True)
    for name, frames in build_scenarios().items():
        path = out_dir / f"{name}.pcap"
        write_pcap(path, frames)
        print(f"wrote {path}  ({len(frames)} frames)")


if __name__ == "__main__":
    main()
