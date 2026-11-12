"""Stream tshark capture output into IEC 61850 analysis."""

from collections.abc import Iterator
from xml.etree.ElementTree import Element, XMLPullParser

from .iec61850 import FIELD_SETS, CaptureAnalysis, ProtocolReport

_MMS_PDU_KINDS = {
    "mms.confirmed_RequestPDU_element": "req",
    "mms.confirmed_ResponsePDU_element": "resp",
    "mms.confirmed_ErrorPDU_element": "error",
    "mms.rejectPDU_element": "reject",
    "mms.cancel_ErrorPDU_element": "cancel error",
}


class FieldCapture:
    def __init__(self, protocol: str) -> None:
        self.analysis = CaptureAnalysis(protocol)
        self.columns = FIELD_SETS[protocol]
        self.args = ["-T", "fields", "-E", "header=y", "-E", "separator=\t", "-E", "quote=n"]
        for column in self.columns:
            self.args.extend(["-e", column])
        self.header_seen = False
        self.partial_line = b""

    def feed(self, chunk: bytes) -> None:
        lines = (self.partial_line + chunk).split(b"\n")
        self.partial_line = lines.pop()
        for line in lines:
            if not line.strip():
                continue
            if not self.header_seen:
                self.header_seen = True
                continue
            fields = line.rstrip(b"\r").decode(errors="replace").split("\t")
            fields.extend([""] * (len(self.columns) - len(fields)))
            self.analysis.add_field_frame(dict(zip(self.columns, fields, strict=False)))

    def finish(self) -> ProtocolReport:
        if self.partial_line:
            self.feed(b"\n")
        return self.analysis.finish()


def _show(node: Element, field_name: str, *, nested: bool = False) -> str:
    path = ".//field" if nested else "field"
    match = node.find(f"{path}[@name='{field_name}']")
    return match.get("show", "") if match is not None else ""


def _mms_rows(packet: Element) -> Iterator[dict[str, str]]:
    frame = packet.find("proto[@name='frame']")
    tcp = packet.find("proto[@name='tcp']")
    if frame is None or tcp is None:
        return

    src = dst = ""
    for node in reversed(packet.findall("proto")):
        network = node.get("name")
        if network in {"ip", "ipv6"}:
            src, dst = _show(node, f"{network}.src"), _show(node, f"{network}.dst")
            break
    fields = {
        "frame.number": _show(frame, "frame.number"),
        "frame.time_epoch": _show(frame, "frame.time_epoch"),
        "tcp.stream": _show(tcp, "tcp.stream"),
        "tcp.srcport": _show(tcp, "tcp.srcport"),
        "tcp.dstport": _show(tcp, "tcp.dstport"),
        "ip.src": src,
        "ip.dst": dst,
    }

    found = False
    for mms in packet.findall("proto[@name='mms']"):
        for pdu in mms:
            kind = _MMS_PDU_KINDS.get(pdu.get("name", ""))
            if kind is None:
                continue
            found = True
            yield {
                **fields,
                "mms.kind": kind,
                "mms.invokeID": _show(pdu, "mms.invokeID"),
                "mms.originalInvokeID": _show(pdu, "mms.originalInvokeID"),
                "mms.errorClass": _show(pdu, "mms.errorClass", nested=True),
                "mms.rejectReason": _show(pdu, "mms.rejectReason"),
            }
    if not found:
        yield fields


class MMSCapture:
    args = ("-T", "pdml", "-J", "frame ip ipv6 tcp mms")

    def __init__(self) -> None:
        self.analysis = CaptureAnalysis("mms")
        self.parser: XMLPullParser[Element] = XMLPullParser(events=("start", "end"))
        self.root: Element | None = None

    def feed(self, chunk: bytes) -> None:
        self.parser.feed(chunk)
        for item in self.parser.read_events():
            if len(item) != 2 or not isinstance(item[1], Element):
                continue
            event, element = item
            if self.root is None:
                self.root = element
            elif event == "end" and element.tag == "packet":
                self.analysis.add_frame(_mms_rows(element))
                self.root.remove(element)

    def finish(self) -> ProtocolReport:
        self.parser.close()
        return self.analysis.finish()
