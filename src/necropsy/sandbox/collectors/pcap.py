"""Packet capture on the host side of the sandbox network.

`tcpdump` writes a classic pcap; we read it back with a small parser rather
than pulling in a capture library, because the fields that matter for triage
are few and specific: who was contacted, what was resolved, and what TLS name
was requested. SNI and DNS names survive even when the payload does not, which
makes them the highest-value C2 indicators available from an encrypted flow.

Capturing on the host means the sample cannot see, disable or poison the
capture -- the usual reason not to collect network telemetry in-guest.
"""

from __future__ import annotations

import logging
import shutil
import signal
import struct
import subprocess
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

PCAP_MAGIC_LE = 0xA1B2C3D4
PCAP_MAGIC_BE = 0xD4C3B2A1
PCAP_MAGIC_NS_LE = 0xA1B23C4D

LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_LINUX_SLL = 113
LINKTYPE_NULL = 0

MAX_PACKETS = 200_000


@dataclass
class PcapSummary:
    packets: int = 0
    bytes: int = 0
    truncated: bool = False
    conversations: list[dict[str, Any]] = field(default_factory=list)
    dns_queries: list[str] = field(default_factory=list)
    tls_sni: list[str] = field(default_factory=list)
    contacted_ips: list[str] = field(default_factory=list)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "packets": self.packets, "bytes": self.bytes, "truncated": self.truncated,
            "conversations": self.conversations[:100],
            "dns_queries": self.dns_queries[:200],
            "tls_sni": self.tls_sni[:100],
            "contacted_ips": self.contacted_ips[:200],
            "error": self.error,
        }


class PcapCapture:
    """A tcpdump running for the duration of a detonation."""

    def __init__(self, interface: str, out_path: Path, tcpdump: str | None = None) -> None:
        self.interface = interface
        self.out_path = out_path
        self._tcpdump = tcpdump or shutil.which("tcpdump") or "tcpdump"
        self._proc: subprocess.Popen[bytes] | None = None
        self.error: str | None = None

    def __enter__(self) -> PcapCapture:
        argv = [
            self._tcpdump, "-i", self.interface, "-w", str(self.out_path),
            "-U",            # flush per packet, so a hard stop keeps what was seen
            "-s", "0",       # full packets: SNI can sit past a small snaplen
            "-n",
        ]
        try:
            self._proc = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        except (OSError, FileNotFoundError) as exc:
            self.error = f"packet capture unavailable: {exc}"
            log.warning("%s", self.error)
        return self

    def __exit__(self, *_exc: object) -> None:
        if self._proc is None:
            return
        try:
            self._proc.send_signal(signal.SIGINT)
            self._proc.wait(timeout=20)
        except (subprocess.TimeoutExpired, OSError):
            self._proc.kill()
        finally:
            if self._proc.returncode not in (0, None) and not self.out_path.exists():
                stderr = (self._proc.stderr.read() if self._proc.stderr else b"") or b""
                self.error = f"tcpdump exited {self._proc.returncode}: {stderr.decode()[:200]}"


def summarise(path: Path) -> PcapSummary:
    summary = PcapSummary()
    try:
        data = path.read_bytes()
    except OSError as exc:
        summary.error = f"{type(exc).__name__}: {exc}"
        return summary

    if len(data) < 24:
        summary.error = "capture file is empty or truncated"
        return summary

    (magic,) = struct.unpack("<I", data[:4])
    if magic in (PCAP_MAGIC_LE, PCAP_MAGIC_NS_LE):
        endian = "<"
    elif magic in (PCAP_MAGIC_BE, 0x4D3CB2A1):
        endian = ">"
    else:
        summary.error = f"not a classic pcap file (magic {magic:#x}); pcapng is not parsed"
        return summary

    (linktype,) = struct.unpack(endian + "I", data[20:24])

    conversations: Counter[tuple[str, str, int, str]] = Counter()
    dns: Counter[str] = Counter()
    sni: Counter[str] = Counter()
    ips: Counter[str] = Counter()

    offset = 24
    while offset + 16 <= len(data):
        _ts_sec, _ts_usec, incl_len, _orig_len = struct.unpack(
            endian + "IIII", data[offset : offset + 16]
        )
        offset += 16
        frame = data[offset : offset + incl_len]
        offset += incl_len
        if len(frame) < incl_len:
            summary.truncated = True
            break

        summary.packets += 1
        summary.bytes += incl_len
        if summary.packets > MAX_PACKETS:
            summary.truncated = True
            break

        _parse_frame(frame, linktype, conversations, dns, sni, ips)

    summary.conversations = [
        {"src": s, "dst": d, "dport": p, "proto": proto, "packets": n}
        for (s, d, p, proto), n in conversations.most_common(100)
    ]
    summary.dns_queries = [q for q, _ in dns.most_common(200)]
    summary.tls_sni = [s for s, _ in sni.most_common(100)]
    summary.contacted_ips = [ip for ip, _ in ips.most_common(200)]
    return summary


def _parse_frame(
    frame: bytes,
    linktype: int,
    conversations: Counter,
    dns: Counter,
    sni: Counter,
    ips: Counter,
) -> None:
    payload = _strip_link_layer(frame, linktype)
    if payload is None or len(payload) < 20:
        return
    if payload[0] >> 4 != 4:
        return  # IPv6 not summarised in the POC

    ihl = (payload[0] & 0x0F) * 4
    if len(payload) < ihl:
        return
    protocol = payload[9]
    src = ".".join(str(b) for b in payload[12:16])
    dst = ".".join(str(b) for b in payload[16:20])
    rest = payload[ihl:]

    if protocol == 6 and len(rest) >= 20:  # TCP
        sport, dport = struct.unpack(">HH", rest[:4])
        data_offset = (rest[12] >> 4) * 4
        conversations[(src, dst, dport, "tcp")] += 1
        ips[dst] += 1
        body = rest[data_offset:]
        name = _tls_sni(body)
        if name:
            sni[name] += 1
    elif protocol == 17 and len(rest) >= 8:  # UDP
        sport, dport = struct.unpack(">HH", rest[:4])
        conversations[(src, dst, dport, "udp")] += 1
        ips[dst] += 1
        if dport == 53 or sport == 53:
            name = _dns_question(rest[8:])
            if name:
                dns[name] += 1


def _strip_link_layer(frame: bytes, linktype: int) -> bytes | None:
    if linktype == LINKTYPE_ETHERNET:
        if len(frame) < 14:
            return None
        ethertype = struct.unpack(">H", frame[12:14])[0]
        offset = 14
        while ethertype in (0x8100, 0x88A8) and len(frame) >= offset + 4:
            ethertype = struct.unpack(">H", frame[offset + 2 : offset + 4])[0]
            offset += 4
        return frame[offset:] if ethertype == 0x0800 else None
    if linktype == LINKTYPE_RAW:
        return frame
    if linktype == LINKTYPE_LINUX_SLL:
        return frame[16:] if len(frame) > 16 else None
    if linktype == LINKTYPE_NULL:
        return frame[4:] if len(frame) > 4 else None
    return None


def _dns_question(payload: bytes) -> str | None:
    if len(payload) < 13:
        return None
    labels: list[str] = []
    offset = 12
    while offset < len(payload):
        length = payload[offset]
        if length == 0:
            break
        if length & 0xC0:  # compression pointer: not valid in a question
            return None
        offset += 1
        label = payload[offset : offset + length]
        if len(label) < length:
            return None
        labels.append(label.decode("latin-1"))
        offset += length
        if len(labels) > 16:
            return None
    name = ".".join(labels)
    return name or None


def _tls_sni(body: bytes) -> str | None:
    """Pull server_name out of a TLS ClientHello.

    Survives encryption, which is why it is worth 30 lines: for most modern C2
    it is the only readable destination name in the flow.
    """
    if len(body) < 45 or body[0] != 0x16 or body[1] != 0x03:
        return None
    if body[5] != 0x01:  # handshake type: ClientHello
        return None
    try:
        pos = 43  # record(5) + handshake(4) + version(2) + random(32)
        session_len = body[pos]
        pos += 1 + session_len
        cipher_len = struct.unpack(">H", body[pos : pos + 2])[0]
        pos += 2 + cipher_len
        comp_len = body[pos]
        pos += 1 + comp_len
        ext_total = struct.unpack(">H", body[pos : pos + 2])[0]
        pos += 2
        end = min(len(body), pos + ext_total)

        while pos + 4 <= end:
            ext_type, ext_len = struct.unpack(">HH", body[pos : pos + 4])
            pos += 4
            if ext_type == 0x0000:  # server_name
                inner = body[pos : pos + ext_len]
                if len(inner) >= 5:
                    name_len = struct.unpack(">H", inner[3:5])[0]
                    return inner[5 : 5 + name_len].decode("latin-1") or None
                return None
            pos += ext_len
    except (struct.error, IndexError, UnicodeDecodeError):
        return None
    return None
