"""Host-side packet capture parsing.

Synthetic captures rather than recorded ones: a real pcap in the repository is
a sample by another name, and these frames are built to exercise exactly the
fields triage reads.
"""

from __future__ import annotations

import socket
import struct
from pathlib import Path

from necropsy.sandbox.collectors.pcap import summarise


def _eth_ip(protocol: int, src: str, dst: str, payload: bytes) -> bytes:
    ip = (
        bytes([0x45, 0, 0, 0, 0, 0, 0, 0, 64, protocol, 0, 0])
        + socket.inet_aton(src) + socket.inet_aton(dst)
    )
    return b"\xaa" * 6 + b"\xbb" * 6 + b"\x08\x00" + ip + payload


def udp(src: str, dst: str, sport: int, dport: int, payload: bytes) -> bytes:
    return _eth_ip(17, src, dst, struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload)


def tcp(src: str, dst: str, dport: int, payload: bytes) -> bytes:
    header = struct.pack(">HHIIBBHHH", 44444, dport, 0, 0, 0x50, 0x18, 8192, 0, 0)
    return _eth_ip(6, src, dst, header + payload)


def dns_query(name: str) -> bytes:
    question = b"".join(bytes([len(l)]) + l.encode() for l in name.split(".")) + b"\x00"
    return struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + question + struct.pack(">HH", 1, 1)


def client_hello(host: str) -> bytes:
    name = host.encode()
    server_name = b"\x00" + struct.pack(">H", len(name)) + name
    sni_list = struct.pack(">H", len(server_name)) + server_name
    extension = struct.pack(">HH", 0, len(sni_list)) + sni_list
    extensions = struct.pack(">H", len(extension)) + extension
    body = (
        b"\x03\x03" + b"\x00" * 32 + b"\x00"
        + struct.pack(">H", 2) + b"\x00\x2f" + b"\x01\x00" + extensions
    )
    handshake = b"\x01" + struct.pack(">I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack(">H", len(handshake)) + handshake


def write_pcap(path: Path, frames: list[bytes], linktype: int = 1) -> Path:
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype)
    for frame in frames:
        out += struct.pack("<IIII", 0, 0, len(frame), len(frame)) + frame
    path.write_bytes(out)
    return path


def test_extracts_dns_sni_and_conversations(tmp_path: Path) -> None:
    path = write_pcap(tmp_path / "c.pcap", [
        udp("10.0.0.5", "10.0.0.1", 5353, 53, dns_query("gate.evil-c2.ru")),
        tcp("10.0.0.5", "185.220.101.44", 443, client_hello("panel.evil-c2.ru")),
        tcp("10.0.0.5", "185.220.101.44", 80, b"GET /x HTTP/1.1\r\n"),
    ])
    summary = summarise(path)

    assert summary.packets == 3
    assert summary.dns_queries == ["gate.evil-c2.ru"]
    assert summary.tls_sni == ["panel.evil-c2.ru"]
    assert "185.220.101.44" in summary.contacted_ips
    assert {(c["dport"], c["proto"]) for c in summary.conversations} == {
        (53, "udp"), (443, "tcp"), (80, "tcp")
    }


def test_sni_survives_when_the_payload_does_not(tmp_path: Path) -> None:
    """The reason SNI parsing is worth the code: it is readable when TLS is not."""
    path = write_pcap(tmp_path / "tls.pcap", [
        tcp("10.0.0.5", "1.2.3.4", 443, client_hello("c2.example.ru")),
        tcp("10.0.0.5", "1.2.3.4", 443, b"\x17\x03\x03" + b"\xff" * 200),  # encrypted
    ])
    summary = summarise(path)
    assert summary.tls_sni == ["c2.example.ru"]


def test_vlan_tagged_frames_are_parsed(tmp_path: Path) -> None:
    inner = udp("10.0.0.5", "10.0.0.1", 5353, 53, dns_query("vlan.example.ru"))
    tagged = inner[:12] + b"\x81\x00\x00\x64" + inner[12:]
    summary = summarise(write_pcap(tmp_path / "v.pcap", [tagged]))
    assert summary.dns_queries == ["vlan.example.ru"]


def test_raw_ip_linktype(tmp_path: Path) -> None:
    frame = udp("10.0.0.5", "10.0.0.1", 5353, 53, dns_query("raw.example.ru"))[14:]
    summary = summarise(write_pcap(tmp_path / "r.pcap", [frame], linktype=101))
    assert summary.dns_queries == ["raw.example.ru"]


def test_big_endian_capture(tmp_path: Path) -> None:
    frame = udp("10.0.0.5", "10.0.0.1", 5353, 53, dns_query("be.example.ru"))
    out = struct.pack(">IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    out += struct.pack(">IIII", 0, 0, len(frame), len(frame)) + frame
    path = tmp_path / "be.pcap"
    path.write_bytes(out)
    assert summarise(path).dns_queries == ["be.example.ru"]


def test_empty_and_malformed_captures_do_not_raise(tmp_path: Path) -> None:
    empty = tmp_path / "empty.pcap"
    empty.write_bytes(b"")
    assert "empty" in (summarise(empty).error or "")

    junk = tmp_path / "junk.pcap"
    junk.write_bytes(b"\x00" * 64)
    assert "not a classic pcap" in (summarise(junk).error or "")

    missing = summarise(tmp_path / "nope.pcap")
    assert missing.error and missing.packets == 0


def test_truncated_trailing_packet_is_flagged(tmp_path: Path) -> None:
    frame = udp("10.0.0.5", "10.0.0.1", 5353, 53, dns_query("cut.example.ru"))
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    out += struct.pack("<IIII", 0, 0, len(frame), len(frame)) + frame
    out += struct.pack("<IIII", 0, 0, 500, 500) + b"\x00" * 20  # claims 500, has 20
    path = tmp_path / "t.pcap"
    path.write_bytes(out)

    summary = summarise(path)
    assert summary.truncated is True
    assert summary.dns_queries == ["cut.example.ru"]


def test_a_capture_with_no_traffic_is_not_an_error(tmp_path: Path) -> None:
    summary = summarise(write_pcap(tmp_path / "quiet.pcap", []))
    assert summary.error is None
    assert summary.packets == 0
    assert summary.contacted_ips == []
