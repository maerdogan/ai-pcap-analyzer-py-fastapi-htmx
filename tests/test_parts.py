"""Captures over the part size are read in parts of whole connections. The results must be those of one pass."""
import socket
import struct
import subprocess
import sys
from pathlib import Path

import pytest

from pcap_analyzer import engine, split, tshark
from pcap_analyzer.config import Settings

ROOT = Path(__file__).resolve().parent.parent
TABLES = ("tcp_connections", "http_transactions", "tcp_events", "dns_queries")
SKIP_META = ("id", "created", "duration_s", "parts")


def _rows(a):
    with a.connect() as db:
        out = {}
        for t in TABLES:
            cols = ", ".join(c[0] for c in db.execute(f"DESCRIBE {t}").fetchall())
            out[t] = db.execute(f"SELECT * FROM {t} ORDER BY {cols}").fetchall()
        return out


def _both(monkeypatch, tmp_path, capture, keylog=None, parts=4):
    monkeypatch.setattr(engine, "PART_BYTES", 1 << 40)
    whole = engine.analyze(capture, keylog=keylog, settings=Settings(workdir=tmp_path / "whole"))
    monkeypatch.setattr(engine, "PART_BYTES", max(1, capture.stat().st_size // parts))
    in_parts = engine.analyze(capture, keylog=keylog, settings=Settings(workdir=tmp_path / "parts"))
    return whole, in_parts


@pytest.mark.parametrize("name, keylog", [("http_scenarios.pcap", None), ("node_nat.pcap", None), ("backends.pcap", None),
                                          ("https_h2.pcap", "https_h2.keylog"), ("poor_capture.pcap", None)])
def test_parts_give_the_same_result(samples, tmp_path, monkeypatch, name, keylog):
    whole, in_parts = _both(monkeypatch, tmp_path, samples / name, keylog and samples / keylog)
    assert in_parts.meta["parts"] > 1 and whole.meta["parts"] == 0
    assert _rows(whole) == _rows(in_parts)
    assert {k: v for k, v in whole.meta.items() if k not in SKIP_META} == {k: v for k, v in in_parts.meta.items() if k not in SKIP_META}


def test_requests_that_start_together_keep_their_order(tmp_path, monkeypatch):
    sys.path.insert(0, str(ROOT / "tools"))
    import gen_samples as g

    w = g.PcapWriter(tmp_path / "together.pcap")
    conns = [g.Conn(w, "10.1.0.1", 40000 + i, "10.2.0.1", 80) for i in range(8)]
    for i, c in enumerate(conns):
        c.handshake(g.T0 + i * 0.01)
    for c in conns:  # every request leaves at the same moment, as a capture with coarse timestamps shows it
        g.txn(c, g.T0 + 1, g.req("GET", f"/together/{c.c[1]}"), g.resp(200, b"ok"), 0.01)
    w.close()
    whole, in_parts = _both(monkeypatch, tmp_path, tmp_path / "together.pcap", parts=8)
    assert in_parts.meta["parts"] > 1 and _rows(whole) == _rows(in_parts)


def test_pcapng_parts(samples, tmp_path, monkeypatch):
    ng = tmp_path / "http.pcapng"
    subprocess.run(["tshark", "-r", samples / "http_scenarios.pcap", "-F", "pcapng", "-w", ng], check=True, capture_output=True)
    whole, in_parts = _both(monkeypatch, tmp_path, ng)
    assert _rows(whole) == _rows(in_parts)


def test_a_cut_capture_is_reported(samples, tmp_path, monkeypatch):
    cut = tmp_path / "cut.pcap"
    data = (samples / "http_scenarios.pcap").read_bytes()
    cut.write_bytes(data[:-7])
    monkeypatch.setattr(engine, "PART_BYTES", len(data) // 3)
    a = engine.analyze(cut, settings=Settings(workdir=tmp_path / "w"))
    assert "capture_truncated" in a.meta["warnings"] and a.meta["transactions"] > 0


def test_frame_and_stream_filters_are_refused_in_parts(samples, tmp_path, monkeypatch):
    monkeypatch.setattr(engine, "PART_BYTES", 1000)
    with pytest.raises(tshark.TsharkError, match="tcp.stream"):
        engine.analyze(samples / "http_scenarios.pcap", flt=tshark.Filter(display="tcp.stream == 3"), settings=Settings(workdir=tmp_path / "w"))
    a = engine.analyze(samples / "http_scenarios.pcap", flt=tshark.Filter(port=8080), settings=Settings(workdir=tmp_path / "w"))
    assert a.meta["parts"] > 1


def test_other_files_are_refused_in_parts(tmp_path, monkeypatch):
    junk = tmp_path / "junk.cap"
    junk.write_bytes(b"\x00" * 5000)
    monkeypatch.setattr(engine, "PART_BYTES", 1000)
    with pytest.raises(tshark.TsharkError, match="pcap or pcapng"):
        engine.analyze(junk, settings=Settings(workdir=tmp_path / "w"))


def _tcp(src, dst, sport, dport):
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 40, 1, 0, 64, 6, 0, socket.inet_aton(src), socket.inet_aton(dst))
    return ip + struct.pack(">HHIIBBHHH", sport, dport, 0, 0, 0x50, 0x10, 1000, 0, 0)


def _ether(ip, kind=0x0800):
    return b"\x02" * 12 + struct.pack(">H", kind) + ip


def _udp(src, dst, sport, dport, payload, proto=17):
    return struct.pack(">BBHHHBBH4s4s", 0x45, 0, 28 + len(payload), 1, 0, 64, proto, 0, socket.inet_aton(src), socket.inet_aton(dst)) + \
        struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload


def test_a_connection_has_one_key_in_every_wrapping():
    keys = split._Keys()
    plain = keys.frame(split.ETHERNET, _ether(_tcp("10.244.1.1", "10.244.2.2", 40000, 8080)))
    back = keys.frame(split.ETHERNET, _ether(_tcp("10.244.2.2", "10.244.1.1", 8080, 40000)))
    vlan = keys.frame(split.ETHERNET, b"\x02" * 12 + b"\x81\x00\x00\x05\x08\x00" + _tcp("10.244.1.1", "10.244.2.2", 40000, 8080))
    inner = _ether(_tcp("10.244.2.2", "10.244.1.1", 8080, 40000))
    vxlan = keys.frame(split.ETHERNET, _ether(_udp("192.168.0.2", "192.168.0.1", 51234, 4789, b"\x08\0\0\0\0\0\x01\0" + inner)))
    geneve = keys.frame(split.ETHERNET, _ether(_udp("192.168.0.1", "192.168.0.2", 6081, 6081, b"\0\0\x65\x58\0\0\x01\0" + inner)))
    ipip = keys.frame(split.ETHERNET, _ether(struct.pack(">BBHHHBBH4s4s", 0x45, 0, 60, 1, 0, 64, 4, 0, socket.inet_aton("192.168.0.1"),
                                                         socket.inet_aton("192.168.0.2")) + _tcp("10.244.1.1", "10.244.2.2", 40000, 8080)))
    sll2 = keys.frame(split.SLL2, struct.pack(">H", 0x0800) + b"\0" * 18 + _tcp("10.244.1.1", "10.244.2.2", 40000, 8080))
    icmp = keys.frame(split.ETHERNET, _ether(struct.pack(">BBHHHBBH4s4s", 0x45, 0, 56, 1, 0, 64, 1, 0, socket.inet_aton("10.0.0.1"),
                                                         socket.inet_aton("10.244.1.1")) + b"\x03\x04\0\0\0\0\x05\xdc" + _tcp("10.244.1.1", "10.244.2.2", 40000, 8080)[:28]))
    assert plain and plain == back == vlan == vxlan == geneve == ipip == sll2 == icmp
    assert keys.frame(split.ETHERNET, _ether(_tcp("10.244.1.1", "10.244.2.2", 40001, 8080))) != plain


def test_fragments_follow_the_first():
    keys = split._Keys()
    head = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 40, 77, 0x2000, 64, 6, 0, socket.inet_aton("10.0.0.1"), socket.inet_aton("10.0.0.2"))
    rest = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 40, 77, 3, 64, 6, 0, socket.inet_aton("10.0.0.1"), socket.inet_aton("10.0.0.2"))
    first = keys.frame(split.RAW[0], head + _tcp("10.0.0.1", "10.0.0.2", 1, 2)[20:])
    assert first and keys.frame(split.RAW[0], rest + b"\0" * 20) == first


def test_connection_export_from_a_part(samples, tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    from pcap_analyzer.web.app import create_app
    from test_web import PW, form_token, upload

    monkeypatch.setattr(engine, "PART_BYTES", (samples / "http_scenarios.pcap").stat().st_size // 4)
    s = Settings(workdir=tmp_path / "w", admin_password=PW)
    with TestClient(create_app(s), follow_redirects=False, base_url="https://testserver") as c:
        c.post("/login", data={"username": "admin", "password": PW})
        c.headers["X-CSRF-Token"] = form_token(c)
        aid = upload(c, samples / "http_scenarios.pcap").rsplit("/", 1)[1]
        assert engine.open_analysis(aid, s).meta["parts"] > 1
        r = c.get(f"/export/{aid}/conn/2.pcapng")
        assert r.status_code == 200
        out = tmp_path / "one.pcapng"
        out.write_bytes(r.content)
        assert {p["tcp.dstport"] for p in tshark.packets(out)} == {"8080", "40003"}
        for path in ("requests.csv", "requests.har", "requests.xlsx", "connections.json"):
            assert c.get(f"/export/{aid}/{path}").status_code == 200
