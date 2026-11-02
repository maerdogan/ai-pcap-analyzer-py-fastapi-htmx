#!/usr/bin/env python3
"""Generate synthetic PCAP samples with known timings for pcap-analyzer tests.

No capture rights are needed: TCP frames are built here and TLS bytes come from a
real in-memory OpenSSL session, so the keylog files can really decrypt the traffic.
Each sample's expected values are written to samples/truth.json.
All IPs are private and all data is fake.

Usage: gen_samples.py [output_dir] [--perf]
"""
import gzip
import json
import random
import socket
import ssl
import struct
import subprocess
import sys
from pathlib import Path

T0 = 1_790_000_000.0
SYN, FIN, RST, PSH, ACK = 0x02, 0x01, 0x04, 0x08, 0x10
MAC_C = bytes.fromhex("02000000000a")
MAC_S = bytes.fromhex("02000000000b")


class PcapWriter:
    def __init__(self, path):
        self.f = open(path, "wb")
        self.f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        self.size = 24
        self.ipid = 1
        self.frames = []

    def write(self, ts, frame):
        self.frames.append((ts, frame))

    def close(self):
        """Frames are sorted so overlapping connections read like a real capture."""
        self.frames.sort(key=lambda x: x[0])
        for ts, frame in self.frames:
            sec = int(ts)
            usec = int(round((ts - sec) * 1e6))
            if usec == 1000000:
                sec, usec = sec + 1, 0
            self.f.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)))
            self.f.write(frame)
        self.f.close()


def ip_checksum(hdr):
    s = sum(struct.unpack(">10H", hdr))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


def ipv4(w, src, dst, proto, payload, ttl):
    w.ipid = (w.ipid + 1) & 0xffff
    hdr = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), w.ipid, 0x4000, ttl, proto, 0,
                      socket.inet_aton(src), socket.inet_aton(dst))
    hdr = hdr[:10] + struct.pack(">H", ip_checksum(hdr)) + hdr[12:]
    return hdr + payload


class Conn:
    """One TCP connection as seen from the capture point."""

    def __init__(self, w, c_ip, c_port, s_ip, s_port, mss=1460, win=64240):
        self.w, self.c, self.s = w, (c_ip, c_port), (s_ip, s_port)
        self.seq = {True: random.randrange(1 << 31), False: random.randrange(1 << 31)}
        self.mss = mss
        self.win = {True: win, False: win}

    def emit(self, t, from_c, flags, payload=b"", seq=None, opts=b""):
        src, dst = (self.c, self.s) if from_c else (self.s, self.c)
        s = self.seq[from_c] if seq is None else seq
        a = self.seq[not from_c] if flags & ACK else 0
        doff = (20 + len(opts)) // 4
        tcp = struct.pack(">HHIIBBHHH", src[1], dst[1], s, a, doff << 4, flags, self.win[from_c], 0, 0) + opts + payload
        eth = (MAC_S + MAC_C) if from_c else (MAC_C + MAC_S)
        self.w.write(t, eth + b"\x08\x00" + ipv4(self.w, src[0], dst[0], 6, tcp, 64 if from_c else 60))
        if seq is None:
            self.seq[from_c] = (self.seq[from_c] + len(payload) + (1 if flags & (SYN | FIN) else 0)) & 0xffffffff

    def handshake(self, t, srv_rtt=0.002, cli_rtt=0.001):
        opts = struct.pack(">BBH", 2, 4, self.mss) + b"\x04\x02\x01\x01"
        self.emit(t, True, SYN, opts=opts)
        self.emit(t + srv_rtt, False, SYN | ACK, opts=opts)
        self.emit(t + srv_rtt + cli_rtt, True, ACK)
        return t + srv_rtt + cli_rtt

    def send(self, t, from_c, data, gap=0.0002, ack_rtt=0.002, lose=(), rto=0.4):
        """Send data in MSS segments, the peer acks every 2nd segment. lose: indexes retransmitted after rto."""
        n = 0
        pos = 0
        while pos < len(data):
            chunk = data[pos:pos + self.mss]
            pos += len(chunk)
            flags = ACK | (PSH if pos == len(data) else 0)
            seq0 = self.seq[from_c]
            self.emit(t, from_c, flags, chunk)
            if n in lose:
                t += rto
                self.emit(t, from_c, flags, chunk, seq=seq0)
            n += 1
            if n % 2 == 0 or pos == len(data):
                self.emit(t + ack_rtt, not from_c, ACK)
            if pos < len(data):
                t += gap
        return t

    def close(self, t, from_c=True, rtt=0.002):
        self.emit(t, from_c, FIN | ACK)
        self.emit(t + rtt, not from_c, FIN | ACK)
        self.emit(t + 2 * rtt, from_c, ACK)
        return t + 2 * rtt

    def rst(self, t, from_c, window=None):
        self.win[from_c] = self.win[from_c] if window is None else window
        self.emit(t, from_c, RST | ACK)


def req(method, uri, host="app.example.test", extra=(), body=b""):
    h = [f"{method} {uri} HTTP/1.1", f"Host: {host}", "User-Agent: sample-gen/1.0"] + list(extra)
    if body:
        h.append(f"Content-Length: {len(body)}")
    return ("\r\n".join(h) + "\r\n\r\n").encode() + body


def resp(status, body=b"", extra=(), reason="OK", clen=None):
    h = [f"HTTP/1.1 {status} {reason}", "Server: sample", "Content-Type: application/json"] + list(extra)
    h.append(f"Content-Length: {len(body) if clen is None else clen}")
    return ("\r\n".join(h) + "\r\n\r\n").encode() + body


def rand_body(n):
    return bytes(random.getrandbits(8) for _ in range(n))


def txn(c, t, request, response, service, truth=None, **send_kw):
    """Request/response pair; service is the time from last request byte to first response byte at the capture point."""
    t_req_end = c.send(t, True, request)
    t_first = t_req_end + service
    t_end = c.send(t_first, False, response, **send_kw)
    if truth is not None:
        truth.update(ttfb=round(t_first - t, 6), total=round(t_end - t, 6))
    return t_end


def dns_exchange(w, t, qname, delay, ip_answer):
    q = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    q += b"".join(bytes([len(p)]) + p.encode() for p in qname.split(".")) + b"\0" + struct.pack(">HH", 1, 1)
    a = struct.pack(">HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0) + q[12:]
    a += b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + socket.inet_aton(ip_answer)
    for ts, src, dst, sp, dp, m, d in ((t, "10.10.1.50", "10.10.0.2", 53000, 53, MAC_S + MAC_C, q),
                                      (t + delay, "10.10.0.2", "10.10.1.50", 53, 53000, MAC_C + MAC_S, a)):
        udp = struct.pack(">HHHH", sp, dp, 8 + len(d), 0) + d
        w.write(ts, m + b"\x08\x00" + ipv4(w, src, dst, 17, udp, 64))


def gen_http(out, truth):
    w = PcapWriter(out / "http_scenarios.pcap")
    cl, srv = "10.10.1.50", "10.20.2.10"
    tr = []

    def rec(name, cause, **kw):
        e = dict(name=name, cause=cause, **kw)
        tr.append(e)
        return e

    dns_exchange(w, T0 - 0.2, "app.example.test", 0.12, srv)

    c = Conn(w, cl, 40001, srv, 8080)  # keep-alive, URL grouping, connection reuse
    t = c.handshake(T0)
    t = txn(c, t + 0.01, req("GET", "/api/users/123"), resp(200, b'{"id":123}'), 0.05, rec("reuse_1", "normal", new_conn=True))
    t = txn(c, t + 0.05, req("GET", "/api/users/456"), resp(200, b'{"id":456}'), 0.06, rec("reuse_2", "normal", new_conn=False))
    t = txn(c, t + 0.05, req("GET", "/api/orders/789?x=1"), resp(404, b"{}", reason="Not Found"), 0.02, rec("reuse_3", "normal"))
    body = rand_body(20000)
    t = txn(c, t + 0.05, req("POST", "/api/orders", body=body), resp(201, b"{}", reason="Created"), 0.08, rec("upload", "normal"))
    c.close(t + 0.5, from_c=True)

    c = Conn(w, cl, 40002, srv, 8080)  # slow service
    t = c.handshake(T0 + 2)
    t = txn(c, t + 0.01, req("GET", "/api/reports/2024"), resp(200, rand_body(5000)), 2.5, rec("slow_service", "service", service=2.5))
    c.close(t + 0.2, from_c=False)

    c = Conn(w, cl, 40003, srv, 8080)  # loss: RTO retransmissions
    t = c.handshake(T0 + 6)
    t = txn(c, t + 0.01, req("GET", "/files/large.bin"), resp(200, rand_body(200_000)), 0.05, rec("packet_loss", "loss", retransmits=2, rto=0.4), lose=(20, 70))
    c.close(t + 0.1)

    c = Conn(w, cl, 40004, srv, 8080)  # receiver stalls with zero window
    t = c.handshake(T0 + 9)
    t = c.send(t + 0.01, True, req("GET", "/files/big2.bin"))
    r = resp(200, rand_body(100_000))
    t = c.send(t + 0.03, False, r[:30000])
    c.win[True] = 0
    c.emit(t + 0.002, True, ACK)
    c.win[True] = 64240
    c.emit(t + 1.202, True, ACK)
    t = c.send(t + 1.204, False, r[30000:])
    rec("zero_window", "slow_client", zero_window_s=1.2)
    c.close(t + 0.1)

    c = Conn(w, cl, 40005, srv, 8080)  # unanswered, server resets after 30 s
    t = c.handshake(T0 + 12)
    t = c.send(t + 0.01, True, req("GET", "/api/slow"))
    c.rst(t + 30, False, window=9300)
    rec("unanswered", "timeout", rst_by="server", wait=30)

    c = Conn(w, cl, 40006, srv, 8080)  # gateway errors
    t = c.handshake(T0 + 13)
    t = txn(c, t + 0.01, req("GET", "/api/pay"), resp(502, b"{}", reason="Bad Gateway"), 0.01, rec("gw_502", "gateway"))
    t = txn(c, t + 0.01, req("GET", "/api/pay"), resp(503, b"{}", reason="Service Unavailable"), 0.01, rec("gw_503", "gateway"))
    t = txn(c, t + 0.01, req("GET", "/api/pay"), resp(504, b"{}", reason="Gateway Timeout"), 60, rec("gw_504", "gateway", service=60))
    c.close(t + 0.01, from_c=False)

    c = Conn(w, cl, 40007, srv, 8080)  # delayed ACK + Nagle: 2nd write waits 200 ms for the ACK
    t = c.handshake(T0 + 80)
    r = req("POST", "/api/nagle", body=b'{"a":1,"b":2,"c":3}')
    head = r[:r.index(b"\r\n\r\n") + 4]
    c.emit(t + 0.01, True, ACK | PSH, head)
    c.emit(t + 0.21, False, ACK)
    c.emit(t + 0.211, True, ACK | PSH, r[len(head):])
    t = c.send(t + 0.26, False, resp(200, b"{}"))
    rec("delayed_ack", "delayed_ack", delay=0.2)
    c.close(t + 0.05)

    c = Conn(w, cl, 40008, srv, 8080)  # truncated response then RST
    t = c.handshake(T0 + 82)
    t = c.send(t + 0.01, True, req("GET", "/files/cut.bin"))
    t = c.send(t + 0.05, False, resp(200, rand_body(6000), clen=10000))
    c.rst(t + 0.1, False)
    rec("truncated", "truncated", content_length=10000, received=6000, rst_by="server")

    c = Conn(w, cl, 40009, srv, 8080)  # gzip + chunked + Server-Timing
    t = c.handshake(T0 + 83)
    z = gzip.compress(b'{"items":[1,2,3]}' * 500)
    chunk = f"{len(z):x}\r\n".encode() + z + b"\r\n0\r\n\r\n"
    head = ("HTTP/1.1 200 OK\r\nServer: sample\r\nContent-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n"
            "Server-Timing: app;dur=120.5\r\nContent-Type: application/json\r\n\r\n").encode()
    t = txn(c, t + 0.01, req("GET", "/api/items"), head + chunk, 0.13, rec("gzip_chunked", "normal", server_timing_ms=120.5))
    c.close(t + 0.05)

    c = Conn(w, cl, 40010, srv, 8080)  # pipelining: 2nd request queues behind the 1st
    t = c.handshake(T0 + 84)
    c.emit(t + 0.01, True, ACK | PSH, req("GET", "/api/first"))
    c.emit(t + 0.02, True, ACK | PSH, req("GET", "/api/second"))
    t = c.send(t + 1.02, False, resp(200, b"{}"))
    t = c.send(t + 0.01, False, resp(200, b"{}"))
    rec("queue", "queueing", queued_s=1.0)
    c.close(t + 0.05)

    c = Conn(w, cl, 40011, srv, 8080, mss=536)  # small MSS: many segments for one response
    t = c.handshake(T0 + 86)
    t = txn(c, t + 0.01, req("GET", "/files/mss.bin"), resp(200, rand_body(20000)), 0.02, rec("small_mss", "mtu", mss=536))
    c.close(t + 0.05)

    c = Conn(w, cl, 40012, srv, 8080)  # high RTT: mostly network delay
    t = c.handshake(T0 + 88, srv_rtt=0.3)
    t = c.send(t + 0.01, True, req("GET", "/api/far"), ack_rtt=0.3)
    t = c.send(t + 0.31, False, resp(200, b"{}"), ack_rtt=0.001)
    rec("high_rtt", "network", rtt=0.3, service=0.01)
    c.close(t + 0.05, rtt=0.3)

    w.close()
    truth["http_scenarios.pcap"] = tr


class Tls:
    """Real TLS session over memory BIOs. Records flights so they can be laid on the fake TCP."""

    def __init__(self, certdir, keylog, alpn=None, maxv=None, ciphers=None):
        cctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        cctx.load_verify_locations(certdir / "test_cert.pem")
        cctx.keylog_filename = str(keylog)
        sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        sctx.load_cert_chain(certdir / "test_cert.pem", certdir / "test_key.pem")
        for ctx in (cctx, sctx):
            if alpn:
                ctx.set_alpn_protocols(alpn)
            if maxv:
                ctx.maximum_version = maxv
            if ciphers:
                ctx.set_ciphers(ciphers)
        self.c_in, self.c_out, self.s_in, self.s_out = (ssl.MemoryBIO() for _ in range(4))
        self.c = cctx.wrap_bio(self.c_in, self.c_out, server_hostname="app.example.test")
        self.s = sctx.wrap_bio(self.s_in, self.s_out, server_side=True)

    def handshake(self):
        flights = []
        done_c = done_s = False
        while not (done_c and done_s):
            if not done_c:
                try:
                    self.c.do_handshake()
                    done_c = True
                except ssl.SSLWantReadError:
                    pass
            d = self.c_out.read()
            if d:
                flights.append((True, d))
                self.s_in.write(d)
            if not done_s:
                try:
                    self.s.do_handshake()
                    done_s = True
                except ssl.SSLWantReadError:
                    pass
            d = self.s_out.read()
            if d:
                flights.append((False, d))
                self.c_in.write(d)
        return flights

    def wrap(self, from_c, data):
        o = self.c if from_c else self.s
        bio = self.c_out if from_c else self.s_out
        peer_bio = self.s_in if from_c else self.c_in
        peer = self.s if from_c else self.c
        o.write(data)
        out = bio.read()
        peer_bio.write(out)
        try:
            while peer.read(65536):
                pass
        except ssl.SSLWantReadError:
            pass
        return out


def play_handshake(c, tls, t, rtt=0.002):
    fl = tls.handshake()
    start = t
    for from_c, d in fl:
        t = c.send(t + rtt / 2, from_c, d, ack_rtt=rtt / 2)
    return t, t - start


def gen_tls(out, certdir, truth):
    variants = [
        ("https_tls13.pcap", dict(), "keylog"),
        ("https_tls12_ecdhe.pcap", dict(maxv=ssl.TLSVersion.TLSv1_2, ciphers="ECDHE-RSA-AES128-GCM-SHA256"), "keylog"),
        ("https_tls12_rsa.pcap", dict(maxv=ssl.TLSVersion.TLSv1_2, ciphers="AES256-GCM-SHA384"), "rsa_key"),
    ]
    for name, kw, method in variants:
        keylog = out / (name.replace(".pcap", "") + ".keylog")
        keylog.unlink(missing_ok=True)
        w = PcapWriter(out / name)
        tr = []
        for i, (uri, status, svc) in enumerate([("/secure/login", 200, 0.08), ("/secure/report/77", 200, 1.8), ("/secure/missing", 404, 0.02)]):
            c = Conn(w, "10.10.1.50", 41000 + i, "10.20.2.20", 443)
            t = c.handshake(T0 + i * 5)
            tls = Tls(certdir, keylog, **kw)
            t, hs = play_handshake(c, tls, t + 0.005)
            q = tls.wrap(True, req("GET", uri))
            a = tls.wrap(False, resp(status, rand_body(3000)))
            t2 = c.send(t + 0.01, True, q)
            t3 = c.send(t2 + svc, False, a)
            tr.append(dict(uri=uri, status=status, service=svc, tls_handshake=round(hs, 6)))
            c.close(t3 + 0.05)
        w.close()
        truth[name] = dict(decrypt=method, txns=tr)


def h2_frame(ftype, flags, stream, payload):
    return struct.pack(">I", len(payload))[1:] + bytes([ftype, flags]) + struct.pack(">I", stream) + payload


def hpack(headers):
    """HPACK literal fields without indexing or Huffman: valid and needs no library."""
    out = b""
    for k, v in headers:
        k, v = k.encode(), v.encode()
        out += b"\x00" + bytes([len(k)]) + k + bytes([len(v)]) + v
    return out


def gen_h2(out, certdir, truth):
    keylog = out / "https_h2.keylog"
    keylog.unlink(missing_ok=True)
    w = PcapWriter(out / "https_h2.pcap")
    c = Conn(w, "10.10.1.50", 42000, "10.20.2.30", 443)
    t = c.handshake(T0)
    tls = Tls(certdir, keylog, alpn=["h2"])
    t, _ = play_handshake(c, tls, t + 0.005)
    tr = []
    streams = [(1, "/h2/slow", 1.5, 8000), (3, "/h2/fast", 0.05, 500), (5, "/h2/mid", 0.4, 2000)]
    data = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + h2_frame(4, 0, 0, b"")
    t = c.send(t + 0.01, True, tls.wrap(True, data))
    t = c.send(t + 0.002, False, tls.wrap(False, h2_frame(4, 0, 0, b"") + h2_frame(4, 1, 0, b"")))
    t = c.send(t + 0.002, True, tls.wrap(True, h2_frame(4, 1, 0, b"")))
    t0 = t + 0.01
    events = []
    for i, (sid, uri, svc, size) in enumerate(streams):
        ts = t0 + i * 0.01
        h = hpack([(":method", "GET"), (":scheme", "https"), (":authority", "app.example.test"), (":path", uri)])
        events.append((ts, True, h2_frame(1, 0x05, sid, h)))
        rh = hpack([(":status", "200"), ("content-type", "application/json"), ("content-length", str(size))])
        events.append((ts + svc, False, h2_frame(1, 0x04, sid, rh) + h2_frame(0, 0x01, sid, rand_body(size))))
        tr.append(dict(stream=sid, uri=uri, ttfb=svc))
    events.sort(key=lambda e: e[0])
    end = t0
    for ts, from_c, frame in events:
        end = c.send(ts, from_c, tls.wrap(from_c, frame))
    c.close(end + 0.05)
    w.close()
    truth["https_h2.pcap"] = dict(decrypt="keylog", streams=tr)


def gen_netscaler(out, certdir, truth):
    """Client side (TLS to VIP) and server side (HTTP via SNIP, one reused backend connection), same clock."""
    keylog = out / "netscaler_front.keylog"
    keylog.unlink(missing_ok=True)
    vip, snip, backend = "10.30.0.100", "10.30.0.5", "10.40.0.20"
    fw = PcapWriter(out / "netscaler_front.pcap")
    bw = PcapWriter(out / "netscaler_back.pcap")
    b = Conn(bw, snip, 50000, backend, 8080)
    t_b = b.handshake(T0 - 1)
    tr = []
    plan = [
        ("10.10.1.50", 43000, "/api/a/1", "req-1001", 0.20, 0.002, "backend slow"),
        ("10.10.1.51", 43001, "/api/a/2", "req-1002", 1.50, 0.002, "backend slow"),
        ("10.10.1.50", 43002, "/api/b/3", None, 0.05, 0.800, "netscaler delay"),
        ("10.10.1.52", 43003, "/api/b/4", None, 0.04, 0.003, "normal"),
    ]
    for i, (cip, cport, uri, rid, svc, ns_delay, cause) in enumerate(plan):
        c = Conn(fw, cip, cport, vip, 443)
        t = c.handshake(T0 + i * 4)
        tls = Tls(certdir, keylog)
        t, _ = play_handshake(c, tls, t + 0.005)
        ids = [f"X-Request-ID: {rid}"] if rid else []
        t2 = c.send(t + 0.01, True, tls.wrap(True, req("GET", uri, extra=ids)))
        bstart = max(t2 + ns_delay, t_b + 0.001)
        breq = req("GET", uri, extra=ids + [f"X-Forwarded-For: {cip}"])
        body = rand_body(2000)
        be = c2 = b.send(bstart, True, breq)
        c2 = b.send(be + svc, False, resp(200, body))
        t_b = c2
        t3 = c.send(c2 + 0.002, False, tls.wrap(False, resp(200, body)))
        tr.append(dict(uri=uri, client=cip, request_id=rid, backend_service=svc, ns_delay_req=ns_delay, cause=cause,
                       front_total=round(t3 - t, 6)))
        c.close(t3 + 0.05)
    b.close(t_b + 1)
    fw.close()
    bw.close()
    truth["netscaler_front.pcap+netscaler_back.pcap"] = tr


def gen_backends(out, truth):
    """Three servers behind a load balancer. One is slow, and one starts failing at a known moment."""
    w = PcapWriter(out / "backends.pcap")
    servers = {"10.50.0.1": 0.02, "10.50.0.2": 0.02, "10.50.0.3": 1.0}
    first_error = None
    for i in range(30):
        ip = list(servers)[i % 3]
        c = Conn(w, "10.30.0.5", 51000 + i, ip, 8080)
        t = T0 + i * 2
        t1 = c.handshake(t)
        t2 = c.send(t1 + 0.001, True, req("GET", f"/api/data/{i}"))
        failing = ip == "10.50.0.2" and i >= 16
        if failing and first_error is None:
            first_error = t
        t3 = c.send(t2 + servers[ip], False, resp(503, reason="Service Unavailable", body=b"busy") if failing else resp(200, b"ok"))
        c.close(t3 + 0.01)
    w.close()
    truth["backends.pcap"] = dict(slow="10.50.0.3", failing="10.50.0.2", first_error=first_error)


def gen_poor(out, truth):
    """A capture with known gaps: one side missing, packets the capture lost, and connections cut at both ends."""
    w = PcapWriter(out / "poor_capture.pcap")
    c = Conn(w, "10.60.0.1", 52000, "10.60.0.2", 8080)  # only the client side is visible
    t = T0
    c.emit(t, True, SYN)
    c.emit(t + 0.01, True, PSH | ACK, req("GET", "/one-way"))
    c = Conn(w, "10.60.0.1", 52001, "10.60.0.2", 8080)  # the server acknowledges data the capture never saw
    t1 = c.handshake(t + 1)
    t2 = c.send(t1 + 0.001, True, req("GET", "/gap"))
    c.seq[True] += 5000
    c.emit(t2 + 0.01, False, ACK)
    c.send(t2 + 0.02, True, b"z" * 100)
    c = Conn(w, "10.60.0.1", 52002, "10.60.0.2", 8080)  # started before the capture and never closed
    c.send(t + 2, True, req("GET", "/mid"))
    c.send(t + 2.1, False, resp(200, b"ok"))
    w.close()
    truth["poor_capture.pcap"] = dict(unseen=1, one_way=1)


def gen_split(out, truth):
    """Long headers that do not fit one segment, and a body in a segment of its own."""
    w = PcapWriter(out / "split_headers.pcap")
    c = Conn(w, "10.60.0.3", 53000, "10.60.0.4", 8080)
    t = c.handshake(T0)
    for i in range(3):
        t = c.send(t + 0.01, True, req("GET", f"/long/{i}", extra=["Cookie: a=" + "b" * 3000, "X-Tail: 1"]))
        head = b"HTTP/1.1 200 OK\r\nContent-Length: 500\r\nX-Pad: " + b"p" * 3000 + b"\r\n\r\n"
        t = c.send(t + 0.1, False, head)
        t = c.send(t + 0.01, False, b"y" * 500)
    c.close(t + 0.01)
    w.close()
    truth["split_headers.pcap"] = dict(requests=3)


def gen_perf(out, certdir, truth):
    target = 100 * 1024 * 1024
    for name, use_tls in (("perf_http_100mb.pcap", False), ("perf_https_100mb.pcap", True)):
        keylog = out / (name.replace(".pcap", "") + ".keylog")
        keylog.unlink(missing_ok=True)
        w = PcapWriter(out / name)
        size, n, conns = 24, 0, 0
        random.seed(7)
        body = rand_body(30000)
        while size < target:
            t = T0 + conns * 0.05
            cl = f"10.{50 + conns % 8}.{conns % 200}.{1 + conns % 250}"
            c = Conn(w, cl, 20000 + conns % 40000, "10.20.2.40", 443 if use_tls else 8080)
            t = c.handshake(t)
            tls = None
            if use_tls:
                tls = Tls(certdir, keylog)
                t, _ = play_handshake(c, tls, t + 0.001)
            for j in range(5):
                q, a = req("GET", f"/api/item/{conns}/{j}"), resp(200, body)
                if tls:
                    q, a = tls.wrap(True, q), tls.wrap(False, a)
                t = c.send(t + 0.005, True, q)
                t = c.send(t + 0.01 + (j * conns) % 7 * 0.01, False, a)
            c.close(t + 0.01)
            conns += 1
            if conns % 50 == 0:
                size = 24 + sum(len(f) + 16 for _, f in w.frames)
        n = len(w.frames)
        w.close()
        truth[name] = dict(packets=n, connections=conns, transactions=conns * 5, size=(out / name).stat().st_size)


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    out = Path(args[0] if args else "samples")
    out.mkdir(parents=True, exist_ok=True)
    random.seed(42)
    if not (out / "test_key.pem").exists():
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "3650",
                        "-subj", "/CN=app.example.test", "-addext", "subjectAltName=DNS:app.example.test", "-keyout", out / "test_key.pem", "-out", out / "test_cert.pem"],
                       check=True, capture_output=True)
    truth = {}
    gen_http(out, truth)
    gen_tls(out, out, truth)
    gen_h2(out, out, truth)
    gen_netscaler(out, out, truth)
    gen_backends(out, truth)
    gen_poor(out, truth)
    gen_split(out, truth)
    if "--perf" in sys.argv:
        gen_perf(out, out, truth)
    (out / "truth.json").write_text(json.dumps(truth, indent=2))
    for p in sorted(out.iterdir()):
        print(f"{p.stat().st_size:>11} {p.name}")


if __name__ == "__main__":
    main()
