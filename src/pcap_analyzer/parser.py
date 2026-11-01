"""Turn tshark packets into connections, HTTP transactions and TCP events."""
from collections import deque
from dataclasses import dataclass, field

from .tshark import AGG, EVENTS

SYN, ACK, FIN, RST = 0x02, 0x10, 0x01, 0x04
TLS_ALERT = 21
RTT_INDISTINCT = 0.0005  # below this, timestamps cannot tell near from far


def many(p, key):
    v = p.get(key, "")
    return v.split(AGG) if v else []


def first(p, key):
    v = p.get(key, "")
    return v.split(AGG, 1)[0] if v else None


def to_int(v):
    try:
        return int(v, 0) if v not in (None, "") else None
    except ValueError:
        return None


def to_float(v):
    try:
        return float(v) if v not in (None, "") else None
    except ValueError:
        return None


def header(block, name):
    """Find one header in tshark's http.request.line / http.response.line list."""
    prefix = name.lower() + ":"
    for line in block:
        if line.lower().startswith(prefix):
            return line[len(prefix):].removesuffix("\\r\\n").strip()  # tshark prints CRLF as literal text
    return None


@dataclass
class Packet:
    frame: int
    t: float
    size: int
    src: str
    payload: int
    flags: int
    tls_alert_only: bool
    retrans: bool


@dataclass
class Stream:
    sid: int
    a: tuple
    b: tuple
    packets: list = field(default_factory=list)
    client: tuple | None = None
    syn: Packet | None = None
    synack: Packet | None = None
    hs_ack: Packet | None = None
    rtt_srv: list = field(default_factory=list)
    rtt_cli: list = field(default_factory=list)
    mss: list = field(default_factory=list)
    requests: list = field(default_factory=list)
    responses: list = field(default_factory=list)
    h2: dict = field(default_factory=dict)
    sni: str | None = None
    tls_version: str | None = None
    tls_seen: bool = False
    tls_start: Packet | None = None
    tls_end: Packet | None = None
    pending_rtt: list = field(default_factory=list)


class Builder:
    def __init__(self):
        self.streams = {}
        self.events = []
        self.dns = {}
        self.dns_rows = []
        self.total = self.tcp = self.bytes = self.truncated = 0
        self.t_first = self.t_last = None

    def add(self, p):
        self.total += 1
        size = to_int(p["frame.len"]) or 0
        self.bytes += size
        cap = to_int(p["frame.cap_len"])
        if cap is not None and cap < size:
            self.truncated += 1
        t = float(p["frame.time_epoch"])
        self.t_first = t if self.t_first is None else min(self.t_first, t)
        self.t_last = t if self.t_last is None else max(self.t_last, t)
        if p.get("dns.time"):
            self.dns_rows.append((first(p, "dns.qry.name"), to_float(p["dns.time"]), to_int(p["frame.number"]), t))
        sid = to_int(p.get("tcp.stream"))
        if sid is None:
            return
        self.tcp += 1
        frame = int(p["frame.number"])
        src_ip = first(p, "ip.src") or first(p, "ipv6.src")
        dst_ip = first(p, "ip.dst") or first(p, "ipv6.dst")
        src = (src_ip, int(p["tcp.srcport"]))
        dst = (dst_ip, int(p["tcp.dstport"]))
        s = self.streams.get(sid)
        if s is None:
            s = self.streams[sid] = Stream(sid, src, dst)
        flags = to_int(p["tcp.flags"]) or 0
        payload = to_int(p["tcp.len"]) or 0
        ctypes = [to_int(x) for x in many(p, "tls.record.content_type")]
        retrans = bool(p.get("tcp.analysis.retransmission") or p.get("tcp.analysis.fast_retransmission"))
        pk = Packet(frame, t, size, src, payload, flags, bool(ctypes) and all(c == TLS_ALERT for c in ctypes), retrans)
        s.packets.append(pk)
        for e in EVENTS:
            if p.get(f"tcp.analysis.{e}"):
                self.events.append((sid, frame, t, f"{src[0]}:{src[1]}", e))
        if flags & SYN and not flags & ACK:
            s.syn = s.syn or pk
            s.client = src
        elif flags & SYN and flags & ACK:
            s.synack = s.synack or pk
            s.client = s.client or dst
        elif s.synack and not s.hs_ack and flags & ACK and src == s.client:
            s.hs_ack = pk
        mss = to_int(p.get("tcp.options.mss_val"))
        if mss:
            s.mss.append(mss)
        rtt = to_float(p.get("tcp.analysis.ack_rtt"))
        if rtt is not None:
            s.pending_rtt.append((src, rtt))
        self._tls(p, s, pk, src, ctypes)
        self._http1(p, s, pk, src, dst)
        self._http2(p, s, pk, src, dst)

    def _tls(self, p, s, pk, src, ctypes):
        if not ctypes:
            return
        s.tls_seen = True
        if s.tls_start is None:
            s.tls_start = pk
        hs = [to_int(x) for x in many(p, "tls.handshake.type")]
        s.sni = s.sni or first(p, "tls.handshake.extensions_server_name")
        if 2 in hs:
            v = many(p, "tls.handshake.extensions.supported_version")
            s.tls_version = {"0x0304": "TLS 1.3", "0x0303": "TLS 1.2", "0x0302": "TLS 1.1", "0x0301": "TLS 1.0"}.get(
                v[-1] if v else "0x0303", "unknown")
        if 20 in hs and s.client == src:
            s.tls_end = pk

    def _http1(self, p, s, pk, src, dst):
        segs = sorted({int(x) for k in ("tcp.segment", "tls.segment") for x in many(p, k)})
        methods = many(p, "http.request.method")
        if methods:
            uris, hosts, versions = many(p, "http.request.uri"), many(p, "http.host"), many(p, "http.request.version")
            lines = many(p, "http.request.line")
            s.client = s.client or src
            for i, m in enumerate(methods):
                s.requests.append(dict(
                    frame=pk.frame, start_frame=min(segs + [pk.frame]), method=m,
                    uri=uris[i] if i < len(uris) else None, host=hosts[i] if i < len(hosts) else None,
                    version=versions[i] if i < len(versions) else "HTTP/1.1",
                    xff=first(p, "http.x_forwarded_for"), request_id=header(lines, "x-request-id"),
                    content_length=to_int(first(p, "http.content_length"))))
        codes = many(p, "http.response.code")
        if codes:
            s.client = s.client or dst
            phrases = many(p, "http.response.phrase")
            lines = many(p, "http.response.line")
            lengths = many(p, "http.content_length")
            for i, c in enumerate(codes):
                s.responses.append(dict(
                    frame=pk.frame, start_frame=min(segs + [pk.frame]), status=int(c),
                    phrase=phrases[i] if i < len(phrases) else None,
                    content_length=to_int(lengths[i]) if i < len(lengths) else None,
                    content_type=first(p, "http.content_type"), encoding=first(p, "http.content_encoding"),
                    transfer=first(p, "http.transfer_encoding"), server_timing=header(lines, "server-timing")))

    def _http2(self, p, s, pk, src, dst):
        types = many(p, "http2.type")
        if not types:
            return
        ids, flags, lengths = many(p, "http2.streamid"), many(p, "http2.flags"), many(p, "http2.length")
        counts = [int(x) for x in many(p, "http2.header.count")]
        names, values = many(p, "http2.header.name"), many(p, "http2.header.value")
        hpos = cpos = 0
        for i, ty in enumerate(types):
            sid2 = int(ids[i]) if i < len(ids) else 0
            fl = int(flags[i], 16) if i < len(flags) else 0
            ln = int(lengths[i]) if i < len(lengths) else 0
            hdrs = {}
            if ty == "1":
                n = counts[cpos] if cpos < len(counts) else 0
                cpos += 1
                hdrs = dict(zip(names[hpos:hpos + n], values[hpos:hpos + n]))
                hpos += n
            if sid2 == 0 or ty not in ("0", "1"):
                continue
            if ":method" in hdrs:
                s.client = s.client or src
            elif ":status" in hdrs:
                s.client = s.client or dst
            st = s.h2.setdefault(sid2, dict(req=None, resp=None, c_end=None, s_end=None, c_data=0, s_data=0, last_s=None))
            is_client = src == s.client
            if ":method" in hdrs:
                st["req"] = dict(hdrs, frame=pk.frame, t=pk.t)
            if ":status" in hdrs and not hdrs[":status"].startswith("1"):
                st["resp"] = dict(hdrs, frame=pk.frame, t=pk.t)
            if ty == "0":
                st["c_data" if is_client else "s_data"] += ln
            if is_client:
                st["last_c"] = pk
            else:
                st["last_s"] = pk
            if fl & 1:
                st["c_end" if is_client else "s_end"] = pk


def pick_rtt(handshake, samples):
    vals = [v for v in [handshake] + samples if v is not None and v >= 0]
    return min(vals) if vals else None


def capture_point(rtt_srv, rtt_cli):
    if rtt_srv is None or rtt_cli is None or max(rtt_srv, rtt_cli) < RTT_INDISTINCT:
        return "unknown"
    if rtt_cli <= 0.25 * rtt_srv:
        return "near_client"
    if rtt_srv <= 0.25 * rtt_cli:
        return "near_server"
    return "middle"


def finish_stream(s):
    """Return (connection row, transaction rows) for one stream."""
    client = s.client or min(s.a, s.b, key=lambda e: -e[1])
    server = s.b if client == s.a else s.a
    for src, rtt in s.pending_rtt:
        (s.rtt_cli if src == client else s.rtt_srv).append(rtt)
    hs_srv = s.synack.t - s.syn.t if s.syn and s.synack else None
    hs_cli = s.hs_ack.t - s.synack.t if s.synack and s.hs_ack else None
    rtt_srv, rtt_cli = pick_rtt(hs_srv, s.rtt_srv), pick_rtt(hs_cli, s.rtt_cli)
    connect = hs_srv + hs_cli if hs_srv is not None and hs_cli is not None else None
    tls_time = s.tls_end.t - s.tls_start.t if s.tls_start and s.tls_end else None
    closer = next((p for p in s.packets if p.flags & RST), None) or next((p for p in s.packets if p.flags & FIN), None)
    txns = _h1_transactions(s, client, rtt_srv) + _h2_transactions(s, client, rtt_srv)
    txns.sort(key=lambda x: x["req_start"])
    for i, x in enumerate(txns):
        x["seq_on_conn"] = i + 1
        x["new_conn"] = i == 0 and s.syn is not None
        x["connect_time"] = connect if x["new_conn"] else None
        x["tls_time"] = tls_time if x["new_conn"] else None
    kind = "HTTP/2" if s.h2 else "HTTP" if s.requests or s.responses else "TCP"
    if s.tls_seen:
        kind = "HTTPS/2" if s.h2 else "HTTPS" if txns else "TLS"
    conn = dict(
        stream=s.sid, client_ip=client[0], client_port=client[1], server_ip=server[0], server_port=server[1],
        kind=kind, first_frame=s.packets[0].frame, start_time=s.packets[0].t, end_time=s.packets[-1].t,
        duration=s.packets[-1].t - s.packets[0].t, packets=len(s.packets), bytes=sum(p.size for p in s.packets),
        payload_client=sum(p.payload for p in s.packets if p.src == client),
        payload_server=sum(p.payload for p in s.packets if p.src != client),
        handshake_seen=s.syn is not None and s.synack is not None, connect_time=connect,
        rtt_server=rtt_srv, rtt_client=rtt_cli, capture_point=capture_point(rtt_srv, rtt_cli), mss=min(s.mss) if s.mss else None,
        tls_version=s.tls_version, sni=s.sni, tls_time=tls_time,
        close_type="RST" if closer and closer.flags & RST else "FIN" if closer else None,
        closed_by=None if not closer else "client" if closer.src == client else "server",
        transactions=len(txns))
    return conn, txns


def _h1_transactions(s, client, rtt_srv):
    if not s.requests and not s.responses:
        return []
    frames = {p.frame: p for p in s.packets}
    finals = deque(r for r in s.responses if r["status"] >= 200)
    pairs = [(q, finals.popleft() if finals else None) for q in s.requests]
    pairs += [(None, r) for r in finals]
    out = []
    rs = [r["start_frame"] for _, r in pairs if r]
    for i, (q, r) in enumerate(pairs):
        if q is None:
            continue  # response whose request was not captured
        next_q = pairs[i + 1][0]["start_frame"] if i + 1 < len(pairs) and pairs[i + 1][0] else 1 << 62
        r_start = r["start_frame"] if r else None
        next_r = next((f for f in rs if r_start is not None and f > r_start), 1 << 62)
        req_pk = [p for p in s.packets if p.src == client and p.payload and q["start_frame"] <= p.frame < min(next_q, r_start or 1 << 62)]
        resp_pk = [p for p in s.packets if p.src != client and p.payload and not p.tls_alert_only and r_start is not None and r_start <= p.frame < next_r]
        q_first = frames[q["start_frame"]] if q["start_frame"] in frames else frames[q["frame"]]
        q_last = req_pk[-1] if req_pk else q_first
        r_first = frames.get(r_start) if r else None
        r_last = resp_pk[-1] if resp_pk else r_first
        out.append(_row(s, q["method"], q["uri"], q["host"], q["version"], r and r["status"], r and r["phrase"],
                        q_first, q_last, r_first, r_last, rtt_srv, sum(p.payload for p in req_pk if not p.retrans),
                        sum(p.payload for p in resp_pk if not p.retrans), q["content_length"], r and r["content_length"],
                        r and r["content_type"], r and r["encoding"], r and r["transfer"], r and r["server_timing"],
                        q["xff"], q["request_id"], None))
    return out


def _h2_transactions(s, client, rtt_srv):
    out = []
    for sid2, st in s.h2.items():
        q, r = st["req"], st["resp"]
        if not q:
            continue
        frames = {p.frame: p for p in s.packets}
        q_first = frames[q["frame"]]
        q_last = st["c_end"] or st.get("last_c") or q_first
        r_first = frames[r["frame"]] if r else None
        r_last = st["s_end"] or st["last_s"] or r_first
        out.append(_row(s, q.get(":method"), q.get(":path"), q.get(":authority"), "HTTP/2", to_int((r or {}).get(":status")), None,
                        q_first, q_last, r_first, r_last, rtt_srv, st["c_data"], st["s_data"],
                        to_int(q.get("content-length")), to_int((r or {}).get("content-length")),
                        (r or {}).get("content-type"), (r or {}).get("content-encoding"), None, (r or {}).get("server-timing"),
                        q.get("x-forwarded-for"), q.get("x-request-id"), sid2))
    return out


def _row(s, method, uri, host, version, status, phrase, q_first, q_last, r_first, r_last, rtt_srv,
         req_bytes, resp_bytes, req_clen, resp_clen, ctype, enc, transfer, server_timing, xff, rid, h2_stream):
    wait = r_first.t - q_last.t if r_first else None
    service = wait - rtt_srv if wait is not None and rtt_srv is not None else None
    if service is not None and service < 0:
        service = None  # RTT estimate exceeded the wait, so the split is not measurable
    end = r_last or q_last
    return dict(
        stream=s.sid, h2_stream=h2_stream, method=method, uri=uri, host=host, http_version=version,
        status=status, phrase=phrase, answered=r_first is not None, req_frame=q_first.frame, resp_frame=r_first.frame if r_first else None,
        req_start=q_first.t, req_end=q_last.t, resp_start=r_first.t if r_first else None, resp_end=r_last.t if r_last else None,
        request_send=q_last.t - q_first.t, wait=wait, service=service,
        ttfb=r_first.t - q_first.t if r_first else None, transfer=r_last.t - r_first.t if r_first else None,
        total=end.t - q_first.t if r_first else None, req_bytes=req_bytes, resp_bytes=resp_bytes,
        req_content_length=req_clen, resp_content_length=resp_clen, content_type=ctype, content_encoding=enc,
        transfer_encoding=transfer, server_timing=server_timing, x_forwarded_for=xff, request_id=rid)
