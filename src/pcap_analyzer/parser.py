"""Turn tshark packets into connections, HTTP transactions and TCP events."""
import math
import re
from collections import deque
from dataclasses import dataclass, field

from . import causes, privacy, urls
from .tshark import AGG, EVENTS

SYN, ACK, FIN, RST = 0x02, 0x10, 0x01, 0x04
TLS_ALERT = 21
RTT_INDISTINCT = 0.0005  # below this, timestamps cannot tell near from far
BODY_PREVIEW = 2000
DELAYED_ACK_MIN, DELAYED_ACK_MAX = 0.03, 0.5
SEND_AFTER_ACK = 0.01
NO_BODY_METHODS = ("HEAD", "CONNECT")
NO_BODY_STATUS = (204, 304)


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


def clean_line(line):
    return line.removesuffix("\\r\\n").strip()  # tshark prints CRLF as literal text


def header(block, name):
    """Find one header in tshark's http.request.line / http.response.line list."""
    prefix = name.lower() + ":"
    for line in block:
        if line.lower().startswith(prefix):
            return clean_line(line[len(prefix):])
    return None


def masked_headers(pairs):
    return "\n".join(f"{k}: {privacy.mask_header(k, v)}" for k, v in pairs)


def line_pairs(block):
    pairs = []
    for line in block:
        name, _, value = clean_line(line).partition(":")
        pairs.append((name, value.strip()))
    return pairs


def preview(raw):
    """First part of a body as text; tshark gives hex, and binary data is left out rather than shown as noise."""
    if not raw:
        return None
    try:
        data = bytes.fromhex(raw.replace(":", "")[:BODY_PREVIEW * 2])
    except ValueError:
        return None
    text = data.decode("utf-8", "replace")
    bad = sum(1 for c in text if c == "\ufffd" or (ord(c) < 32 and c not in "\r\n\t"))
    return None if bad > len(text) * 0.05 else privacy.mask_body(text)


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
    win: int = 0


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
    wscale: int | None = None
    sack: bool = False
    zero_windows: list = field(default_factory=list)
    offload: bool = False


class Builder:
    def __init__(self):
        self.streams = {}
        self.events = []
        self.dns = {}
        self.dns_rows = []
        self.total = self.tcp = self.bytes = self.truncated = self.fragments = self.frag_needed = 0
        self.t_first = self.t_last = None

    def add(self, p):
        self.total += 1
        size = to_int(p["frame.len"]) or 0
        self.bytes += size
        cap = to_int(p["frame.cap_len"])
        if cap is not None and cap < size:
            self.truncated += 1
        if first(p, "ip.flags.mf") in ("1", "True"):
            self.fragments += 1
        if first(p, "icmp.type") == "3" and first(p, "icmp.code") == "4":
            self.frag_needed += 1
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
        win = to_int(p.get("tcp.window_size")) or 0
        pk = Packet(frame, t, size, src, payload, flags, bool(ctypes) and all(c == TLS_ALERT for c in ctypes), retrans, win)
        s.packets.append(pk)
        for e in EVENTS:
            if p.get(f"tcp.analysis.{e}"):
                self.events.append((sid, frame, t, f"{src[0]}:{src[1]}", e))
        if p.get("tcp.analysis.zero_window"):
            s.zero_windows.append(pk)
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
        if s.mss and payload > max(s.mss) and not s.tls_seen:
            s.offload = True
        shift = to_int(first(p, "tcp.options.wscale.shift"))
        if shift is not None:
            s.wscale = shift if s.wscale is None else min(s.wscale, shift)
        s.sack = s.sack or bool(p.get("tcp.options.sack_perm"))
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
            bodies = many(p, "http.file_data")
            s.client = s.client or src
            for i, m in enumerate(methods):
                s.requests.append(dict(
                    frame=pk.frame, start_frame=min(segs + [pk.frame]), method=m,
                    uri=uris[i] if i < len(uris) else None, host=hosts[i] if i < len(hosts) else None,
                    version=versions[i] if i < len(versions) else "HTTP/1.1",
                    xff=first(p, "http.x_forwarded_for"), request_id=header(lines, "x-request-id"),
                    content_length=to_int(first(p, "http.content_length")), headers=masked_headers(line_pairs(lines)),
                    body=preview(bodies[0]) if bodies else None))
        codes = many(p, "http.response.code")
        if codes:
            s.client = s.client or dst
            phrases = many(p, "http.response.phrase")
            lines = many(p, "http.response.line")
            lengths = many(p, "http.content_length")
            bodies = many(p, "http.file_data")
            versions = many(p, "http.response.version")
            for i, c in enumerate(codes):
                head = f"{versions[i] if i < len(versions) else 'HTTP/1.1'} {c} {phrases[i] if i < len(phrases) else ''}"
                head_len = len(head) + 2 + sum(len(clean_line(x)) + 2 for x in lines) + 2
                s.responses.append(dict(
                    frame=pk.frame, start_frame=min(segs + [pk.frame]), status=int(c),
                    phrase=phrases[i] if i < len(phrases) else None,
                    content_length=to_int(lengths[i]) if i < len(lengths) else None,
                    content_type=first(p, "http.content_type"), encoding=first(p, "http.content_encoding"),
                    transfer=first(p, "http.transfer_encoding"), server_timing=header(lines, "server-timing"),
                    response_time=header(lines, "x-response-time"), headers=masked_headers(line_pairs(lines)),
                    head_len=head_len, body=preview(bodies[0]) if bodies else None))

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
    pay_c = sum(p.payload for p in s.packets if p.src == client)
    pay_s = sum(p.payload for p in s.packets if p.src != client)
    conn = dict(
        stream=s.sid, client_ip=client[0], client_port=client[1], server_ip=server[0], server_port=server[1],
        kind=kind, first_frame=s.packets[0].frame, start_time=s.packets[0].t, end_time=s.packets[-1].t,
        duration=s.packets[-1].t - s.packets[0].t, packets=len(s.packets), bytes=sum(p.size for p in s.packets),
        payload_client=pay_c, payload_server=pay_s,
        handshake_seen=s.syn is not None and s.synack is not None, connect_time=connect,
        rtt_server=rtt_srv, rtt_client=rtt_cli, capture_point=capture_point(rtt_srv, rtt_cli), mss=min(s.mss) if s.mss else None,
        tls_version=s.tls_version, sni=s.sni, tls_time=tls_time,
        close_type="RST" if closer and closer.flags & RST else "FIN" if closer else None,
        closed_by=None if not closer else "client" if closer.src == client else "server",
        transactions=len(txns), sack=s.sack, wscale=s.wscale, min_window=min((p.win for p in s.packets if not p.flags & SYN), default=None),
        retransmissions=sum(1 for p in s.packets if p.retrans), zero_windows=len(s.zero_windows),
        byte_ratio_db=_ratio_db(pay_c, pay_s), offload=s.offload)
    _enrich(s, client, txns, conn)
    return conn, txns


def _ratio_db(a, b):
    """How one-sided a connection is, in dB. 3 dB is about double, capped at 100."""
    if not a or not b:
        return 100.0 if a or b else 0.0
    return round(min(100.0, 10 * math.log10(max(a, b) / min(a, b))), 1)


def _stalls(s, lo, hi):
    """Retransmission and zero window waiting inside a frame range."""
    last_seen = {}
    retrans_n, retrans_t = 0, 0.0
    for p in s.packets:
        if p.frame > hi:
            break
        if p.payload:
            if lo <= p.frame and p.retrans and p.src in last_seen:
                retrans_n += 1
                retrans_t += p.t - last_seen[p.src]
            last_seen[p.src] = p.t
    zero_t = 0.0
    for z in s.zero_windows:
        if lo <= z.frame <= hi:
            after = next((p for p in s.packets if p.frame > z.frame and p.src == z.src and p.win > 0), None)
            if after:
                zero_t += after.t - z.t
    return retrans_n, retrans_t, zero_t


def _delayed_ack(s, sender, lo, hi):
    """Time a sender sat idle until a late bare ACK released its next segment."""
    pk = [p for p in s.packets if lo <= p.frame <= hi]
    total = 0.0
    prev = None
    for p in pk:
        if p.src != sender or not p.payload:
            continue
        if prev is not None:
            acks = [a for a in pk if prev.frame < a.frame < p.frame and a.src != sender and not a.payload and a.flags & ACK]
            if acks and DELAYED_ACK_MIN <= acks[-1].t - prev.t <= DELAYED_ACK_MAX and p.t - acks[-1].t <= SEND_AFTER_ACK:
                total += p.t - prev.t
        prev = p
    return total


def _enrich(s, client, txns, conn):
    server = next((e for e in (s.a, s.b) if e != client), None)
    for i, t in enumerate(txns):
        lo = t["req_frame"]
        hi = t["last_frame"] or t["req_frame"]
        n, retrans, zero = _stalls(s, lo, hi)
        delayed_req = _delayed_ack(s, client, lo, t["resp_frame"] or hi)
        delayed_resp = _delayed_ack(s, server, t["resp_frame"], hi) if t["resp_frame"] else 0.0
        t.update(retrans_count=n, retrans_time=retrans, zero_window_time=zero, delayed_ack_time=delayed_req + delayed_resp,
                 queue_time=0.0, network=conn["rtt_server"] if t["answered"] else 0.0)
        prev = txns[i - 1] if i else None
        if prev and t["h2_stream"] is None and prev["resp_end"] and prev["resp_end"] > t["req_end"] and t["answered"]:
            t["queue_time"] = prev["resp_end"] - t["req_end"]
        if t["wait"] is not None and t["network"] is not None:
            svc = t["wait"] - t["network"] - t["queue_time"]
            t["service"] = svc if svc >= 0 else None
        if t["queue_time"] and t["service"] is None:
            t["service"] = 0.0
        moved = retrans + zero + delayed_resp
        t["transfer_clean"] = max(_or0(t["transfer"]) - moved, 0.0)
        t["request_clean"] = max(t["request_send"] - delayed_req - max(moved - _or0(t["transfer"]), 0.0), 0.0)
        if t["head_len"] is not None:
            t["body_bytes"] = max(t["resp_bytes"] - t["head_len"], 0)
        elif t["http_version"] == "HTTP/2":
            t["body_bytes"] = t["resp_bytes"]
        clen = t["resp_content_length"]
        t["truncated"] = bool(t["answered"] and clen and t["body_expected"] and t["body_bytes"] is not None
                              and t["body_bytes"] < clen and not conn["kind"].startswith("HTTPS"))
        t["server_reported"] = causes.parse_server_timing(t["server_timing"])
        t["cause"], t["cause_share"], flags = causes.classify(t, conn)
        t["flags"] = ",".join(flags)


def _or0(v):
    return v or 0.0


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
                        r and r["content_type"], r and r["encoding"], r and r["transfer"], r and (r["server_timing"] or _rt(r)),
                        q["xff"], q["request_id"], None))
        out[-1].update(req_headers=q["headers"], resp_headers=r and r["headers"], req_body=q["body"], resp_body=r and r["body"],
                       head_len=r and r["head_len"], last_frame=r_last.frame if r_last else None,
                       body_expected=bool(r) and q["method"] not in NO_BODY_METHODS and r["status"] not in NO_BODY_STATUS)
    return out


def _rt(r):
    """Turn X-Response-Time into Server-Timing form so one parser reads both."""
    m = re.fullmatch(r"([0-9.]+)\s*(ms|s)?", r["response_time"] or "")
    if not m:
        return None
    return f"app;dur={float(m[1]) * (1000 if m[2] == 's' else 1)}"


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
        out[-1].update(req_headers=_h2_headers(q), resp_headers=_h2_headers(r) if r else None, req_body=None, resp_body=None,
                       head_len=None, last_frame=r_last.frame if r_last else None,
                       body_expected=bool(r) and q.get(":method") not in NO_BODY_METHODS)
    return out


def _h2_headers(h):
    return masked_headers((k, v) for k, v in h.items() if k not in ("frame", "t"))


def _row(s, method, uri, host, version, status, phrase, q_first, q_last, r_first, r_last, rtt_srv,
         req_bytes, resp_bytes, req_clen, resp_clen, ctype, enc, transfer, server_timing, xff, rid, h2_stream):
    wait = r_first.t - q_last.t if r_first else None
    service = wait - rtt_srv if wait is not None and rtt_srv is not None else None
    if service is not None and service < 0:
        service = None  # RTT estimate exceeded the wait, so the split is not measurable
    end = r_last or q_last
    return dict(
        stream=s.sid, h2_stream=h2_stream, method=method, uri=privacy.mask_uri(uri), url_template=urls.template(uri), host=host, http_version=version,
        status=status, phrase=phrase, answered=r_first is not None, req_frame=q_first.frame, resp_frame=r_first.frame if r_first else None,
        req_start=q_first.t, req_end=q_last.t, resp_start=r_first.t if r_first else None, resp_end=r_last.t if r_last else None,
        request_send=q_last.t - q_first.t, wait=wait, service=service,
        ttfb=r_first.t - q_first.t if r_first else None, transfer=r_last.t - r_first.t if r_first else None,
        total=end.t - q_first.t if r_first else None, req_bytes=req_bytes, resp_bytes=resp_bytes,
        req_content_length=req_clen, resp_content_length=resp_clen, content_type=ctype, content_encoding=enc,
        transfer_encoding=transfer, server_timing=server_timing, x_forwarded_for=xff, request_id=rid)
