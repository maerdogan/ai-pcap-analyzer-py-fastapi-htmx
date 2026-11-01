"""Read-only reports over one analysis. The CLI and the web interface share these."""
from dataclasses import dataclass

from . import causes

SUCCESS = "status BETWEEN 200 AND 399"
TIME_STATS = """count(*) AS requests, count(*) FILTER ({ok}) AS ok,
    count(*) FILTER (status >= 400 OR NOT answered) AS failed, avg(total) AS avg_total,
    median(total) AS p50_total, quantile_cont(total, 0.95) AS p95_total, max(total) AS max_total,
    avg(wait) AS avg_wait, avg(service) AS avg_service, avg(transfer) AS avg_transfer,
    sum(resp_bytes) AS resp_bytes""".format(ok=SUCCESS)
TOP_DEFAULT = 5
TOP_PERCENT = 0.10
SLOWEST = 10


def rows(db, sql, params=()):
    cur = db.execute(sql, params)
    cols = [c[0] for c in cur.description]
    return [dict(zip(cols, r)) for r in cur.fetchall()]


def one(db, sql, params=()):
    got = rows(db, sql, params)
    return got[0] if got else None


def overview(db, meta):
    http = one(db, f"SELECT {TIME_STATS} FROM http_transactions")
    tcp = one(db, """SELECT count(*) AS connections, count(*) FILTER (handshake_seen) AS handshakes,
        count(*) FILTER (close_type = 'RST') AS resets, avg(connect_time) AS avg_connect, avg(duration) AS avg_duration,
        avg(rtt_server) AS avg_rtt_server, sum(retransmissions) AS retransmissions FROM tcp_connections""")
    return dict(
        meta=meta, http=http, tcp=tcp,
        kinds=rows(db, "SELECT kind, count(*) AS connections, sum(bytes) AS bytes FROM tcp_connections GROUP BY 1 ORDER BY 2 DESC"),
        statuses=rows(db, """SELECT coalesce(CAST(status // 100 AS VARCHAR) || 'xx', 'none') AS class, count(*) AS requests
            FROM http_transactions GROUP BY 1 ORDER BY 1"""),
        capture_points=rows(db, "SELECT capture_point, count(*) AS connections FROM tcp_connections GROUP BY 1 ORDER BY 2 DESC"))


def _where(flt):
    return (" WHERE " + flt[0], flt[1]) if flt and flt[0] else ("", [])


def url_groups(db, flt=None):
    """URL shapes, slowest first, each with its status codes underneath."""
    where, params = _where(flt)
    groups = rows(db, f"""SELECT coalesce(method, '') AS method, coalesce(url_template, '') AS url, {TIME_STATS}
        FROM http_transactions{where} GROUP BY 1, 2 ORDER BY avg_total DESC NULLS LAST""", params)
    detail = rows(db, f"""SELECT coalesce(method, '') AS method, coalesce(url_template, '') AS url, status,
        count(*) AS requests, avg(total) AS avg_total, max(total) AS max_total
        FROM http_transactions{where} GROUP BY 1, 2, 3 ORDER BY status NULLS LAST""", params)
    for g in groups:
        g["statuses"] = [d for d in detail if (d["method"], d["url"]) == (g["method"], g["url"])]
    return groups


def connections(db, flt=None):
    where, params = _where(flt)
    return rows(db, f"""SELECT c.*, count(t.id) AS requests, avg(t.total) AS avg_total, max(t.total) AS max_total
        FROM tcp_connections c LEFT JOIN http_transactions t USING (stream){where}
        GROUP BY ALL ORDER BY max_total DESC NULLS LAST, c.stream""", params)


def connection_top(db, stream, percent=False):
    """Slowest requests of one connection: the first 5, or the top 10 percent."""
    total = one(db, "SELECT count(*) AS n FROM http_transactions WHERE stream = ?", [stream])["n"]
    limit = max(1, int(total * TOP_PERCENT + 0.999)) if percent else TOP_DEFAULT
    return dict(conn=one(db, "SELECT * FROM tcp_connections WHERE stream = ?", [stream]), total=total,
                top=rows(db, "SELECT * FROM http_transactions WHERE stream = ? ORDER BY total DESC NULLS FIRST LIMIT ?", [stream, limit]))


def hosts(db):
    """Group by name instead of address: HTTP Host, then TLS SNI, then server IP."""
    return rows(db, """WITH named AS (
            SELECT c.stream, c.server_ip, c.bytes, coalesce(split_part(min(t.host), ':', 1), c.sni, c.server_ip) AS host,
                count(t.id) AS requests
            FROM tcp_connections c LEFT JOIN http_transactions t USING (stream)
            GROUP BY c.stream, c.server_ip, c.bytes, c.sni)
        SELECT host, count(*) AS connections, list_sort(list(DISTINCT server_ip)) AS addresses, sum(bytes) AS bytes,
            sum(requests) AS requests
        FROM named GROUP BY host ORDER BY bytes DESC""")


@dataclass(frozen=True)
class Inspect:
    """Focused view on one source, destination, port and connection type."""
    src: str | None = None
    dst: str | None = None
    port: int | None = None
    kind: str | None = None  # TCP, HTTP, HTTPS, HTTP/2, HTTPS/2
    url: str | None = None
    min_size: int | None = None
    size_of: str = "total"  # total, request, response, packet


SIZE_SQL = {"total": "coalesce(t.req_bytes, 0) + coalesce(t.resp_bytes, 0)", "request": "t.req_bytes", "response": "t.resp_bytes",
            "packet": "t.max_packet"}


def conn_where(f):
    sql, params = [], []
    if f.src:
        sql.append("c.client_ip = ?")
        params.append(f.src)
    if f.dst:
        sql.append("c.server_ip = ?")
        params.append(f.dst)
    if f.port is not None:
        sql.append("c.server_port = ?")
        params.append(f.port)
    if f.kind:
        sql.append("c.kind = ?")
        params.append(f.kind)
    return sql, params


def txn_where(f):
    sql, params = conn_where(f)
    if f.url:
        sql.append("contains(lower(coalesce(t.uri, '')), lower(?))")
        params.append(f.url)
    if f.min_size is not None:
        if f.size_of not in SIZE_SQL:
            raise ValueError(f"unknown size type: {f.size_of}")
        sql.append(f"{SIZE_SQL[f.size_of]} > ?")
        params.append(f.min_size)
    return " AND ".join(sql), params


def inspect(db, f):
    tw, tp = txn_where(f)
    cw, cp = conn_where(f)
    twhere = f" WHERE {tw}" if tw else ""
    cwhere = f" WHERE {' AND '.join(cw)}" if cw else ""
    join = "FROM http_transactions t JOIN tcp_connections c USING (stream)"
    stats = one(db, f"SELECT {TIME_STATS} {join}{twhere}", tp)
    conns = one(db, f"""SELECT count(*) AS connections, count(*) FILTER (c.handshake_seen AND coalesce(c.close_type, '') <> 'RST') AS ok,
        count(*) FILTER (c.kind IN ('TCP', 'TLS')) AS tcp_only, count(*) FILTER (c.kind NOT IN ('TCP', 'TLS')) AS http,
        avg(c.connect_time) AS avg_connect, avg(c.duration) AS avg_duration, avg(c.rtt_server) AS avg_rtt
        FROM tcp_connections c{cwhere}""", cp)
    return dict(requests=stats, connections=conns,
                causes=rows(db, f"SELECT t.cause, count(*) AS requests, avg(t.total) AS avg_total {join}{twhere} GROUP BY 1 ORDER BY 2 DESC", tp),
                urls=_groups(db, tw, tp), slowest=slowest(db, tw, tp))


def _groups(db, tw, tp):
    return url_groups(db, (f"stream IN (SELECT c.stream FROM tcp_connections c JOIN http_transactions t USING (stream) WHERE {tw}) "
                           f"AND id IN (SELECT t.id FROM http_transactions t JOIN tcp_connections c USING (stream) WHERE {tw})", tp + tp)) if tw else url_groups(db)


def slowest(db, tw="", tp=(), limit=SLOWEST):
    """Slowest requests with their explanation. Unanswered requests count by how long they waited."""
    where = f" WHERE {tw}" if tw else ""
    got = rows(db, f"""SELECT t.* FROM http_transactions t JOIN tcp_connections c USING (stream){where}
        ORDER BY coalesce(t.total, c.end_time - t.req_end) DESC NULLS LAST LIMIT ?""", list(tp) + [limit])
    return [describe(db, t) for t in got]


def describe(db, t):
    """Add the time breakdown and a plain explanation to one transaction."""
    conn = one(db, "SELECT * FROM tcp_connections WHERE stream = ?", [t["stream"]])
    ph = causes.phases(t)
    t["phases"] = [dict(name=k, label=causes.PHASE_LABELS[k], seconds=v) for k, v in ph.items() if v > 0]
    t["cause_label"] = causes.LABELS[t["cause"]]
    t["explanation"] = causes.explain(t, conn)
    t["conn"] = conn
    t["longest"] = t["total"] if t["total"] is not None else max(conn["end_time"] - t["req_end"], 0)
    if not t["answered"]:
        t["phases"] = [dict(name="service", label="Waiting for a response", seconds=t["longest"])]
    return t


def transaction(db, tid):
    t = one(db, "SELECT * FROM http_transactions WHERE id = ?", [tid])
    return describe(db, t) if t else None


def histogram(db):
    """Request counts per latency bucket on a log scale."""
    edges = [0, .001, .005, .01, .05, .1, .25, .5, 1, 2.5, 5, 10, 30, 60]
    got = []
    for lo, hi in zip(edges, edges[1:] + [None]):
        sql = "SELECT count(*) AS n FROM http_transactions WHERE total >= ?" + (" AND total < ?" if hi is not None else "")
        n = db.execute(sql, [lo] + ([hi] if hi is not None else [])).fetchone()[0]
        got.append(dict(label=f"{lo}-{hi} s" if hi is not None else f">{lo} s", requests=n))
    return got


# key, title, why, severity, condition on requests (t), condition on connections (c)
ISSUES = [
    ("no_response", "Requests without a response", "The service hung, crashed, or a device dropped the reply.", 1, "NOT t.answered", None),
    ("resets", "Connections reset", "An RST ended the connection, often a timeout or a crash on one side.", 1, None, "c.close_type = 'RST'"),
    ("no_handshake", "Handshakes not completed", "SYN got no full answer: a firewall, a closed port or an unreachable host.", 1, None,
     "NOT c.handshake_seen AND c.transactions = 0 AND c.packets <= 3"),
    ("truncated", "Incomplete responses", "Fewer body bytes arrived than Content-Length promised.", 1, "t.truncated", None),
    ("gateway", "Gateway errors", "HTTP 502, 503 or 504: a proxy got no good answer from the service behind it.", 1, "t.status IN (502, 503, 504)", None),
    ("server_errors", "Server errors", "Other HTTP 5xx answers.", 1, "t.status >= 500 AND t.status NOT IN (502, 503, 504)", None),
    ("slow_service", "Slow service", "The server took most of the time.", 2, "t.cause = 'service'", None),
    ("loss", "Packet loss", "Retransmissions cost noticeable time.", 2, "t.cause = 'loss'", None),
    ("retrans", "Connections with retransmissions", "Packets were lost or delayed on the path.", 2, None, "c.retransmissions > 0"),
    ("slow_client", "Slow receivers", "The receiver closed its TCP window.", 2, "t.zero_window_time > 0", None),
    ("delayed_ack", "Delayed ACK waits", "Senders stalled for a late ACK, a classic Nagle and delayed ACK pattern.", 3, "t.delayed_ack_time > 0", None),
    ("queueing", "Requests queued on a connection", "A request waited for an earlier response on the same connection.", 3, "t.queue_time > 0", None),
    ("network", "Network delay", "Round-trip time was the largest part.", 3, "t.cause = 'network'", None),
    ("small_mss", "Small MSS", "Small segments mean more packets and round trips, often from a tunnel or a low MTU.", 3, None, "c.mss < 1200"),
]
ISSUE_LIMIT = 200


def issues(db, meta):
    """Curated problems, most serious first. Each says what to look at next."""
    found = []
    for key, title, why, severity, tsql, csql in ISSUES:
        table, cond = ("http_transactions t", tsql) if tsql else ("tcp_connections c", csql)
        n = db.execute(f"SELECT count(*) FROM {table} WHERE {cond}").fetchone()[0]
        if n:
            found.append(dict(key=key, title=title, why=why, count=n, severity=severity, drill=True))
    dns = db.execute("SELECT count(*) FROM dns_queries WHERE duration > 0.1").fetchone()[0]
    for key, title, why, severity, n in (
            ("slow_dns", "Slow DNS answers", "Lookups took over 100 ms.", 3, dns),
            ("frag_needed", "Fragmentation needed", "ICMP says packets were too big for the path.", 2, meta.get("frag_needed", 0)),
            ("ip_fragments", "IP fragments", "Fragmented packets raise the cost of any loss.", 3, meta.get("ip_fragments", 0))):
        if n:
            found.append(dict(key=key, title=title, why=why, count=n, severity=severity, drill=False))
    return sorted(found, key=lambda x: (x["severity"], -x["count"]))


def issue_detail(db, key):
    """Requests and connections behind one issue."""
    row = next((i for i in ISSUES if i[0] == key), None)
    if row is None:
        return None
    _, title, why, _, tsql, csql = row
    if tsql:
        txns = slowest(db, tsql, [], ISSUE_LIMIT)
        conns = []
    else:
        conns = rows(db, f"SELECT * FROM tcp_connections c WHERE {csql} ORDER BY c.stream LIMIT ?", [ISSUE_LIMIT])
        txns = slowest(db, csql, [], ISSUE_LIMIT)
    return dict(key=key, title=title, why=why, transactions=txns, connections=conns)


def time_budget(db):
    """Total seconds spent in each phase, across all requests."""
    t = one(db, f"""SELECT {', '.join(f'sum({p}) AS {p}' for p in causes.PHASES)} FROM http_transactions""")
    return [dict(name=k, label=causes.PHASE_LABELS[k], seconds=v) for k, v in t.items() if v]
