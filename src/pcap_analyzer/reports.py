"""Read-only reports over one analysis. The CLI and the web interface share these."""
import fnmatch
import math
import statistics
from dataclasses import dataclass

import duckdb

from . import causes, knowledge

SUCCESS = "status BETWEEN 200 AND 399"
UNANSWERED = "(NOT {t}answered AND {t}cause <> 'capture_end')"  # a request the capture stopped right after is not known to have failed
TIME_STATS = """count(*) AS requests, count(*) FILTER ({ok}) AS ok,
    count(*) FILTER (status >= 400 OR {unanswered}) AS failed, avg(total) AS avg_total,
    median(total) AS p50_total, quantile_cont(total, 0.95) AS p95_total, max(total) AS max_total,
    avg(wait) AS avg_wait, avg(service) AS avg_service, avg(transfer) AS avg_transfer,
    sum(resp_bytes) AS resp_bytes""".format(ok=SUCCESS, unanswered=UNANSWERED.format(t=""))
TOP_DEFAULT = 5
TOP_PERCENT = 0.10
SLOWEST = 10
BUCKETS_S = (0.1, 0.5, 1, 2, 5, 10, 30, 60, 300, 600, 1800, 3600)
CHART_POINTS = 150
BACKEND_MIN_REQUESTS = 5
BACKEND_SLOW_RATIO = 2.0
BACKEND_ERROR_GAP = 0.2
LOST_SHARE_HIGH = 0.01
MOST = 0.5
DRIFT_RATIO = 1.5


def rows(db, sql, params=()):
    cur = db.execute(sql, params)
    cols = [c[0] for c in cur.description]
    return [dict(zip(cols, r)) for r in cur.fetchall()]


def each_row(db, sql, params=(), batch=5000):
    """Like rows, one batch at a time."""
    cur = db.execute(sql, params)
    cols = [c[0] for c in cur.description]
    while chunk := cur.fetchmany(batch):
        for r in chunk:
            yield dict(zip(cols, r))


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


def quality(meta):
    """How far this capture can be trusted, as a level and the reasons for it."""
    q = meta.get("quality")
    if q is None:
        return None
    conns, found = q["connections"] or 1, []

    def note(key, level):
        found.append(dict(key=key, level=level, text=knowledge.quality_line(key, q[key])))

    if q["unseen"]:
        note("unseen", "low" if q["unseen"] / (q["tcp_packets"] or 1) > LOST_SHARE_HIGH else "medium")
    if q["encrypted"]:
        note("encrypted", "low" if q["encrypted"] == q["connections"] else "medium")
    if q["one_way"]:
        note("one_way", "low" if q["one_way"] / conns > MOST else "medium")
    if q["snapped"]:
        note("snapped", "medium")
    if q["started_before"]:
        note("started_before", "medium" if q["started_before"] / conns > MOST else "info")
    if q["open_at_end"]:
        note("open_at_end", "info")
    if q["copies"]:
        note("copies", "info")
    levels = {f["level"] for f in found}
    level = "low" if "low" in levels else "medium" if "medium" in levels else "high"
    return dict(level=level, label=knowledge.t({"high": "High", "medium": "Medium", "low": "Low"}[level]), findings=found)


def timeline(db):
    """Traffic over time, so that the start of a problem can be read from one chart."""
    span = one(db, "SELECT min(req_start) AS lo, max(coalesce(resp_end, req_end)) AS hi FROM http_transactions")
    if span["lo"] is None:
        return dict(start=None, width=None, rows=[])
    lo, length = span["lo"], max(span["hi"] - span["lo"], 0.001)
    width = next((b for b in BUCKETS_S if length / b <= CHART_POINTS), BUCKETS_S[-1])
    count = int(length // width) + 1
    got = {r["slot"]: r for r in rows(db, f"""SELECT CAST(floor((req_start - ?) / ?) AS INT) AS slot, count(*) AS requests,
        count(*) FILTER (status >= 500 OR {UNANSWERED.format(t="")}) AS errors, quantile_cont(total, 0.95) AS p95_total FROM http_transactions GROUP BY 1""", [lo, width])}
    lost = {r["slot"]: r["n"] for r in rows(db, """SELECT CAST(floor((time - ?) / ?) AS INT) AS slot, count(*) AS n FROM tcp_events
        WHERE event IN ('retransmission', 'fast_retransmission') GROUP BY 1""", [lo, width])}
    spans = db.execute("SELECT start_time, end_time FROM tcp_connections").fetchall()
    out = []
    for slot in range(count):
        start, r = lo + slot * width, got.get(slot, {})
        out.append(dict(start=start, requests=r.get("requests", 0), errors=r.get("errors", 0), p95_total=r.get("p95_total"), retransmissions=lost.get(slot, 0),
                        open_connections=sum(a < start + width and b >= start for a, b in spans)))
    return dict(start=lo, width=width, rows=out)


def _others(rows_, key, row):
    values = [r[key] for r in rows_ if r is not row and r[key] is not None]
    return statistics.median(values) if values else None


def backends(db):
    """Each server behind the capture point. A slow one disappears in an average, so mark it against its peers."""
    got = rows(db, f"""SELECT c.server_ip, c.server_port, count(DISTINCT c.stream) AS connections, count(*) AS requests,
        count(*) FILTER (t.status >= 500 OR {UNANSWERED.format(t="t.")}) AS failed, avg(t.total) AS avg_total, median(t.total) AS p50_total,
        quantile_cont(t.total, 0.95) AS p95_total, median(t.service) AS p50_service, count(DISTINCT c.stream) FILTER (c.close_type = 'RST') AS resets,
        sum(t.retrans_count) AS retransmissions FROM http_transactions t JOIN tcp_connections c USING (stream)
        GROUP BY 1, 2 ORDER BY p50_total DESC NULLS LAST""")
    for r in got:
        r["error_share"], r["flag"] = r["failed"] / r["requests"], None
    for r in got:
        peers = [x for x in got if x["server_port"] == r["server_port"] and x["requests"] >= BACKEND_MIN_REQUESTS]
        if r not in peers or len(peers) < 2:
            continue
        usual, usual_errors = _others(peers, "p50_total", r), _others(peers, "error_share", r)
        if usual_errors is not None and r["error_share"] - usual_errors > BACKEND_ERROR_GAP:
            r["flag"] = "errors"
        elif usual is not None and r["p50_total"] is not None and r["p50_total"] > BACKEND_SLOW_RATIO * usual and r["p50_total"] - usual >= causes.SLOW_S:
            r["flag"] = "slow"
    return got


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
    start: float | None = None
    end: float | None = None


SIZE_SQL = {"total": "coalesce(t.req_bytes, 0) + coalesce(t.resp_bytes, 0)", "request": "t.req_bytes", "response": "t.resp_bytes",
            "packet": "t.max_packet"}


def conn_where(f):
    sql, params = [], []
    if f.start is not None:
        sql.append("c.end_time >= ?")
        params.append(f.start)
    if f.end is not None:
        sql.append("c.start_time <= ?")
        params.append(f.end)
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
    if f.start is not None:
        sql.append("t.req_start >= ?")
        params.append(f.start)
    if f.end is not None:
        sql.append("t.req_start <= ?")
        params.append(f.end)
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
    t["phases"] = [knowledge.phase(k, v) for k, v in ph.items() if v > 0]
    t["cause_label"] = knowledge.label(t["cause"])
    t["explanation"] = causes.explain(t, conn)
    t["conn"] = conn
    t["longest"] = t["total"] if t["total"] is not None else max(conn["end_time"] - t["req_end"], 0)
    if not t["answered"]:
        t["phases"] = [dict(knowledge.phase("waiting", t["longest"]), name="service")]
    return t


def transaction(db, tid):
    t = one(db, "SELECT * FROM http_transactions WHERE id = ?", [tid])
    if not t:
        return None
    t = describe(db, t)
    t["guide"] = knowledge.guide(t["cause"], causes.facts(t, t["conn"]))
    return t


def histogram(db):
    """Request counts per latency bucket on a log scale."""
    edges = [0, .001, .005, .01, .05, .1, .25, .5, 1, 2.5, 5, 10, 30, 60]
    got = []
    for lo, hi in zip(edges, edges[1:] + [None]):
        sql = "SELECT count(*) AS n FROM http_transactions WHERE total >= ?" + (" AND total < ?" if hi is not None else "")
        n = db.execute(sql, [lo] + ([hi] if hi is not None else [])).fetchone()[0]
        got.append(dict(label=f"{lo}-{hi} s" if hi is not None else f">{lo} s", requests=n))
    return got


# key, severity, condition on requests (t), condition on connections (c). Titles and reasons come from the knowledge base.
ISSUES = [
    ("no_response", 1, UNANSWERED.format(t="t."), None),
    ("resets", 1, None, "c.close_type = 'RST'"),
    ("no_handshake", 1, None, "NOT c.handshake_seen AND c.transactions = 0 AND c.packets <= 3"),
    ("truncated", 1, "t.truncated", None),
    ("gateway", 1, "t.status IN (502, 503, 504)", None),
    ("server_errors", 1, "t.status >= 500 AND t.status NOT IN (502, 503, 504)", None),
    ("grpc_errors", 1, "t.grpc_status > 0", None),
    ("tls_no_answer", 1, None, "c.tls_no_answer"),
    ("tls_alerts", 2, None, "c.tls_alert IS NOT NULL"),
    ("slow_service", 2, "t.cause = 'service'", None),
    ("loss", 2, "t.cause = 'loss'", None),
    ("retrans", 2, None, "c.retransmissions > 0"),
    ("slow_client", 2, "t.zero_window_time > 0", None),
    ("delayed_ack", 3, "t.delayed_ack_time > 0", None),
    ("queueing", 3, "t.queue_time > 0", None),
    ("network", 3, "t.cause = 'network'", None),
    ("small_mss", 3, None, "c.mss < 1200"),
]
META_ISSUES = (("slow_dns", 3), ("frag_needed", 2), ("ip_fragments", 3), ("slow_backend", 2))
ISSUE_LIMIT = 200


def percentile(values, q):
    """Value at share q of a sorted list, with the same interpolation as quantile_cont in the reports."""
    place = (len(values) - 1) * q
    low, high = math.floor(place), math.ceil(place)
    return values[low] + (values[high] - values[low]) * (place - low)


def issue_keys():
    return [i[0] for i in ISSUES] + [k for k, _ in META_ISSUES]


def issues(db, meta):
    """Curated problems, most serious first. Each says what to look at next."""
    found = []
    for key, severity, tsql, csql in ISSUES:
        table, cond = ("http_transactions t", tsql) if tsql else ("tcp_connections c", csql)
        try:
            n = db.execute(f"SELECT count(*) FROM {table} WHERE {cond}").fetchone()[0]
        except duckdb.BinderException:  # saved by an older version, which did not record this
            continue
        if n:
            found.append(dict(knowledge.issue(key), count=n, severity=severity, drill=True))
    counts = dict(slow_dns=db.execute("SELECT count(*) FROM dns_queries WHERE duration > 0.1").fetchone()[0],
                  frag_needed=meta.get("frag_needed", 0), ip_fragments=meta.get("ip_fragments", 0),
                  slow_backend=sum(bool(b["flag"]) for b in backends(db)))
    for key, severity in META_ISSUES:
        if counts[key]:
            found.append(dict(knowledge.issue(key), count=counts[key], severity=severity, drill=False))
    return sorted(found, key=lambda x: (x["severity"], -x["count"]))


def issue_detail(db, key):
    """Requests and connections behind one issue."""
    row = next((i for i in ISSUES if i[0] == key), None)
    if row is None:
        return None
    _, _, tsql, csql = row
    if tsql:
        txns = slowest(db, tsql, [], ISSUE_LIMIT)
        conns = []
    else:
        conns = rows(db, f"SELECT * FROM tcp_connections c WHERE {csql} ORDER BY c.stream LIMIT ?", [ISSUE_LIMIT])
        txns = slowest(db, csql, [], ISSUE_LIMIT)
    for c in conns:
        c["rst_note"] = knowledge.reset_note(c.get("rst_code"))
    about = knowledge.issue(key)
    return dict(about, transactions=txns, connections=conns, guide=knowledge.guide(about["topic"]))


def time_budget(db):
    """Total seconds spent in each phase, across all requests."""
    t = one(db, f"""SELECT {', '.join(f'sum({p}) AS {p}' for p in causes.PHASES)} FROM http_transactions""")
    return [knowledge.phase(k, v) for k, v in t.items() if v]


def waterfall(db, stream):
    """Requests of one connection on one time axis, each split into its phases."""
    conn = one(db, "SELECT start_time FROM tcp_connections WHERE stream = ?", [stream])
    if conn is None:
        return None
    labels = {p: knowledge.phase(p, 0)["label"] for p in causes.PHASES}
    got = rows(db, "SELECT * FROM http_transactions WHERE stream = ? ORDER BY req_start", [stream])
    return dict(phases=labels, rows=[dict(id=t["id"], label=f"{t['method']} {(t['uri'] or '')[:48]}", status=t["status"], start=t["req_start"] - conn["start_time"],
                                          **{p: t.get(p) or 0.0 for p in causes.PHASES}) for t in got])


def target_misses(db, targets):
    """URL shapes whose 95th percentile is over the target set for them."""
    missed = []
    for g in url_groups(db):
        target = next((t for t in targets if fnmatch.fnmatch(g["url"], t["pattern"])), None)
        if target and g["p95_total"] is not None and g["p95_total"] > target["seconds"]:
            missed.append(dict(g, target=target["seconds"], over=sum(1 for r in db.execute(
                "SELECT total FROM http_transactions WHERE url_template = ? AND total > ?", [g["url"], target["seconds"]]).fetchall())))
    return missed


def drift(db, base):
    """URL shapes that got clearly slower or started failing since the reference analysis."""
    before = {(u["method"], u["url"]): u for u in url_groups(base)}
    found = []
    for u in url_groups(db):
        b = before.get((u["method"], u["url"]))
        if b is None:
            found.append(dict(u, why="new", base_p95=None, base_failed=None))
        elif u["failed"] > b["failed"] and u["failed"] / u["requests"] > b["failed"] / b["requests"]:
            found.append(dict(u, why="failing", base_p95=b["p95_total"], base_failed=b["failed"]))
        elif None not in (u["p95_total"], b["p95_total"]) and u["p95_total"] > DRIFT_RATIO * b["p95_total"] and u["p95_total"] - b["p95_total"] >= causes.SLOW_S:
            found.append(dict(u, why="slower", base_p95=b["p95_total"], base_failed=b["failed"]))
    return found


def trend(analyses, url):
    """One URL shape across saved analyses, oldest first."""
    out = []
    for a in sorted(analyses, key=lambda x: x.meta.get("capture_start") or x.meta["created"]):
        with a.connect() as db:
            got = one(db, f"SELECT {TIME_STATS} FROM http_transactions WHERE url_template = ?", [url])
        if got["requests"]:
            out.append(dict(got, id=a.id, filename=a.meta["filename"], when=a.meta.get("capture_start") or a.meta["created"]))
    return out


def url_names(analyses, limit=200):
    names = set()
    for a in analyses:
        with a.connect() as db:
            names |= {r[0] for r in db.execute("SELECT DISTINCT url_template FROM http_transactions WHERE url_template IS NOT NULL").fetchall()}
    return sorted(names)[:limit]


def check(db, p95=None, error_rate=None, slowest_s=None):
    """Compare an analysis with limits. Returns the numbers and the limits it broke."""
    s = one(db, f"SELECT {TIME_STATS} FROM http_transactions")
    rate = s["failed"] / s["requests"] * 100 if s["requests"] else 0.0
    broken = []
    if p95 is not None and (s["p95_total"] or 0) > p95:
        broken.append(dict(limit="p95", value=s["p95_total"], allowed=p95))
    if slowest_s is not None and (s["max_total"] or 0) > slowest_s:
        broken.append(dict(limit="slowest", value=s["max_total"], allowed=slowest_s))
    if error_rate is not None and rate > error_rate:
        broken.append(dict(limit="error_rate", value=rate, allowed=error_rate))
    return dict(requests=s["requests"], failed=s["failed"], error_rate=rate, p95=s["p95_total"], slowest=s["max_total"], broken=broken)


def tls_health(db):
    """What the handshakes show. None of this needs a key, so it also works on traffic that stays encrypted."""
    try:
        db.execute("SELECT tls_cipher, tls_alert, tls_no_answer FROM tcp_connections LIMIT 0")
    except duckdb.BinderException:
        return None
    where = "WHERE tls_version IS NOT NULL OR tls_no_answer OR tls_alert IS NOT NULL"
    return dict(
        versions=rows(db, f"""SELECT coalesce(tls_version, '-') AS version, coalesce(tls_cipher, '-') AS cipher, coalesce(tls_alpn, '-') AS alpn, count(*) AS connections,
            count(*) FILTER (tls_resumed) AS resumed, avg(tls_time) AS avg_handshake FROM tcp_connections {where} GROUP BY 1, 2, 3 ORDER BY connections DESC"""),
        problems=rows(db, """SELECT stream, client_ip, client_port, server_ip, server_port, sni, tls_alert, tls_no_answer FROM tcp_connections
            WHERE tls_no_answer OR tls_alert IS NOT NULL ORDER BY stream LIMIT 200"""),
        certificates=rows(db, """SELECT coalesce(sni, server_ip) AS name, tls_cert_expires AS expires, count(*) AS connections FROM tcp_connections
            WHERE tls_cert_expires IS NOT NULL GROUP BY 1, 2 ORDER BY 2"""))
