"""Compare two captures, and match the same requests seen at two points."""
import statistics

from . import reports

MIN_SAMPLE = 5
MATCH_WINDOW_S = 5.0
PHASE_AVG = ["network", "queue_time", "service", "transfer_clean", "retrans_time", "zero_window_time", "delayed_ack_time"]


def _delta(a, b):
    return b - a if a is not None and b is not None else None


def _pct(a, b):
    return (b - a) / a * 100 if a and b is not None else None


def _phases(db, f):
    tw, tp = reports.txn_where(f)
    where = f" WHERE {tw}" if tw else ""
    return reports.one(db, f"""SELECT {', '.join(f'avg(t.{p}) AS {p}' for p in PHASE_AVG)}
        FROM http_transactions t JOIN tcp_connections c USING (stream){where}""", tp)


def _capture_point(db):
    got = reports.one(db, "SELECT capture_point, count(*) AS n FROM tcp_connections WHERE capture_point <> 'unknown' GROUP BY 1 ORDER BY 2 DESC LIMIT 1")
    return got["capture_point"] if got else None


def captures(db_a, db_b, f_a, f_b):
    """Same report for both sides, with the change from A to B."""
    a, b = reports.inspect(db_a, f_a), reports.inspect(db_b, f_b)
    summary = []
    for key, label in (("requests", "Requests"), ("failed", "Failed"), ("avg_total", "Average"), ("p50_total", "Median"), ("p95_total", "95th percentile"),
                       ("max_total", "Slowest"), ("avg_wait", "Average server wait"), ("avg_service", "Average service"), ("avg_transfer", "Average transfer")):
        x, y = a["requests"][key], b["requests"][key]
        summary.append(dict(key=key, label=label, a=x, b=y, delta=_delta(x, y), percent=_pct(x, y), is_time=key not in ("requests", "failed")))
    for key, label in (("connections", "TCP connections"), ("avg_connect", "Average connect"), ("avg_rtt", "Average round trip")):
        x, y = a["connections"][key], b["connections"][key]
        summary.append(dict(key=key, label=label, a=x, b=y, delta=_delta(x, y), percent=_pct(x, y), is_time=key != "connections"))
    urls_a = {(u["method"], u["url"]): u for u in a["urls"]}
    urls_b = {(u["method"], u["url"]): u for u in b["urls"]}
    urls = []
    for k in sorted(urls_a.keys() | urls_b.keys()):
        x, y = urls_a.get(k), urls_b.get(k)
        row = dict(method=k[0], url=k[1], requests_a=x and x["requests"], requests_b=y and y["requests"], failed_a=x and x["failed"], failed_b=y and y["failed"],
                   avg_a=x and x["avg_total"], avg_b=y and y["avg_total"], p95_a=x and x["p95_total"], p95_b=y and y["p95_total"],
                   only_in="A" if not y else "B" if not x else None)
        row["delta"] = _delta(row["avg_a"], row["avg_b"])
        row["percent"] = _pct(row["avg_a"], row["avg_b"])
        row["few"] = min(row["requests_a"] or 0, row["requests_b"] or 0) < MIN_SAMPLE
        urls.append(row)
    urls.sort(key=lambda r: abs(r["delta"]) if r["delta"] is not None else -1, reverse=True)
    pa, pb = _phases(db_a, f_a), _phases(db_b, f_b)
    phases = [dict(name=p, a=pa[p], b=pb[p], delta=_delta(pa[p], pb[p])) for p in PHASE_AVG]
    cp_a, cp_b = _capture_point(db_a), _capture_point(db_b)
    notes = []
    if cp_a and cp_b and cp_a != cp_b:
        notes.append(f"The captures were taken at different points ({cp_a.replace('_', ' ')} and {cp_b.replace('_', ' ')}), so network time differs by nature.")
    if a["requests"]["requests"] < MIN_SAMPLE or b["requests"]["requests"] < MIN_SAMPLE:
        notes.append(f"One side has fewer than {MIN_SAMPLE} requests, so averages can mislead.")
    return dict(summary=summary, urls=urls, phases=phases, causes_a=a["causes"], causes_b=b["causes"], slowest_a=a["slowest"], slowest_b=b["slowest"], notes=notes)


def _txns(db):
    return reports.rows(db, """SELECT t.id, t.stream, t.method, t.uri, t.status, t.request_id, t.x_forwarded_for, t.req_start, t.req_end,
        t.resp_start, t.resp_end, t.total, t.wait FROM http_transactions t ORDER BY t.req_start""")


def _clock_offset(pairs):
    """Median start difference of exact matches. A positive value means B's clock runs behind A's."""
    return statistics.median(a["req_start"] - b["req_start"] for a, b in pairs) if pairs else 0.0


def two_point(db_a, db_b):
    """Match requests seen at two points. A is the point nearer the client.

    An ID in both captures gives an exact match. Otherwise method, URL and status must agree and the
    closest start time wins; those matches are labeled as likely.
    """
    a_rows, b_rows = _txns(db_a), _txns(db_b)
    by_id = {}
    for b in b_rows:
        if b["request_id"]:
            by_id.setdefault(b["request_id"], b)
    exact, used = [], set()
    for a in a_rows:
        b = by_id.get(a["request_id"]) if a["request_id"] else None
        if b and b["id"] not in used:
            exact.append((a, b))
            used.add(b["id"])
    offset = _clock_offset(exact)
    matched_a = {a["id"] for a, _ in exact}
    likely = []
    for a in a_rows:
        if a["id"] in matched_a:
            continue
        options = [b for b in b_rows if b["id"] not in used and (b["method"], b["uri"], b["status"]) == (a["method"], a["uri"], a["status"])
                   and abs(b["req_start"] + offset - a["req_start"]) <= MATCH_WINDOW_S]
        if options:
            best = min(options, key=lambda b: abs(b["req_start"] + offset - a["req_start"]))
            likely.append((a, best))
            used.add(best["id"])
    rows = []
    for kind, pairs in (("exact", exact), ("likely", likely)):
        for a, b in pairs:
            forward = b["req_start"] + offset - a["req_end"]
            back = a["resp_start"] - (b["resp_start"] + offset) if a["resp_start"] and b["resp_start"] else None
            rows.append(dict(match=kind, method=a["method"], uri=a["uri"], status=a["status"], id_a=a["id"], id_b=b["id"], total_a=a["total"], total_b=b["total"],
                             added=_delta(b["total"], a["total"]), forward=forward, back=back))
    rows.sort(key=lambda r: r["added"] if r["added"] is not None else -1, reverse=True)
    return dict(rows=rows, clock_offset=offset, clock_known=bool(exact), exact=len(exact), likely=len(likely),
                unmatched_a=len(a_rows) - len(rows), unmatched_b=len(b_rows) - len(rows))
