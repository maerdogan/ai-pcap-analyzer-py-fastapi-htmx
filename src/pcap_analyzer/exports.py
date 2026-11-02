"""Turn reports into downloadable files."""
import csv
import datetime
import io
import json

from openpyxl import Workbook

from . import __version__, knowledge, reports

REQUEST_COLUMNS = ("id, stream, method, uri, url_template, host, http_version, status, answered, req_frame, resp_frame, connect_time, tls_time, "
                   "request_send, wait, service, ttfb, transfer, total, network, queue_time, retrans_count, retrans_time, zero_window_time, "
                   "delayed_ack_time, dns_time, server_reported, req_bytes, resp_bytes, truncated, cause, flags")
TABLES = ("requests", "urls", "connections", "hosts", "issues")
FORMATS = {"csv": "text/csv; charset=utf-8", "json": "application/json",
           "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"}


def table(db, name, meta):
    if name == "requests":
        return reports.rows(db, f"SELECT {REQUEST_COLUMNS} FROM http_transactions ORDER BY req_start")
    if name == "urls":
        got = reports.url_groups(db)
        for g in got:
            g["statuses"] = ", ".join(f"{s['status'] or knowledge.t('none')} x{s['requests']}" for s in g["statuses"])
        return got
    if name == "connections":
        return reports.connections(db)
    if name == "hosts":
        got = reports.hosts(db)
        for h in got:
            h["addresses"] = ", ".join(h["addresses"] or [])
        return got
    if name == "issues":
        return reports.issues(db, meta)
    raise ValueError(name)


def _pairs(block):
    pairs = []
    for line in (block or "").splitlines():
        name, sep, value = line.partition(":")
        if sep and name:
            pairs.append(dict(name=name, value=value.strip()))
    return pairs


def _ms(v):
    return round(v * 1000, 3) if v is not None else -1


def _entry(t):
    tls = t["kind"].startswith("HTTPS")
    host = t["host"] or t["server_ip"]
    version = t["http_version"] or "HTTP/1.1"
    return dict(
        startedDateTime=datetime.datetime.fromtimestamp(t["req_start"], datetime.UTC).isoformat(), time=_ms(t["total"] or 0),
        request=dict(method=t["method"], url=f"{'https' if tls else 'http'}://{host}{t['uri'] or ''}", httpVersion=version, cookies=[], headers=_pairs(t["req_headers"]),
                     queryString=[], headersSize=-1, bodySize=t["req_bytes"] or 0),
        response=dict(status=t["status"] or 0, statusText=t["phrase"] or "", httpVersion=version, cookies=[], headers=_pairs(t["resp_headers"]),
                      content=dict(size=t["resp_bytes"] or 0, mimeType=t["content_type"] or ""), redirectURL="", headersSize=-1, bodySize=t["resp_bytes"] or 0),
        cache={}, serverIPAddress=t["server_ip"], connection=str(t["stream"]),
        timings=dict(blocked=-1, dns=_ms(t["dns_time"]), connect=_ms(t["connect_time"]), ssl=_ms(t["tls_time"]), send=_ms(t["request_send"]),
                     wait=_ms(t["wait"] or 0), receive=_ms(t["transfer"] or 0)))


def har(db, flt=None):
    """Requests as a HAR 1.2 file. Headers and URLs are the masked ones, so secrets stay out of it here too."""
    tw, tp = reports.txn_where(flt or reports.Inspect())
    rows = reports.rows(db, f"""SELECT t.*, c.kind, c.server_ip FROM http_transactions t JOIN tcp_connections c USING (stream)
        {"WHERE " + tw if tw else ""} ORDER BY t.req_start""", tp)
    return json.dumps(dict(log=dict(version="1.2", creator=dict(name="pcap-analyzer", version=__version__), entries=[_entry(t) for t in rows])), indent=1).encode()


def _safe(v):
    """URLs come from the capture, so stop spreadsheets from running them as formulas."""
    if isinstance(v, str) and v[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + v
    return v


def render(rows, fmt):
    if fmt == "json":
        return json.dumps(rows, indent=2, default=str).encode()
    cols = list(rows[0]) if rows else []
    if fmt == "csv":
        out = io.StringIO()
        w = csv.writer(out)
        w.writerow([knowledge.column(c) for c in cols])
        for r in rows:
            w.writerow([_safe(r[c]) for c in cols])
        return ("﻿" + out.getvalue()).encode()  # BOM so Excel reads UTF-8
    if fmt == "xlsx":
        wb = Workbook()
        ws = wb.active
        ws.append([knowledge.column(c) for c in cols])
        for r in rows:
            ws.append([_safe(r[c]) if not isinstance(r[c], (list, dict)) else str(r[c]) for c in cols])
        out = io.BytesIO()
        wb.save(out)
        return out.getvalue()
    raise ValueError(fmt)
