"""Turn reports into downloadable files."""
import csv
import io
import json

from openpyxl import Workbook

from . import knowledge, reports

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
