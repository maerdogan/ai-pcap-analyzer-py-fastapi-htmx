"""Write analysis results to one DuckDB file per analysis."""
import csv
import tempfile
from pathlib import Path

import duckdb

SCHEMA = {
    "tcp_connections": """
        stream INT PRIMARY KEY, client_ip VARCHAR, client_port INT, server_ip VARCHAR, server_port INT, kind VARCHAR,
        first_frame BIGINT, start_time DOUBLE, end_time DOUBLE, duration DOUBLE, packets BIGINT, bytes BIGINT,
        payload_client BIGINT, payload_server BIGINT, handshake_seen BOOLEAN, connect_time DOUBLE, rtt_server DOUBLE,
        rtt_client DOUBLE, capture_point VARCHAR, mss INT, tls_version VARCHAR, sni VARCHAR, tls_time DOUBLE,
        close_type VARCHAR, closed_by VARCHAR, transactions INT""",
    "http_transactions": """
        id BIGINT PRIMARY KEY, stream INT, h2_stream INT, seq_on_conn INT, new_conn BOOLEAN, method VARCHAR, uri VARCHAR,
        host VARCHAR, http_version VARCHAR, status INT, phrase VARCHAR, answered BOOLEAN, req_frame BIGINT, resp_frame BIGINT,
        req_start DOUBLE, req_end DOUBLE, resp_start DOUBLE, resp_end DOUBLE, connect_time DOUBLE, tls_time DOUBLE,
        request_send DOUBLE, wait DOUBLE, service DOUBLE, ttfb DOUBLE, transfer DOUBLE, total DOUBLE, req_bytes BIGINT,
        resp_bytes BIGINT, req_content_length BIGINT, resp_content_length BIGINT, content_type VARCHAR,
        content_encoding VARCHAR, transfer_encoding VARCHAR, server_timing VARCHAR, x_forwarded_for VARCHAR, request_id VARCHAR""",
    "tcp_events": "stream INT, frame BIGINT, time DOUBLE, sender VARCHAR, event VARCHAR",
    "dns_queries": "name VARCHAR, duration DOUBLE, frame BIGINT, time DOUBLE",
}


def _columns(ddl):
    return [c.split()[0] for c in ddl.split(",") if c.split() and c.split()[0].isidentifier()]


def _load(db, table, rows):
    """Bulk load through CSV: fast, and needs no dataframe library."""
    if not rows:
        return
    cols = _columns(SCHEMA[table])
    with tempfile.NamedTemporaryFile("w", suffix=".csv", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        for r in rows:
            w.writerow(r)
        f.flush()
        db.execute(f"COPY {table} ({', '.join(cols)}) FROM '{f.name}' (FORMAT csv, HEADER false, NULL '', AUTO_DETECT false)")


def _as_rows(dicts, table):
    cols = _columns(SCHEMA[table])
    return [[d.get(c) for c in cols] for d in dicts]


def write(path, conns, txns, events, dns):
    for i, t in enumerate(txns, 1):
        t["id"] = i
    with duckdb.connect(str(path)) as db:
        for table, ddl in SCHEMA.items():
            db.execute(f"CREATE TABLE {table} ({ddl})")
        _load(db, "tcp_connections", _as_rows(conns, "tcp_connections"))
        _load(db, "http_transactions", _as_rows(txns, "http_transactions"))
        _load(db, "tcp_events", events)
        _load(db, "dns_queries", dns)


def connect(path):
    return duckdb.connect(str(Path(path)), read_only=True)
