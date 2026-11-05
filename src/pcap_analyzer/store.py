"""Write analysis results to one DuckDB file per analysis."""
import json
import shutil
import tempfile
from pathlib import Path

import duckdb

SCHEMA = {
    "tcp_connections": """
        stream INT PRIMARY KEY, client_ip VARCHAR, client_port INT, server_ip VARCHAR, server_port INT, kind VARCHAR,
        first_frame BIGINT, start_time DOUBLE, end_time DOUBLE, duration DOUBLE, packets BIGINT, bytes BIGINT,
        payload_client BIGINT, payload_server BIGINT, handshake_seen BOOLEAN, connect_time DOUBLE, rtt_server DOUBLE,
        rtt_client DOUBLE, capture_point VARCHAR, mss INT, tls_version VARCHAR, sni VARCHAR, tls_time DOUBLE,
        close_type VARCHAR, closed_by VARCHAR, transactions INT, sack BOOLEAN, wscale INT, min_window BIGINT,
        retransmissions INT, zero_windows INT, byte_ratio_db DOUBLE, offload BOOLEAN, rst_code INT, one_way BOOLEAN,
        tls_cipher VARCHAR, tls_alpn VARCHAR, tls_alert VARCHAR, tls_resumed BOOLEAN, tls_no_answer BOOLEAN, tls_cert_expires VARCHAR, tls_unread BOOLEAN""",
    "http_transactions": """
        id BIGINT PRIMARY KEY, stream INT, h2_stream INT, seq_on_conn INT, new_conn BOOLEAN, method VARCHAR, uri VARCHAR,
        url_template VARCHAR, host VARCHAR, http_version VARCHAR, status INT, phrase VARCHAR, answered BOOLEAN, req_frame BIGINT, resp_frame BIGINT,
        req_start DOUBLE, req_end DOUBLE, resp_start DOUBLE, resp_end DOUBLE, connect_time DOUBLE, tls_time DOUBLE,
        request_send DOUBLE, wait DOUBLE, service DOUBLE, ttfb DOUBLE, transfer DOUBLE, total DOUBLE, req_bytes BIGINT,
        resp_bytes BIGINT, req_content_length BIGINT, resp_content_length BIGINT, content_type VARCHAR,
        content_encoding VARCHAR, transfer_encoding VARCHAR, server_timing VARCHAR, x_forwarded_for VARCHAR, request_id VARCHAR, req_headers VARCHAR, resp_headers VARCHAR,
        req_body VARCHAR, resp_body VARCHAR, retrans_count INT, retrans_time DOUBLE, zero_window_time DOUBLE,
        delayed_ack_time DOUBLE, queue_time DOUBLE, network DOUBLE, transfer_clean DOUBLE, request_clean DOUBLE,
        body_bytes BIGINT, truncated BOOLEAN, server_reported DOUBLE, cause VARCHAR, cause_share DOUBLE, flags VARCHAR,
        max_packet INT, dns_time DOUBLE, grpc_status INT, grpc_message VARCHAR""",
    "tcp_events": "stream INT, frame BIGINT, time DOUBLE, sender VARCHAR, event VARCHAR",
    "dns_queries": "name VARCHAR, duration DOUBLE, frame BIGINT, time DOUBLE",
    "stream_parts": "stream INT, part INT, part_stream INT",  # where a capture read in parts keeps each connection
}


def columns(table):
    return [c.split()[0] for c in SCHEMA[table].split(",") if c.split() and c.split()[0].isidentifier()]


def _load(db, table, rows, folder):
    """Bulk load through JSON lines: fast, and safe for multi-line text. The file sits next to the database, since /tmp may be small."""
    if not rows:
        return
    cols = columns(table)
    with tempfile.NamedTemporaryFile("w", suffix=".json", encoding="utf-8", dir=folder) as f:
        for r in rows:
            f.write(json.dumps(dict(zip(cols, r))) + "\n")
        f.flush()
        db.execute(f"COPY {table} ({', '.join(cols)}) FROM '{f.name}' (FORMAT json)")


def _types(table, extra=()):
    """Column types for read_json, from the table's definition."""
    found = {}
    for c in SCHEMA[table].split(","):
        words = c.split()
        if words and words[0].isidentifier():
            found[words[0]] = words[1]
    found.update(extra)
    return "{" + ", ".join(f"'{k}': '{v}'" for k, v in found.items()) + "}"


STAGED = {"tcp_connections": {"part": "INT", "part_stream": "INT"}, "http_transactions": {"n": "BIGINT"}, "tcp_events": {"n": "BIGINT"}}
MEMORY_LIMIT = "768MB"  # tshark has ended by then, so this and the app stay well inside a 2 GiB pod
THREADS = 2  # each reading thread holds its own buffers


class Writer:
    """Results arrive one part of a capture at a time and wait in files next to the database, so memory does not grow with the capture.
    Connection numbers are final only at the end, when connections seen twice through NAT are known."""

    def __init__(self, path):
        self.path = Path(path)
        self.files = {t: self.path.parent / f"stage-{t}.json" for t in STAGED}
        self.out = {t: open(f, "w", encoding="utf-8") for t, f in self.files.items()}
        self.n = 0

    def add(self, conns, txns, events):
        cols = columns("tcp_connections") + list(STAGED["tcp_connections"])
        for c in conns:
            self.out["tcp_connections"].write(json.dumps({k: c.get(k) for k in cols}) + "\n")
        cols = columns("http_transactions")
        for t in txns:
            self.n += 1
            self.out["http_transactions"].write(json.dumps({**{k: t.get(k) for k in cols}, "n": self.n}) + "\n")
        cols = columns("tcp_events")
        for e in events:
            self.n += 1
            self.out["tcp_events"].write(json.dumps({**dict(zip(cols, e)), "n": self.n}) + "\n")

    def _read(self, table):
        return f"read_json('{self.files[table]}', format='newline_delimited', columns={_types(table, STAGED[table])})"

    def close(self, number, dns, attach_dns):
        """number: each connection that stays, from its number while reading to its final number.
        attach_dns gets the requests that opened a connection and fills in their dns_time."""
        for f in self.out.values():
            f.close()
        folder = self.path.parent
        with duckdb.connect(str(self.path)) as db:
            db.execute(f"SET memory_limit = '{MEMORY_LIMIT}'")
            db.execute(f"SET threads = {THREADS}")
            db.execute(f"SET temp_directory = '{folder / 'duckdb.tmp'}'")
            for table, ddl in SCHEMA.items():
                db.execute(f"CREATE TABLE {table} ({ddl})")
            db.execute("CREATE TEMP TABLE renumber (reading INT, final INT)")
            _load_into(db, "renumber", ["reading", "final"], number.items(), folder)
            opened = [dict(zip(("n", "host", "connect_time", "req_start"), r)) for r in db.execute(
                f"SELECT n, host, connect_time, req_start FROM {self._read('http_transactions')} WHERE connect_time IS NOT NULL").fetchall()]
            attach_dns(opened)
            db.execute("CREATE TEMP TABLE dns_fix (n BIGINT, dns_time DOUBLE)")
            _load_into(db, "dns_fix", ["n", "dns_time"], ((o["n"], o["dns_time"]) for o in opened if o.get("dns_time") is not None), folder)

            cols = columns("tcp_connections")
            pick = ", ".join("m.final" if c == "stream" else f"c.{c}" for c in cols)
            db.execute(f"INSERT INTO tcp_connections SELECT {pick} FROM {self._read('tcp_connections')} c JOIN renumber m ON c.stream = m.reading ORDER BY m.final")
            db.execute(f"""INSERT INTO stream_parts SELECT m.final, c.part, c.part_stream FROM {self._read('tcp_connections')} c
                JOIN renumber m ON c.stream = m.reading WHERE c.part IS NOT NULL ORDER BY m.final""")
            cols = columns("http_transactions")
            pick = ", ".join({"id": "row_number() OVER (ORDER BY t.req_start, m.final, t.n)", "stream": "m.final", "dns_time": "coalesce(f.dns_time, t.dns_time)"}.get(c, f"t.{c}") for c in cols)
            db.execute(f"""INSERT INTO http_transactions SELECT {pick} FROM {self._read('http_transactions')} t JOIN renumber m ON t.stream = m.reading
                LEFT JOIN dns_fix f ON f.n = t.n ORDER BY t.req_start, m.final, t.n""")
            cols = columns("tcp_events")
            pick = ", ".join("m.final" if c == "stream" else f"e.{c}" for c in cols)
            db.execute(f"INSERT INTO tcp_events SELECT {pick} FROM {self._read('tcp_events')} e JOIN renumber m ON e.stream = m.reading ORDER BY e.n")
            _load(db, "dns_queries", dns, folder)
        for f in self.files.values():
            f.unlink()
        shutil.rmtree(folder / "duckdb.tmp", ignore_errors=True)


def _load_into(db, table, cols, rows, folder):
    with tempfile.NamedTemporaryFile("w", suffix=".json", encoding="utf-8", dir=folder) as f:
        for r in rows:
            f.write(json.dumps(dict(zip(cols, r))) + "\n")
        f.flush()
        if f.tell():
            db.execute(f"COPY {table} FROM '{f.name}' (FORMAT json)")


def connect(path, write=False):
    return duckdb.connect(str(Path(path)), read_only=not write)
