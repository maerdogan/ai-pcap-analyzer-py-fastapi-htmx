"""Decide why a request took long and say it in plain language."""
import re

from . import knowledge

SLOW_S = 0.2  # requests under this are normal, whatever their largest phase is
PHASES = ["connect_time", "tls_time", "request_clean", "network", "queue_time", "service", "transfer_clean",
          "retrans_time", "zero_window_time", "delayed_ack_time"]
CAUSE_OF_PHASE = {
    "connect_time": "connect", "tls_time": "tls", "request_clean": "upload", "network": "network",
    "queue_time": "queueing", "service": "service", "transfer_clean": "transfer", "retrans_time": "loss",
    "zero_window_time": "slow_client", "delayed_ack_time": "delayed_ack",
}
CAUSES = sorted(set(CAUSE_OF_PHASE.values()) | {"normal", "no_response", "capture_end", "connection_reset", "truncated", "gateway", "websocket"})
ROUND_TIMEOUTS = (5, 10, 15, 30, 60, 90, 120, 180, 240, 300, 600, 900)  # seconds people set as limits
SYN_RETRIES = (1, 3, 7, 15, 31)  # total wait when a 1 s timer doubles
TEXT_TYPES = ("json", "text", "xml", "javascript")
LARGE_TEXT = 100_000


def _f(v):
    return v or 0.0


def parse_server_timing(value):
    """Sum the dur= values of a Server-Timing header, in seconds."""
    if not value:
        return None
    durs = [float(x) for x in re.findall(r"dur=([0-9.]+)", value)]
    return sum(durs) / 1000 if durs else None


def phases(t):
    return {p: _f(t.get(p)) for p in PHASES}


def classify(t, conn, slow_s=SLOW_S):
    """Return (cause, share of elapsed time, flags)."""
    flags = []
    if t.get("status") in (502, 503, 504):
        flags.append("gateway_error")
    if t.get("truncated"):
        flags.append("truncated")
    mss = conn.get("mss")
    if mss and mss < 1200:
        flags.append("small_mss")
    if t.get("content_encoding"):
        flags.append("compressed")
    if t.get("transfer_encoding"):
        flags.append("chunked")
    if t.get("connect_time") is not None:
        flags.append("new_connection")
    if not t.get("answered"):
        cause = "connection_reset" if conn.get("close_type") == "RST" else "no_response"
        return cause, 1.0, flags
    if t.get("status") == 101:
        return "websocket", 1.0, flags
    if t.get("truncated"):
        return "truncated", 1.0, flags
    if "gateway_error" in flags:
        return "gateway", 1.0, flags
    ph = phases(t)
    total = sum(ph.values())
    if ph["network"] and ph["connect_time"] <= 3 * ph["network"]:  # a normal handshake is just round trips
        ph["network"] += ph.pop("connect_time")
        ph["connect_time"] = 0.0
    top = max(PHASES, key=ph.get)
    share = ph[top] / total if total else 0.0
    if ph[top] < slow_s:
        return "normal", share, flags
    return CAUSE_OF_PHASE[top], share, flags


def _near(value, targets, share):
    """The target a value sits on, allowing a share of it or 100 ms."""
    if value is None:
        return None
    return next((x for x in targets if abs(value - x) <= max(0.1, share * x)), None)


def facts(t, conn):
    """Everything the knowledge base may test or print about one request and its connection."""
    answered = t.get("answered")
    if answered:
        elapsed = t.get("total") if t.get("truncated") else t.get("wait")
    else:
        elapsed = max(conn.get("end_time", 0) - t.get("req_end", 0), 0)
    timeout = _near(elapsed, ROUND_TIMEOUTS, 0.01)
    retrans_count, transfer, rtt, tls_time = t.get("retrans_count"), t.get("transfer_clean"), conn.get("rtt_server"), t.get("tls_time")
    reported, service, ctype = t.get("server_reported"), t.get("service"), t.get("content_type") or ""
    return dict(
        t, pct=f"{(t.get('cause_share') or 0) * 100:.0f}", elapsed=elapsed, near_timeout=timeout is not None, timeout=timeout,
        retrans_gap=t.get("retrans_time", 0) / retrans_count if retrans_count else None,
        reported_gap=service - reported if None not in (service, reported) else None,
        throughput_mbps=t.get("resp_bytes", 0) * 8 / transfer / 1e6 if transfer else None,
        tls_rtts=tls_time / rtt if tls_time and rtt else None,
        syn_retry=_near(t.get("connect_time"), SYN_RETRIES, 0.1) is not None, still_open=not conn.get("close_type"),
        uncompressed_text=(t.get("resp_bytes") or 0) >= LARGE_TEXT and not t.get("content_encoding") and any(x in ctype for x in TEXT_TYPES),
        expect_continue="100-continue" in (t.get("req_headers") or "").lower(), conn_retransmissions=conn.get("retransmissions"),
        **{k: conn.get(k) for k in ("capture_point", "closed_by", "close_type", "mss", "offload", "rtt_client", "rst_code", "tls_version")})


def explain(t, conn):
    """One or two plain sentences for a transaction row."""
    return knowledge.summary(t["cause"], facts(t, conn))
