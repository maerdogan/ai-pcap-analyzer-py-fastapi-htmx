"""Decide why a request took long and say it in plain language."""
import re

SLOW_S = 0.2  # requests under this are normal, whatever their largest phase is
PHASES = ["connect_time", "tls_time", "request_clean", "network", "queue_time", "service", "transfer_clean",
          "retrans_time", "zero_window_time", "delayed_ack_time"]
CAUSE_OF_PHASE = {
    "connect_time": "connect", "tls_time": "tls", "request_clean": "upload", "network": "network",
    "queue_time": "queueing", "service": "service", "transfer_clean": "transfer", "retrans_time": "loss",
    "zero_window_time": "slow_client", "delayed_ack_time": "delayed_ack",
}
LABELS = {
    "normal": "Normal", "no_response": "No response", "connection_reset": "Connection reset", "truncated": "Incomplete response",
    "gateway": "Gateway error", "service": "Slow service", "network": "Network delay", "loss": "Packet loss",
    "slow_client": "Slow receiver", "transfer": "Data transfer", "upload": "Slow upload", "queueing": "Queued on connection",
    "delayed_ack": "Delayed ACK", "connect": "Connection setup", "tls": "TLS handshake",
}
PHASE_LABELS = {
    "connect_time": "TCP connect", "tls_time": "TLS handshake", "request_clean": "Request send", "network": "Network round trip",
    "queue_time": "Queue on connection", "service": "Service", "transfer_clean": "Response transfer",
    "retrans_time": "Retransmission wait", "zero_window_time": "Receiver window closed", "delayed_ack_time": "Delayed ACK wait",
}


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


def classify(t, conn):
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
    if ph[top] < SLOW_S:
        return "normal", share, flags
    return CAUSE_OF_PHASE[top], share, flags


def _ms(s):
    return f"{s * 1000:.0f} ms" if s < 1 else f"{s:.2f} s"


def explain(t, conn):
    """One or two plain sentences for a transaction row."""
    c = t["cause"]
    wait = conn.get("end_time", 0) - t["req_end"] if not t.get("answered") else 0
    pct = f"{(t.get('cause_share') or 0) * 100:.0f}%"
    if c == "no_response":
        return f"The server never answered. The capture shows no response for {_ms(max(wait, 0))} after the request."
    if c == "connection_reset":
        return f"No response: the {conn.get('closed_by') or 'other side'} reset the connection {_ms(max(wait, 0))} after the request."
    if c == "truncated":
        return (f"The response stopped early: {t.get('body_bytes')} of {t.get('resp_content_length')} body bytes arrived "
                f"before the connection closed ({conn.get('close_type') or 'unknown'} by {conn.get('closed_by') or 'unknown'}).")
    if c == "gateway":
        return f"HTTP {t['status']} came from a proxy or gateway after {_ms(_f(t.get('wait')))}, so look at the service behind it."
    text = {
        "normal": "No delay stands out.",
        "service": f"The server spent {_ms(_f(t.get('service')))} ({pct}) before its first byte. The network is not the reason.",
        "network": f"Round-trip time of {_ms(_f(t.get('network')))} ({pct}) is the largest part. The server itself answered quickly.",
        "loss": f"{t.get('retrans_count')} retransmission(s) cost {_ms(_f(t.get('retrans_time')))} ({pct}). Packets were lost or badly delayed.",
        "slow_client": f"The receiver closed its TCP window for {_ms(_f(t.get('zero_window_time')))} ({pct}), so it was reading too slowly.",
        "transfer": f"Sending {t.get('resp_bytes')} bytes took {_ms(_f(t.get('transfer_clean')))} ({pct}). The body size or bandwidth limits it.",
        "upload": f"Sending the request took {_ms(_f(t.get('request_clean')))} ({pct}).",
        "queueing": f"The request waited {_ms(_f(t.get('queue_time')))} ({pct}) for an earlier response on the same connection.",
        "delayed_ack": f"A sender waited {_ms(_f(t.get('delayed_ack_time')))} ({pct}) for a delayed ACK. This pattern often means Nagle and delayed ACK together.",
        "connect": f"Opening the TCP connection took {_ms(_f(t.get('connect_time')))} ({pct}).",
        "tls": f"The TLS handshake took {_ms(_f(t.get('tls_time')))} ({pct}).",
    }[c]
    reported = t.get("server_reported")
    if reported is not None and t.get("service") is not None:
        text += f" The server reports {_ms(reported)} itself, against {_ms(t['service'])} measured here."
    return text
