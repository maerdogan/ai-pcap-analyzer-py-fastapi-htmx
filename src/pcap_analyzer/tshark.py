"""Run tshark and yield one dict per packet.

The capture and any TLS key are copied to a private directory under /tmp first, because
Ubuntu's AppArmor profile stops tshark from reading most other paths.
"""
import ipaddress
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

MIN_VERSION = (4, 0)
AGG = "\x1f"

SINGLE = [
    "frame.number", "frame.time_epoch", "frame.len", "frame.cap_len", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
    "tcp.stream", "tcp.srcport", "tcp.dstport", "tcp.seq", "tcp.len", "tcp.flags", "tcp.window_size",
    "tcp.options.mss_val", "tcp.options.wscale.shift", "tcp.options.sack_perm", "tcp.analysis.initial_rtt",
    "tcp.analysis.ack_rtt", "dns.qry.name", "dns.time", "ip.flags.mf", "icmp.type", "icmp.code",
]
MULTI = [
    "http.request.method", "http.request.uri", "http.request.version", "http.host", "http.response.code",
    "http.response.phrase", "http.response.version", "http.content_length", "http.content_type",
    "http.content_encoding", "http.transfer_encoding", "http.x_forwarded_for", "http.request.line",
    "http.response.line", "tcp.segment", "tls.segment", "tls.record.content_type", "tls.handshake.type",
    "tls.handshake.extensions_server_name", "tls.handshake.extensions.supported_version",
    "http2.type", "http2.streamid", "http2.flags", "http2.length", "http2.header.count",
    "http2.header.name", "http2.header.value", "http.file_data",
]
# Flags that tshark's TCP analysis sets on a packet. Stored as events.
EVENTS = [
    "retransmission", "fast_retransmission", "spurious_retransmission", "out_of_order", "lost_segment",
    "duplicate_ack", "zero_window", "zero_window_probe", "window_full", "window_update", "keep_alive",
]
FIELDS = SINGLE + MULTI + [f"tcp.analysis.{e}" for e in EVENTS]


class TsharkError(Exception):
    """tshark is missing, too old, or rejected the capture or filter."""


@dataclass(frozen=True)
class Filter:
    """Pre-analysis filter. IP and port match both directions, so a connection stays whole."""
    host_a: str | None = None
    host_b: str | None = None
    port: int | None = None
    start: float | None = None
    end: float | None = None
    display: str | None = None

    def expression(self):
        parts = []
        for host in (self.host_a, self.host_b):
            if host:
                net = ipaddress.ip_network(host, strict=False)
                parts.append(f"{'ip' if net.version == 4 else 'ipv6'}.addr == {net.compressed}")
        if self.port is not None:
            parts.append(f"tcp.port == {int(self.port)}")
        if self.start is not None:
            parts.append(f"frame.time_epoch >= {float(self.start)}")
        if self.end is not None:
            parts.append(f"frame.time_epoch <= {float(self.end)}")
        if self.display:
            parts.append(f"({self.display})")
        return " and ".join(parts) or None


def version(binary="tshark"):
    try:
        out = subprocess.run([binary, "--version"], capture_output=True, text=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError) as e:
        raise TsharkError(f"tshark could not be started: {e}") from e
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", out)
    if not m:
        raise TsharkError("tshark version could not be read")
    found = tuple(int(x) for x in m.groups())
    if found[:2] < MIN_VERSION:
        raise TsharkError(f"tshark {found} is too old, need {MIN_VERSION[0]}.{MIN_VERSION[1]} or newer")
    return ".".join(map(str, found))


def _command(binary, capture, keylog, rsa_key, expr):
    cmd = [binary, "-n", "-r", str(capture), "-o", "http.desegment_body:FALSE",
           "-o", "tcp.desegment_tcp_streams:TRUE", "-o", "tls.desegment_ssl_records:TRUE",
           "-T", "fields", "-E", "separator=/t", "-E", "quote=n", "-E", "occurrence=a", "-E", f"aggregator={AGG}"]
    if keylog:
        cmd += ["-o", f"tls.keylog_file:{keylog}"]
    if rsa_key:
        cmd += ["-o", f'uat:rsa_keys:"{rsa_key}",""']
    if expr:
        cmd += ["-Y", expr]
    for f in FIELDS:
        cmd += ["-e", f]
    return cmd


def _private_copy(src, directory, name):
    dst = Path(directory) / name
    shutil.copyfile(src, dst)
    os.chmod(dst, 0o600)
    return dst


def extract_stream(capture, stream, out, binary="tshark"):
    """Write one TCP connection to a new capture file, keeping it whole so Wireshark can reassemble it."""
    with tempfile.TemporaryDirectory(prefix="pcap-analyzer-", dir="/tmp") as tmp:
        src = _private_copy(capture, tmp, "capture")
        dst = Path(tmp) / "out.pcapng"
        done = subprocess.run([binary, "-n", "-r", str(src), "-Y", f"tcp.stream == {int(stream)}", "-w", str(dst)], capture_output=True, text=True)
        if done.returncode != 0:
            raise TsharkError(done.stderr.strip().splitlines()[-1] if done.stderr.strip() else "tshark could not write the file")
        shutil.copyfile(dst, out)


def packets(path, keylog=None, rsa_key=None, flt=None, binary="tshark", warnings=None):
    """Yield packets as dicts. Non-fatal problems are appended to warnings."""
    expr = flt.expression() if flt else None
    with tempfile.TemporaryDirectory(prefix="pcap-analyzer-", dir="/tmp") as tmp:
        os.chmod(tmp, 0o700)
        capture = _private_copy(path, tmp, "capture")
        kl = _private_copy(keylog, tmp, "keylog") if keylog else None
        rk = _private_copy(rsa_key, tmp, "rsa.pem") if rsa_key else None
        env = dict(os.environ, LC_ALL="C")
        with tempfile.TemporaryFile(mode="w+", dir=tmp) as errfile:
            try:
                proc = subprocess.Popen(_command(binary, capture, kl, rk, expr), stdout=subprocess.PIPE,
                                        stderr=errfile, text=True, encoding="utf-8", errors="replace", env=env)
            except OSError as e:
                raise TsharkError(f"tshark could not be started: {e}") from e
            count = 0
            with proc.stdout:
                for line in proc.stdout:
                    vals = line.rstrip("\n").split("\t")
                    count += 1
                    yield dict(zip(FIELDS, vals))
            code = proc.wait()
            errfile.seek(0)
            err = errfile.read().strip()
        if code == 0:
            return
        if "cut short" in err and count:
            if warnings is not None:
                warnings.append("capture_truncated")
            return
        raise TsharkError(err.splitlines()[-1] if err else f"tshark exited with code {code}")
