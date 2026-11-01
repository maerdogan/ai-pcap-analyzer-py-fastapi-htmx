"""Analyze a capture once and keep the result; the same input reopens the saved result."""
import hashlib
import json
import re
import shutil
import tempfile
import time
from dataclasses import astuple, dataclass
from pathlib import Path

from . import __version__, store, tshark
from .config import Settings
from .parser import Builder, finish_stream


DNS_WINDOW_S = 5.0


class CaptureTooLarge(Exception):
    pass


class NotFound(Exception):
    pass


@dataclass
class Analysis:
    id: str
    dir: Path
    meta: dict
    cached: bool

    @property
    def db_path(self):
        return self.dir / "analysis.duckdb"

    def connect(self):
        return store.connect(self.db_path)


def _digest(paths, flt):
    h = hashlib.sha256()
    h.update(__version__.encode())
    for p in paths:
        h.update(b"\0")
        if p:
            with open(p, "rb") as f:
                while chunk := f.read(1 << 20):
                    h.update(chunk)
    h.update(repr(astuple(flt)).encode())
    return h.hexdigest()[:20]


def _warnings(b, conns, keyed, warnings):
    if b.truncated:
        warnings.append("frames_truncated")
    if any(c["offload"] for c in conns):
        warnings.append("offload_suspected")
    tls_undecrypted = [c for c in conns if c["kind"] == "TLS"]
    if tls_undecrypted:
        warnings.append("tls_key_did_not_decrypt" if keyed else "tls_not_decrypted")
    return sorted(set(warnings))


def _attach_dns(txns, dns):
    """Link a lookup to a new connection when its answer came shortly before that connection."""
    by_name = {}
    for name, duration, _, t in dns:
        if name:
            by_name.setdefault(name.lower(), []).append((t, duration))
    for x in txns:
        host = (x.get("host") or "").split(":")[0].lower()
        if x.get("connect_time") is None or host not in by_name:
            continue
        near = [(t, d) for t, d in by_name[host] if 0 <= x["req_start"] - t <= DNS_WINDOW_S]
        if near:
            x["dns_time"] = max(near)[1]


def _attach_packet_size(b, txns):
    for x in txns:
        s = b.streams[x["stream"]]
        hi = x["last_frame"] or x["req_frame"]
        x["max_packet"] = max((p.size for p in s.packets if x["req_frame"] <= p.frame <= hi), default=0)


def analyze(path, keylog=None, rsa_key=None, flt=None, settings=None, use_cached=True, display_name=None):
    settings = settings or Settings()
    flt = flt or tshark.Filter()
    path = Path(path)
    limit = settings.max_size_mb * 1024 * 1024
    if path.stat().st_size > limit:
        raise CaptureTooLarge(f"{path.name} is larger than the {settings.max_size_mb} MB limit")
    ts_version = tshark.version(settings.tshark)
    aid = _digest([path, keylog, rsa_key], flt)
    out = settings.workdir / aid
    if use_cached and (out / "meta.json").exists():
        return Analysis(aid, out, json.loads((out / "meta.json").read_text()), True)

    started = time.monotonic()
    warnings = []
    b = Builder()
    for p in tshark.packets(path, keylog, rsa_key, flt, settings.tshark, warnings):
        b.add(p)
    conns, txns = [], []
    for s in b.streams.values():
        c, t = finish_stream(s)
        conns.append(c)
        txns += t
    txns.sort(key=lambda x: x["req_start"])
    _attach_dns(txns, b.dns_rows)
    _attach_packet_size(b, txns)

    settings.workdir.mkdir(parents=True, exist_ok=True)
    tmp = Path(tempfile.mkdtemp(prefix=".tmp-", dir=settings.workdir))
    store.write(tmp / "analysis.duckdb", conns, txns, b.events, b.dns_rows)
    meta = dict(
        id=aid, filename=display_name or path.name, size=path.stat().st_size, created=time.time(), tshark=ts_version, version=__version__,
        decryption="keylog" if keylog else "rsa_key" if rsa_key else None, filter=flt.expression(),
        packets=b.total, tcp_packets=b.tcp, bytes=b.bytes, connections=len(conns), transactions=len(txns),
        ip_fragments=b.fragments, frag_needed=b.frag_needed, capture_start=b.t_first, capture_end=b.t_last, duration_s=round(time.monotonic() - started, 3),
        warnings=_warnings(b, conns, bool(keylog or rsa_key), warnings))
    if settings.keep_capture:
        shutil.copyfile(path, tmp / "capture")
        (tmp / "capture").chmod(0o600)
    meta["capture_kept"] = settings.keep_capture
    (tmp / "meta.json").write_text(json.dumps(meta, indent=2))
    shutil.rmtree(out, ignore_errors=True)
    try:
        tmp.rename(out)
    except OSError:  # an identical analysis finished first
        shutil.rmtree(tmp, ignore_errors=True)
    return Analysis(aid, out, meta, False)


def open_analysis(aid, settings=None):
    settings = settings or Settings()
    if not re.fullmatch(r"[0-9a-f]{20}", aid):
        raise NotFound(aid)
    d = settings.workdir / aid
    if not (d / "meta.json").exists():
        raise NotFound(aid)
    return Analysis(aid, d, json.loads((d / "meta.json").read_text()), True)


def list_analyses(settings=None):
    settings = settings or Settings()
    if not settings.workdir.exists():
        return []
    metas = [json.loads(m.read_text()) for m in settings.workdir.glob("*/meta.json") if not m.parent.name.startswith(".")]
    return sorted(metas, key=lambda m: -m["created"])


def delete(aid, settings=None):
    settings = settings or Settings()
    try:
        target = open_analysis(aid, settings).dir
    except NotFound:
        return False
    shutil.rmtree(target)
    return True


def purge(settings=None, now=None):
    """Delete analyses older than the configured TTL and return how many were removed."""
    settings = settings or Settings()
    now = now or time.time()
    old = [m["id"] for m in list_analyses(settings) if now - m["created"] > settings.ttl_days * 86400]
    for aid in old:
        delete(aid, settings)
    return len(old)
