"""Analyze a capture once and keep the result; the same input reopens the saved result."""
import hashlib
import json
import re
import shutil
import tempfile
import time
from collections import Counter
from dataclasses import astuple, dataclass
from pathlib import Path

from . import __version__, knowledge, store, tshark
from .config import Settings
from .parser import Builder, finish_stream


DNS_WINDOW_S = 5.0
COMPRESSED_MAGIC = (b"\x1f\x8b", b"\x28\xb5\x2f\xfd", b"\x04\x22\x4d\x18")  # gzip, zstd, lz4
STALE_TMP_S = 6 * 3600
TMP_PREFIXES = ("pcap-analyzer-", "pcap-upload-", "pcap-export-")


class CaptureTooLarge(Exception):
    pass


class NotFound(Exception):
    pass


class CompressedCapture(ValueError):
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


def _refuse_compressed(path):
    """tshark would unpack these, and the unpacked size cannot be known or limited beforehand."""
    with open(path, "rb") as f:
        head = f.read(4)
    if head.startswith(COMPRESSED_MAGIC):
        raise CompressedCapture(knowledge.t("Compressed captures are not accepted, because their real size cannot be checked. Decompress the file and upload it again."))


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
    if b.copies:
        warnings.append("copies_removed")
    if b.tunnelled:
        warnings.append("tunnel_seen")
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


def _quality(b, conns):
    """Counts that show how far this capture can be trusted. Levels and wording come later, from the reports."""
    events = Counter(e[4] for e in b.events)
    return dict(tcp_packets=b.tcp, connections=len(conns), unseen=events["ack_lost_segment"], gaps=events["lost_segment"], snapped=b.truncated, copies=b.copies,
                started_before=sum(not c["handshake_seen"] for c in conns), open_at_end=sum(not c["close_type"] for c in conns),
                one_way=sum(not (c["payload_client"] or c["payload_server"]) or c["one_way"] for c in conns),
                encrypted=sum(c["kind"] == "TLS" for c in conns))


def analyze(path, keylog=None, rsa_key=None, flt=None, settings=None, use_cached=True, display_name=None, limit=None):
    settings = settings or Settings()
    own_limit = limit is None
    limit = limit or tshark.Limit(settings.analysis_timeout_s)
    try:
        return _analyze(path, keylog, rsa_key, flt, settings, use_cached, display_name, limit)
    finally:
        if own_limit:
            limit.close()


def _analyze(path, keylog, rsa_key, flt, settings, use_cached, display_name, limit):
    flt = flt or tshark.Filter()
    path = Path(path)
    if path.stat().st_size > settings.max_size_mb * 1024 * 1024:
        raise CaptureTooLarge(knowledge.t("{name} is larger than the {n} MB limit", name=path.name, n=settings.max_size_mb))
    _refuse_compressed(path)
    ts_version = tshark.version(settings.tshark)
    aid = _digest([path, keylog, rsa_key], flt)
    out = settings.workdir / aid
    if use_cached and (out / "meta.json").exists():
        return Analysis(aid, out, json.loads((out / "meta.json").read_text()), True)

    started = time.monotonic()
    warnings = []
    b = Builder()
    for p in tshark.packets(path, keylog, rsa_key, flt, settings.tshark, warnings, limit):
        b.add(p)
    conns, txns = [], []
    for s in b.streams.values():
        limit.check()
        c, t = finish_stream(s)
        conns.append(c)
        txns += t
    txns.sort(key=lambda x: x["req_start"])
    _attach_dns(txns, b.dns_rows)
    _attach_packet_size(b, txns)

    settings.workdir.mkdir(parents=True, exist_ok=True)
    tmp = Path(tempfile.mkdtemp(prefix=".tmp-", dir=settings.workdir))
    try:
        return _save(tmp, out, aid, path, keylog, rsa_key, flt, settings, display_name, ts_version, started, warnings, b, conns, txns, limit)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _save(tmp, out, aid, path, keylog, rsa_key, flt, settings, display_name, ts_version, started, warnings, b, conns, txns, limit):
    store.write(tmp / "analysis.duckdb", conns, txns, b.events, b.dns_rows)
    limit.check()
    meta = dict(
        id=aid, filename=display_name or path.name, size=path.stat().st_size, created=time.time(), tshark=ts_version, version=__version__,
        decryption="keylog" if keylog else "rsa_key" if rsa_key else None, filter=flt.expression(),
        packets=b.total, tcp_packets=b.tcp, bytes=b.bytes, connections=len(conns), transactions=len(txns),
        ip_fragments=b.fragments, frag_needed=b.frag_needed, copies=b.copies, tunnelled=b.tunnelled, capture_start=b.t_first, capture_end=b.t_last, duration_s=round(time.monotonic() - started, 3),
        quality=_quality(b, conns), warnings=_warnings(b, conns, bool(keylog or rsa_key), warnings))
    if settings.keep_capture:
        shutil.copyfile(path, tmp / "capture")
        (tmp / "capture").chmod(0o600)
    meta["capture_kept"] = settings.keep_capture
    (tmp / "meta.json").write_text(json.dumps(meta, indent=2))
    shutil.rmtree(out, ignore_errors=True)
    try:
        tmp.rename(out)
    except OSError:  # an identical analysis finished first
        pass
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


def _remove_stale(paths, cutoff):
    for p in paths:
        try:
            if p.is_dir() and p.stat().st_mtime < cutoff:
                shutil.rmtree(p, ignore_errors=True)
        except OSError:
            continue  # another process removed it, or it belongs to another user


def purge(settings=None, now=None, tmp_root=Path("/tmp")):
    """Delete expired analyses and what a killed process left behind, and return how many analyses were removed."""
    settings = settings or Settings()
    now = now or time.time()
    old = [m["id"] for m in list_analyses(settings) if now - m["created"] > settings.ttl_days * 86400]
    for aid in old:
        delete(aid, settings)
    cutoff = now - STALE_TMP_S
    if settings.workdir.exists():
        _remove_stale(settings.workdir.glob(".tmp-*"), cutoff)
    if tmp_root.exists():  # these can hold captures and TLS keys
        _remove_stale((p for p in tmp_root.iterdir() if p.name.startswith(TMP_PREFIXES)), cutoff)
    return len(old)
