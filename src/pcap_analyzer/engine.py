"""Analyze a capture once and keep the result; the same input reopens the saved result."""
import gzip
import hashlib
import json
import re
import shutil
import tempfile
import time
from dataclasses import astuple, dataclass
from pathlib import Path

from . import __version__, knowledge, records, split, store, tshark
from .config import Settings
from .parser import Builder, finish_stream, nat_views


DNS_WINDOW_S = 5.0
GZIP_MAGIC = b"\x1f\x8b"
COMPRESSED_MAGIC = (b"\x28\xb5\x2f\xfd", b"\x04\x22\x4d\x18")  # zstd, lz4
CHUNK = 1 << 20
STALE_TMP_S = 6 * 3600
TMP_PREFIXES = ("pcap-analyzer-", "pcap-upload-", "pcap-export-")
PART_BYTES = 100 * CHUNK  # a larger capture is read in parts, and one part takes about as much memory as a capture this size
STREAM_FIELDS = re.compile(r"\b(frame\.number|tcp\.stream)\b")


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


def unpack(path, folder, settings):
    """Unpack a gzip capture and stop at the size limit, because the real size is unknown until then."""
    with open(path, "rb") as f:
        if f.read(2) != GZIP_MAGIC:
            return Path(path)
    limit, written = settings.max_size_mb * CHUNK, 0
    fd, name = tempfile.mkstemp(prefix="unpacked-", dir=folder)
    try:
        with gzip.open(path, "rb") as src, open(fd, "wb") as dst:
            while chunk := src.read(CHUNK):
                written += len(chunk)
                if written > limit:
                    raise CaptureTooLarge(knowledge.t("{name} is larger than the {n} MB limit", name=Path(path).name, n=settings.max_size_mb))
                dst.write(chunk)
    except (OSError, EOFError) as e:
        raise CompressedCapture(knowledge.t("This gzip file is damaged: {reason}", reason=e)) from e
    return Path(name)


def join_parts(paths, folder, settings):
    """Turn several parts into one capture, unpacking each first and holding the size limit on the result."""
    parts = [unpack(p, folder, settings) for p in paths]
    for p in parts:
        _refuse_compressed(p)
    if sum(p.stat().st_size for p in parts) > settings.max_size_mb * CHUNK:
        raise CaptureTooLarge(knowledge.t("{name} is larger than the {n} MB limit", name=Path(paths[0]).name, n=settings.max_size_mb))
    if len(parts) == 1:
        return parts[0]
    out = Path(folder) / "merged.pcapng"
    tshark.merge(parts, out, settings.mergecap, settings.tshark)
    return out


def _digest(paths, flt, slow_s):
    h = hashlib.sha256()
    h.update(__version__.encode())
    for p in paths:
        h.update(b"\0")
        if p:
            with open(p, "rb") as f:
                while chunk := f.read(1 << 20):
                    h.update(chunk)
    h.update(repr((astuple(flt), slow_s)).encode())
    return h.hexdigest()[:20]


def _facts(db):
    """What the warnings and the quality report need from the saved connections and requests."""
    c = db.execute("""SELECT count(*), count(*) FILTER (NOT handshake_seen), count(*) FILTER (close_type IS NULL),
        count(*) FILTER ((payload_client = 0 AND payload_server = 0) OR one_way), count(*) FILTER (kind = 'TLS'),
        coalesce(bool_or(offload), false), coalesce(bool_or(kind = 'TLS' AND handshake_seen), false), coalesce(bool_or(kind = 'TLS' AND NOT handshake_seen), false)
        FROM tcp_connections""").fetchone()
    events = dict(db.execute("SELECT event, count(*) FROM tcp_events WHERE event IN ('ack_lost_segment', 'lost_segment') GROUP BY event").fetchall())
    shared = db.execute("""SELECT 1 FROM http_transactions WHERE request_id IS NOT NULL AND request_id <> ''
        GROUP BY request_id HAVING count(DISTINCT stream) > 1 LIMIT 1""").fetchone()
    return dict(connections=c[0], started_before=c[1], open_at_end=c[2], one_way=c[3], encrypted=c[4], offload=c[5],
                tls_handshake_seen=c[6], tls_started_before=c[7], unseen=events.get("ack_lost_segment", 0), gaps=events.get("lost_segment", 0),
                shared_request_id=bool(shared), transactions=db.execute("SELECT count(*) FROM http_transactions").fetchone()[0])


def _warnings(b, facts, keyed, warnings):
    if b.truncated:
        warnings.append("frames_truncated")
    if b.copies:
        warnings.append("copies_removed")
    if b.nat_views:
        warnings.append("nat_views_removed")
    if facts["shared_request_id"]:
        warnings.append("same_request_on_two_connections")
    if b.tunnelled:
        warnings.append("tunnel_seen")
    if facts["offload"]:
        warnings.append("offload_suspected")
    if not keyed and facts["encrypted"]:
        warnings.append("tls_not_decrypted")
    if keyed and facts["tls_handshake_seen"]:
        warnings.append("tls_key_did_not_decrypt")
    if keyed and facts["tls_started_before"]:
        warnings.append("tls_started_before_capture")  # its keys cannot be matched without the handshake
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


def _quality(b, facts):
    """Counts that show how far this capture can be trusted. Levels and wording come later, from the reports."""
    return dict(tcp_packets=b.tcp, connections=facts["connections"], unseen=facts["unseen"], gaps=facts["gaps"], snapped=b.truncated, copies=b.copies,
                started_before=facts["started_before"], open_at_end=facts["open_at_end"], one_way=facts["one_way"], encrypted=facts["encrypted"])


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
    if path.stat().st_size > settings.max_size_mb * CHUNK:
        raise CaptureTooLarge(knowledge.t("{name} is larger than the {n} MB limit", name=path.name, n=settings.max_size_mb))
    with tempfile.TemporaryDirectory(prefix="pcap-analyzer-", dir="/tmp") as folder:
        capture = join_parts([path], folder, settings)
        display_name = display_name or path.name.removesuffix(".gz")
        return _run(capture, keylog, rsa_key, flt, settings, use_cached, display_name, limit)


def _run(path, keylog, rsa_key, flt, settings, use_cached, display_name, limit):
    ts_version = tshark.version(settings.tshark)
    slow_s = records.slow_s(settings)
    aid = _digest([path, keylog, rsa_key], flt, slow_s)
    out = settings.workdir / aid
    if use_cached and (out / "meta.json").exists():
        return Analysis(aid, out, json.loads((out / "meta.json").read_text()), True)

    started = time.monotonic()
    warnings = []
    run = lambda feed=None: tshark.packets(path, keylog, rsa_key, flt, settings.tshark, warnings, limit, settings.workdir, settings.analysis_timeout_s, feed)
    settings.workdir.mkdir(parents=True, exist_ok=True)
    tmp = Path(tempfile.mkdtemp(prefix=".tmp-", dir=settings.workdir))
    try:
        writer = store.Writer(tmp / "analysis.duckdb")
        b, views = Builder(), []
        if path.stat().st_size > PART_BYTES:
            number, parts = _read_in_parts(path, flt, run, b, writer, views, limit, slow_s, warnings)
        else:
            for p in run():
                b.add(p)
            _flush(b, writer, views, limit, slow_s)
            dropped = nat_views(views, lambda sid: sid)
            number, parts = {sid: sid for sid, _, _ in views if sid not in dropped}, 0
            b.nat_views = len(dropped)
        limit.check()
        writer.close(number, b.dns_rows, lambda txns: _attach_dns(txns, b.dns_rows))
        limit.check()
        return _save(tmp, out, aid, path, keylog, rsa_key, flt, settings, display_name, ts_version, started, warnings, b, parts, slow_s)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _flush(b, writer, views, limit, slow_s, part=None, offset=0):
    """Finish the connections read so far, hand them to the writer and forget their packets."""
    conns, txns = [], []
    for s in b.streams.values():
        limit.check()
        c, t = finish_stream(s, slow_s)
        if part is not None:
            c.update(part=part, part_stream=c["stream"] - offset)
        conns.append(c)
        txns += t
        views.append((s.sid, s.syn.t if s.syn else None, s.isn))
    _attach_packet_size(b, txns)
    writer.add(conns, txns, b.events)
    b.streams.clear()
    b.events.clear()


def _read_in_parts(path, flt, run, b, writer, views, limit, slow_s, warnings):
    """Analyze a large capture in parts of whole connections, so memory stays near that of one part.
    Frame and connection numbers are turned back into those of the whole capture, the way Wireshark counts them."""
    if flt.display and STREAM_FIELDS.search(flt.display):
        raise tshark.TsharkError(knowledge.t("Captures over {n} MB are read in parts, so a display filter cannot use frame.number or tcp.stream. Filter by address, port or time instead.", n=PART_BYTES // CHUNK))
    try:
        plan = split.plan(path, -(-path.stat().st_size // PART_BYTES))
    except split.Unsupported as e:
        raise tshark.TsharkError(knowledge.t("Captures over {n} MB must be pcap or pcapng files.", n=PART_BYTES // CHUNK)) from e
    if plan.truncated:
        warnings.append("capture_truncated")
    first_frame = {}  # first frame of every connection, by its number while reading
    for k, part in enumerate(plan.parts):
        offset = max(first_frame, default=-1) + 1
        for p in run(lambda k=k: split.feed(path, plan, k)):
            _to_whole(p, part.frames, offset, first_frame)
            b.add(p)
        _flush(b, writer, views, limit, slow_s, k, offset)
    dropped = nat_views(views, first_frame.get)
    b.nat_views = len(dropped)
    order = sorted(first_frame, key=first_frame.get)
    return {sid: i for i, sid in enumerate(order) if sid not in dropped}, len(plan.parts)


def _to_whole(p, frames, offset, first_frame):
    """Frame and connection numbers of one part, as numbers of the whole capture."""
    whole = frames[int(p["frame.number"]) - 1]
    p["frame.number"] = str(whole)
    if p.get("tcp.analysis.acks_frame"):
        p["tcp.analysis.acks_frame"] = str(frames[int(p["tcp.analysis.acks_frame"]) - 1])
    for key in ("tcp.segment", "tls.segment"):
        if p.get(key):
            p[key] = tshark.AGG.join(str(frames[int(x) - 1]) for x in p[key].split(tshark.AGG))
    if p.get("tcp.stream"):
        sids = [int(x) + offset for x in p["tcp.stream"].split(tshark.AGG)]
        for sid in sids:
            first_frame.setdefault(sid, whole)
        p["tcp.stream"] = tshark.AGG.join(map(str, sids))


def _save(tmp, out, aid, path, keylog, rsa_key, flt, settings, display_name, ts_version, started, warnings, b, parts, slow_s):
    with store.connect(tmp / "analysis.duckdb") as db:
        facts = _facts(db)
    meta = dict(
        id=aid, filename=display_name or path.name, size=path.stat().st_size, created=time.time(), tshark=ts_version, version=__version__,
        decryption="keylog" if keylog else "rsa_key" if rsa_key else None, filter=flt.expression(),
        packets=b.total, tcp_packets=b.tcp, bytes=b.bytes, connections=facts["connections"], transactions=facts["transactions"],
        ip_fragments=b.fragments, frag_needed=b.frag_needed, copies=b.copies, tunnelled=b.tunnelled, capture_start=b.t_first, capture_end=b.t_last, duration_s=round(time.monotonic() - started, 3), slow_s=slow_s,
        quality=_quality(b, facts), warnings=_warnings(b, facts, bool(keylog or rsa_key), warnings), parts=parts)
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
    records.trim_audit(settings)
    cutoff = now - STALE_TMP_S
    if settings.workdir.exists():
        _remove_stale(settings.workdir.glob(".tmp-*"), cutoff)
    if tmp_root.exists():  # these can hold captures and TLS keys
        _remove_stale((p for p in tmp_root.iterdir() if p.name.startswith(TMP_PREFIXES)), cutoff)
    return len(old)
