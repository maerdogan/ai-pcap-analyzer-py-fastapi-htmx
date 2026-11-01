"""Analyze a capture once and keep the result; the same input reopens the saved result."""
import hashlib
import json
import shutil
import time
from dataclasses import astuple, dataclass
from pathlib import Path

from . import __version__, store, tshark
from .config import Settings
from .parser import Builder, finish_stream


class CaptureTooLarge(Exception):
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
    tls_undecrypted = [c for c in conns if c["kind"] == "TLS"]
    if tls_undecrypted:
        warnings.append("tls_key_did_not_decrypt" if keyed else "tls_not_decrypted")
    return sorted(set(warnings))


def analyze(path, keylog=None, rsa_key=None, flt=None, settings=None, use_cached=True):
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

    tmp = settings.workdir / f".{aid}.tmp"
    shutil.rmtree(tmp, ignore_errors=True)
    tmp.mkdir(parents=True)
    tmp.chmod(0o700)
    store.write(tmp / "analysis.duckdb", conns, txns, b.events, b.dns_rows)
    meta = dict(
        id=aid, filename=path.name, size=path.stat().st_size, created=time.time(), tshark=ts_version, version=__version__,
        decryption="keylog" if keylog else "rsa_key" if rsa_key else None, filter=flt.expression(),
        packets=b.total, tcp_packets=b.tcp, bytes=b.bytes, connections=len(conns), transactions=len(txns),
        capture_start=b.t_first, capture_end=b.t_last, duration_s=round(time.monotonic() - started, 3),
        warnings=_warnings(b, conns, bool(keylog or rsa_key), warnings))
    (tmp / "meta.json").write_text(json.dumps(meta, indent=2))
    shutil.rmtree(out, ignore_errors=True)
    tmp.rename(out)
    return Analysis(aid, out, meta, False)


def list_analyses(settings=None):
    settings = settings or Settings()
    if not settings.workdir.exists():
        return []
    metas = [json.loads(m.read_text()) for m in settings.workdir.glob("*/meta.json") if not m.parent.name.startswith(".")]
    return sorted(metas, key=lambda m: -m["created"])


def delete(aid, settings=None):
    settings = settings or Settings()
    target = settings.workdir / aid
    if not (target / "meta.json").exists():
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
