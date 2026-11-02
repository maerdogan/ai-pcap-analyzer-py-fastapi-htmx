"""Small records kept beside the analyses: notes, audit trail, baseline, thresholds and API tokens."""
import fcntl
import hashlib
import hmac
import json
import os
import re
import secrets
import time
from pathlib import Path

from . import causes

AUDIT_KEEP = 10_000
TOKEN_PREFIX = "pat_"


def _read(path, default):
    try:
        return json.loads(Path(path).read_text())
    except (OSError, ValueError):
        return default


def _write(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(f".{secrets.token_hex(4)}.tmp")
    tmp.write_text(json.dumps(data, indent=2))
    os.chmod(tmp, 0o600)
    tmp.replace(path)


def notes(settings, aid):
    return _read(settings.workdir / aid / "notes.json", dict(case="", tags="", note=""))


def save_notes(settings, aid, case, tags, note):
    _write(settings.workdir / aid / "notes.json", dict(case=case.strip()[:80], tags=tags.strip()[:200], note=note.strip()[:4000]))


def search(settings, metas, text):
    """Analyses whose file name, case, tags or note hold the text."""
    text = text.strip().casefold()
    if not text:
        return metas
    found = []
    for m in metas:
        n = notes(settings, m["id"])
        if text in " ".join((m["filename"], n["case"], n["tags"], n["note"])).casefold():
            found.append(m)
    return found


def audit(settings, event, client, detail=""):
    settings.workdir.mkdir(parents=True, exist_ok=True)
    line = json.dumps(dict(time=time.time(), event=event, client=client, detail=str(detail)[:300]))
    with open(settings.workdir / "audit.log", "a", encoding="utf-8") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        f.write(line + "\n")


def read_audit(settings, event=None, limit=500):
    try:
        lines = (settings.workdir / "audit.log").read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    rows = [json.loads(x) for x in lines[-AUDIT_KEEP:]]
    return [r for r in reversed(rows) if not event or r["event"] == event][:limit]


def trim_audit(settings):
    path = settings.workdir / "audit.log"
    try:
        lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    except OSError:
        return
    if len(lines) > AUDIT_KEEP:
        path.write_text("".join(lines[-AUDIT_KEEP:]), encoding="utf-8")


def baseline(settings):
    return _read(settings.workdir / "baseline.json", {}).get("id")


def set_baseline(settings, aid):
    _write(settings.workdir / "baseline.json", dict(id=aid))


def thresholds(settings):
    return _read(settings.workdir / "thresholds.json", dict(slow_s=causes.SLOW_S, targets=[]))


def slow_s(settings):
    return thresholds(settings)["slow_s"]


def save_thresholds(settings, slow, targets):
    _write(settings.workdir / "thresholds.json", dict(slow_s=slow, targets=targets))


def parse_targets(text):
    """One 'URL-pattern seconds' per line. Returns the targets and the lines that could not be read."""
    targets, bad = [], []
    for line in text.splitlines():
        m = re.fullmatch(r"\s*(\S+)\s+([0-9]*\.?[0-9]+)\s*", line)
        if m:
            targets.append(dict(pattern=m[1], seconds=float(m[2])))
        elif line.strip():
            bad.append(line.strip())
    return targets, bad


def _hash(token):
    return hashlib.sha256(token.encode()).hexdigest()


def tokens(settings):
    return _read(settings.workdir / "api_tokens.json", [])


def new_token(settings, name):
    """The token itself is shown once. Only its hash is stored, and it has 256 random bits, so a plain hash is enough."""
    token = TOKEN_PREFIX + secrets.token_urlsafe(32)
    rows = tokens(settings)
    rows.append(dict(id=secrets.token_hex(6), name=name.strip()[:80], hash=_hash(token), created=time.time()))
    _write(settings.workdir / "api_tokens.json", rows)
    return token


def revoke_token(settings, tid):
    _write(settings.workdir / "api_tokens.json", [t for t in tokens(settings) if t["id"] != tid])


def token_name(settings, token):
    """The name of a valid token, or None."""
    digest = _hash(token or "")
    return next((t["name"] or t["id"] for t in tokens(settings) if hmac.compare_digest(t["hash"], digest)), None)
