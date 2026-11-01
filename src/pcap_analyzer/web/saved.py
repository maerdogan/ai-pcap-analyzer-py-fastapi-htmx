"""Saved inspection filters, kept as one JSON file because there is no shared database."""
import json
import os
import secrets
import threading

FIELDS = ("src", "dst", "port", "kind", "url", "min_size", "size_of")
_lock = threading.Lock()


def _path(settings):
    return settings.workdir / "saved_filters.json"


def load(settings):
    p = _path(settings)
    return json.loads(p.read_text()) if p.exists() else []


def _write(settings, items):
    settings.workdir.mkdir(parents=True, exist_ok=True)
    tmp = _path(settings).with_suffix(".tmp")
    tmp.write_text(json.dumps(items, indent=2))
    os.chmod(tmp, 0o600)
    tmp.replace(_path(settings))


def add(settings, name, values):
    with _lock:
        items = load(settings)
        items.append(dict(id=secrets.token_hex(6), name=name, **{k: values.get(k) or None for k in FIELDS}))
        _write(settings, items)


def remove(settings, fid):
    with _lock:
        _write(settings, [i for i in load(settings) if i["id"] != fid])
