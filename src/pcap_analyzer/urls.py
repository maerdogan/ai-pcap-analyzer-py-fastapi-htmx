"""Group URLs by shape: /users/123/orders becomes /users/{id}/orders."""
import re

_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_HEX = re.compile(r"^[0-9a-f]{16,}$", re.I)
_MIXED = re.compile(r"^(?=.*\d)(?=.*[a-zA-Z])[A-Za-z0-9_-]{12,}$")


def _variable(seg):
    return seg.isdigit() or bool(_UUID.match(seg) or _HEX.match(seg) or _MIXED.match(seg))


def template(uri):
    if not uri:
        return uri
    if "://" in uri:  # absolute form sent to proxies
        uri = "/" + uri.split("://", 1)[1].partition("/")[2]
    path = uri.split("?", 1)[0].split("#", 1)[0]
    return "/".join("{id}" if _variable(s) else s for s in path.split("/")) or "/"
