"""Mask secrets before anything is saved, so results and exports never hold them."""
import re

MASK = "***"
SENSITIVE_HEADERS = {
    "authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key", "x-auth-token", "x-csrf-token",
    "x-amz-security-token",
}
SENSITIVE_WORDS = r"pass(?:word|wd)?|pwd|secret|token|api[_-]?key|access[_-]?key|session(?:id)?|auth"
_QUERY = re.compile(rf"(?i)([?&;](?:\w*(?:{SENSITIVE_WORDS})\w*)=)[^&;#\s]*")
_FORM = re.compile(rf"(?i)((?:^|[&;\s])\w*(?:{SENSITIVE_WORDS})\w*=)[^&;\s]*")
_JSON = re.compile(rf'(?i)("\w*(?:{SENSITIVE_WORDS})\w*"\s*:\s*)"(?:[^"\\]|\\.)*"')


def mask_uri(uri):
    return _QUERY.sub(rf"\1{MASK}", uri) if uri else uri


def mask_header(name, value):
    return MASK if name.strip().lower() in SENSITIVE_HEADERS else value


def mask_body(text):
    if not text:
        return text
    return _JSON.sub(rf'\1"{MASK}"', _FORM.sub(rf"\1{MASK}", text))
