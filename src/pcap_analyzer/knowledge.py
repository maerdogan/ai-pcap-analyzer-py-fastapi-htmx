"""Plain explanations from the bundled knowledge base. No AI model or outside service is involved.

knowledge.bin is built from the knowledge/ folder by tools/build_knowledge.py. Conditions in it
test facts measured from the capture, so the same result always gives the same text.
"""
import contextvars
import hashlib
import json
import operator
import os
import string
import zlib
from functools import lru_cache
from pathlib import Path

MAGIC = b"PCAPKB1\n"
HASH_SIZE = hashlib.sha256().digest_size
LANGUAGES = ("tr", "en", "de", "es")
DEFAULT_LANGUAGE = LANGUAGES[0]
BUNDLED = Path(__file__).with_name("knowledge.bin")
TESTS = {"==": operator.eq, "!=": operator.ne, ">=": operator.ge, "<=": operator.le, ">": operator.gt, "<": operator.lt,
         "in": lambda have, want: have in want, "not in": lambda have, want: have not in want,
         "has": lambda have, want: want.lower() in str(have).lower()}


_chosen = contextvars.ContextVar("language", default=None)


class KnowledgeError(Exception):
    pass


def pack(data):
    body = zlib.compress(json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(), 9)
    return MAGIC + hashlib.sha256(body).digest() + body


def unpack(raw):
    body = raw[len(MAGIC) + HASH_SIZE:]
    if not raw.startswith(MAGIC) or hashlib.sha256(body).digest() != raw[len(MAGIC):len(MAGIC) + HASH_SIZE]:
        raise KnowledgeError("The knowledge file is damaged or is not a pcap-analyzer knowledge file.")
    return json.loads(zlib.decompress(body))


@lru_cache(maxsize=4)
def _read(path):
    try:
        return unpack(Path(path).read_bytes())
    except OSError as e:
        raise KnowledgeError(f"The knowledge file cannot be read: {e}") from e


def base():
    return _read(os.environ.get("PCAP_ANALYZER_KNOWLEDGE") or BUNDLED)


def language():
    """The language chosen for this request, then the installation's default."""
    lang = _chosen.get() or os.environ.get("PCAP_ANALYZER_LANGUAGE") or DEFAULT_LANGUAGE
    if lang not in LANGUAGES:
        raise KnowledgeError(f"PCAP_ANALYZER_LANGUAGE must be one of: {', '.join(LANGUAGES)}")
    return lang


def set_language(lang):
    _chosen.set(lang if lang in LANGUAGES else None)


def t(text, **values):
    """Interface text in the current language. The English text is the key."""
    entry = base()["ui"].get(text)
    out = entry[language()] if entry else text
    return out.format(**values) if values else out


def duration(s):
    return f"{s * 1000:.0f} ms" if s < 1 else f"{s:.2f} s"


class _Text(string.Formatter):
    """Fill a template with facts: {x:time} prints seconds, {x:term} translates a word, and a missing fact prints a dash."""

    def get_value(self, key, args, kwargs):
        return kwargs.get(key)

    def format_field(self, value, spec):
        if spec == "term":
            terms = base()["terms"]
            return terms.get(value, terms["other"])[language()]
        if value is None:
            return "–"
        return duration(value) if spec == "time" else format(value, spec)


def _fill(entry, facts):
    return _Text().vformat(entry[language()], (), facts)


def holds(rule, facts):
    """True when every [fact, test, value] holds. A missing fact never matches."""
    return all(facts.get(name) is not None and TESTS[test](facts[name], want) for name, test, want in rule)


def _matching(entries, facts):
    return [_fill(e, facts) for e in entries if holds(e.get("when", ()), facts)]


def label(topic):
    return base()["topics"][topic]["label"][language()]


def summary(topic, facts):
    """One or two sentences for a result row. The first variant that matches wins."""
    return _matching(base()["topics"][topic]["summary"], facts)[0] + "".join(_matching(base()["common"]["suffix"], facts))


def reset_note(code):
    note = base()["netscaler_resets"].get(str(code))
    return note[language()] if note else None


def guide(topic, facts=None):
    """The full explanation of a topic. Lines with conditions appear only when this capture meets them."""
    facts = dict(facts or {}, rst_note=reset_note((facts or {}).get("rst_code")))
    entry, lang = base()["topics"][topic], language()
    if "meaning" not in entry:
        return None
    return dict(meaning=entry["meaning"][lang], misread=entry["misread"][lang] if "misread" in entry else None,
                evidence=_matching(entry.get("evidence", []) + base()["common"]["evidence"], facts),
                checks=_matching(entry["checks"], facts), headings={k: v[lang] for k, v in base()["headings"].items()},
                sources=[dict(base()["sources"][key], where=where) for key, where in entry["sources"]])


def phase(name, seconds):
    entry = base()["phases"][name]
    return dict(name=name, label=entry["label"][language()], about=entry["about"][language()], seconds=seconds)


def issue(key):
    entry = base()["issues"][key]
    return dict(key=key, title=entry["title"][language()], why=entry["why"][language()], topic=entry["topic"])


def warnings():
    return {key: text[language()] for key, text in base()["warnings"].items()}


def quality_line(key, count):
    return _fill(base()["quality"][key], dict(n=count))


def column(name):
    entry = base()["columns"].get(name)
    return entry[language()] if entry else name
