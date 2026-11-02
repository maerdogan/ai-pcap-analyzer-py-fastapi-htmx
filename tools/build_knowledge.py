#!/usr/bin/env python3
"""Check the knowledge/ folder and build src/pcap_analyzer/knowledge.bin from it.

Usage: build_knowledge.py [--check] [output]
With --check nothing is written, and the run fails if the bundled file is out of date.
"""
import json
import re
import string
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from pcap_analyzer import causes, knowledge, reports, store  # noqa: E402

MIN_OTHER_FIELDS = ("meaning", "checks", "sources")
FACTS = set(causes.facts({}, {})) | set(store.columns("http_transactions")) | {"rst_note", "n"}
UI_FIELDS = re.compile(r"\{(\w*)\}")


def _read(name):
    return json.loads((ROOT / "knowledge" / name).read_text(encoding="utf-8"))


def _fill(node, lang, table):
    """Add a language to every text. Languages other than English and Turkish live in their own table, keyed by the English text."""
    if isinstance(node, dict):
        if isinstance(node.get("en"), str) and lang not in node and node["en"] in table:
            node[lang] = table[node["en"]]
        for value in node.values():
            _fill(value, lang, table)
    elif isinstance(node, list):
        for value in node:
            _fill(value, lang, table)


def load():
    data = _read("catalog.json")
    data["topics"] = _read("topics.json")
    data["sources"] = _read("sources.json")
    data["columns"] = {name: dict(en=label) for name, label in _read("columns.json").items()}
    data["ui"] = {text: dict(en=text) for text in sorted(interface_text() | set(_read("ui_extra.json")))}
    for lang in knowledge.LANGUAGES:
        if lang != "en":
            _fill(data, lang, _read(f"translations/{lang}.json"))
    return data


def _text(where, entry, problems):
    for lang in knowledge.LANGUAGES:
        if not isinstance(entry.get(lang), str) or not entry[lang].strip():
            problems.append(f"{where}: no {lang} text")
            continue
        for _, name, _, _ in string.Formatter().parse(entry[lang]):
            if name is not None and name not in FACTS:
                problems.append(f"{where}: unknown fact {name}")
    if all(entry.get(lang) for lang in knowledge.LANGUAGES):
        names = [{n for _, n, _, _ in string.Formatter().parse(entry[lang]) if n} for lang in knowledge.LANGUAGES]
        if any(n != names[0] for n in names):
            problems.append(f"{where}: languages use different facts")


def _rule(where, entry, problems):
    for name, test, _ in entry.get("when", ()):
        if name not in FACTS:
            problems.append(f"{where}: unknown fact {name}")
        if test not in knowledge.TESTS:
            problems.append(f"{where}: unknown test {test}")


def _lines(where, entries, problems):
    for n, entry in enumerate(entries):
        _rule(f"{where}[{n}]", entry, problems)
        _text(f"{where}[{n}]", entry, problems)


def interface_text():
    """Every text the code asks for, found by reading the templates, the Python code and the browser script."""
    src = ROOT / "src/pcap_analyzer"
    found = set()
    for path in [*src.glob("web/templates/*.html"), *src.glob("**/*.py"), src / "web/static/app.js"]:
        code = path.read_text(encoding="utf-8")
        for m in re.finditer(r'(?:\b_|knowledge\.t|(?<![\w.])t)\("((?:[^"\\]|\\.)*)"', code):
            found.add(m[1].replace('\\"', '"'))
    return found


def validate(data):
    """Return every problem found: text in only one language, unknown facts, or something the code needs but cannot find."""
    problems = []
    topics = data["topics"]
    for key, t in topics.items():
        _text(f"{key}.label", t["label"], problems)
        _lines(f"{key}.summary", t.get("summary", []), problems)
        _lines(f"{key}.evidence", t.get("evidence", []), problems)
        _lines(f"{key}.checks", t.get("checks", []), problems)
        for part in ("meaning", "misread"):
            if part in t:
                _text(f"{key}.{part}", t[part], problems)
        for source, _where in t.get("sources", []):
            if source not in data["sources"]:
                problems.append(f"{key}: unknown source {source}")
        if key != "normal":
            problems += [f"{key}: {f} is missing" for f in MIN_OTHER_FIELDS if not t.get(f)]
    for key in causes.CAUSES:
        if not topics.get(key, {}).get("summary"):
            problems.append(f"{key}: a cause needs a summary")
        elif topics[key]["summary"][-1].get("when"):
            problems.append(f"{key}: the last summary needs no condition")
    for key in causes.PHASES + ["waiting"]:
        if key not in data["phases"]:
            problems.append(f"phase {key} is missing")
    for key in reports.issue_keys():
        if key not in data["issues"]:
            problems.append(f"issue {key} is missing")
    for key, entry in data["issues"].items():
        if entry["topic"] not in topics:
            problems.append(f"issue {key}: unknown topic {entry['topic']}")
    for key in ("frames_truncated", "capture_truncated", "offload_suspected", "tls_not_decrypted", "tls_key_did_not_decrypt", "copies_removed", "tunnel_seen"):
        if key not in data["warnings"]:
            problems.append(f"warning {key} is missing")
    for section in ("headings", "terms", "warnings", "netscaler_resets", "quality"):
        for key, entry in data[section].items():
            _text(f"{section}.{key}", entry, problems)
    for section in ("columns", "ui"):
        for key, entry in data[section].items():
            names = [set(UI_FIELDS.findall(entry.get(lang) or "")) for lang in knowledge.LANGUAGES]
            if not all(entry.get(lang) for lang in knowledge.LANGUAGES):
                problems.append(f"{section}: no text in every language for {key}")
            elif any(n != names[0] for n in names):
                problems.append(f"{section}: languages use different fields in {key}")
    _lines("common.suffix", data["common"]["suffix"], problems)
    _lines("common.evidence", data["common"]["evidence"], problems)
    return problems


def main():
    args = sys.argv[1:]
    check = "--check" in args
    args = [a for a in args if a != "--check"]
    data = load()
    problems = validate(data)
    if problems:
        sys.exit("\n".join(problems))
    out = Path(args[0]) if args else knowledge.BUNDLED
    if check:
        if not out.exists() or knowledge.unpack(out.read_bytes()) != data:
            sys.exit(f"{out} is out of date. Run tools/build_knowledge.py")
    else:
        out.write_bytes(knowledge.pack(data))
    print(f"{len(data['topics'])} topics, {len(data['issues'])} issues, {len(data['sources'])} sources: {out}")


if __name__ == "__main__":
    main()
