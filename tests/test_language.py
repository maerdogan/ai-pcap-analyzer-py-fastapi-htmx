import re
import subprocess
import sys
from html.parser import HTMLParser
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from pcap_analyzer import exports, engine, knowledge
from pcap_analyzer.web.app import create_app

PW = "test-pass-for-unit-tests"
ROOT = Path(__file__).resolve().parent.parent
SAME_WORDS = re.compile(r"^(pcap-analyzer|[\d\W]+|HTTP.*|TCP|TLS|URL|MSS|SACK|DNS.*|CSV|Excel|JSON|PCAP|Host|Pod|Container|Namespace|Capture( [AB])?|Normal|GET|POST|A|B|Port|ms|s|None|Offload|Türkçe|English|Deutsch|Español|Linux.*|\w+:.*)$")


class Text(HTMLParser):
    def __init__(self):
        super().__init__()
        self.found, self.skip = [], 0

    def handle_starttag(self, tag, attrs):
        self.skip += tag in ("script", "style", "pre", "option", "title")

    def handle_endtag(self, tag):
        self.skip -= tag in ("script", "style", "pre", "option", "title")

    def handle_data(self, data):
        if not self.skip and data.strip():
            self.found.append(" ".join(data.split()))


def words(html):
    t = Text()
    t.feed(html)
    return t.found


@pytest.fixture
def client(settings, samples):
    settings.admin_password = PW
    engine.analyze(samples / "backends.pcap", settings=settings)
    engine.analyze(samples / "http_scenarios.pcap", settings=settings)
    with TestClient(create_app(settings), follow_redirects=False, base_url="https://testserver") as c:
        assert c.post("/login", data={"username": "admin", "password": PW}).status_code == 303
        c.headers["X-CSRF-Token"] = re.search(r'"X-CSRF-Token": "(\w+)"', c.get("/").text)[1]
        yield c


def _pages(client):
    aid = re.findall(r"/a/([0-9a-f]{20})", client.get("/").text)
    a = aid[0]
    pages = ["/", "/compare", "/capture-guide", f"/compare?a={aid[0]}&b={aid[1]}&mode=points", f"/compare?a={aid[0]}&b={aid[1]}&mode=captures", f"/a/{a}/inspect", f"/export/{a}/report.html"]
    pages += [f"/a/{a}?tab={t}" for t in ("overview", "issues", "urls", "connections", "hosts", "backends")]
    pages += [f"/a/{a}/issue/resets", f"/a/{a}/issue/gateway", f"/a/{a}/conn/0", f"/a/{a}/txn/1", f"/a/{a}/txn/8", f"/a/{a}/txn/11"]
    return pages


def test_turkish_is_the_default(monkeypatch):
    monkeypatch.delenv("PCAP_ANALYZER_LANGUAGE")
    assert knowledge.language() == "tr" and knowledge.t("Requests") == "İstekler"


def test_language_choice_stays_for_the_browser(client):
    assert '<html lang="en">' in client.get("/").text
    r = client.post("/language", data={"language": "tr", "back": "/compare"})
    assert r.status_code == 303 and r.headers["location"] == "/compare"
    page = client.get("/compare").text
    assert '<html lang="tr">' in page and "Karşılaştır" in page


def test_language_form_needs_no_login_and_stays_on_this_site(settings):
    settings.admin_password = PW
    with TestClient(create_app(settings), follow_redirects=False, base_url="https://testserver") as c:
        assert c.post("/language", data={"language": "tr", "back": "https://evil.test/"}).headers["location"] == "/"
        assert c.post("/language", data={"language": "tr", "back": "//evil.test/"}).headers["location"] == "/"
        assert "Giriş yap" in c.get("/login").text
        assert c.post("/language", data={"language": "xx"}).status_code == 400


@pytest.mark.parametrize("lang", [x for x in knowledge.LANGUAGES if x != "en"])
def test_no_page_is_left_in_english(client, lang):
    untouched = set()
    for path in _pages(client):
        client.post("/language", data={"language": "en"})
        english = client.get(path)
        assert english.status_code == 200, path
        client.post("/language", data={"language": lang})
        other = client.get(path)
        assert other.status_code == 200, path
        same = set(words(english.text)) & set(words(other.text))
        untouched |= {f"{path}: {w}" for w in same if not SAME_WORDS.match(w) and re.search(r"[a-z]{3}", w)}
    data = {s.split(": ", 1)[1] for s in untouched}
    left = {w for w in data if not re.search(r"\.pcap|/api|/files|example|^RFC |^W3C|^NetScaler|^NGINX|^Linux|^Kubernetes|^Wireshark|^Connection flow|^FAQ|^Normal\.|^\d{3} |^: |\(RST\)|^Version |^crictl|^kubectl|^TCP port|^pcap-analyzer|^proxy_read", w)}
    def same_on_purpose(node):
        if isinstance(node, dict):
            if node.get(lang) == node.get("en") and node.get("en"):
                yield node["en"]
            for value in node.values():
                yield from same_on_purpose(value)
        elif isinstance(node, list):
            for value in node:
                yield from same_on_purpose(value)

    assert not {w for w in left if w.rstrip(".") not in set(same_on_purpose(knowledge.base()))}


def test_browser_script_gets_translated_words(client):
    client.post("/language", data={"language": "tr"})
    assert "Sunucu" in client.get("/").text.split("data-words", 1)[1][:4000]


def test_export_headers_follow_the_language(client, samples, settings, monkeypatch):
    a = engine.analyze(samples / "backends.pcap", settings=settings)
    with a.connect() as db:
        rows = exports.table(db, "requests", a.meta)
    assert exports.render(rows, "csv").decode().splitlines()[0].startswith("﻿ID,")
    monkeypatch.setenv("PCAP_ANALYZER_LANGUAGE", "tr")
    assert "Metot" in exports.render(rows, "csv").decode().splitlines()[0]
    assert exports.render(rows, "json").decode().count('"method"') == len(rows)


def test_every_exported_column_has_a_label(samples, settings):
    a = engine.analyze(samples / "http_scenarios.pcap", settings=settings)
    with a.connect() as db:
        for name in exports.TABLES:
            for col in exports.table(db, name, a.meta)[0]:
                assert col in knowledge.base()["columns"], col


def test_every_language_is_complete():
    done = subprocess.run([sys.executable, ROOT / "tools/build_knowledge.py", "--check"], capture_output=True, text=True)
    assert done.returncode == 0, done.stdout + done.stderr
