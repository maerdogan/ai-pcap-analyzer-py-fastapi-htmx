import subprocess
import sys
from pathlib import Path

import pytest

from pcap_analyzer import causes, engine, knowledge, reports

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def a(samples, settings):
    return engine.analyze(samples / "http_scenarios.pcap", settings=settings)


def _reset_request(db):
    return next(t for t in reports.slowest(db, "t.cause = 'connection_reset'") if t["conn"]["rst_code"] == 9300)


def test_bundled_file_matches_the_source():
    r = subprocess.run([sys.executable, ROOT / "tools/build_knowledge.py", "--check"], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr


def test_pack_round_trip_and_damage():
    raw = knowledge.pack({"a": "ü"})
    assert knowledge.unpack(raw) == {"a": "ü"}
    with pytest.raises(knowledge.KnowledgeError):
        knowledge.unpack(raw[:-1] + bytes([raw[-1] ^ 1]))
    with pytest.raises(knowledge.KnowledgeError):
        knowledge.unpack(b"not a knowledge file")


def test_conditions():
    assert knowledge.holds([["x", ">=", 1], ["y", "in", ["a"]]], {"x": 1, "y": "a"})
    assert not knowledge.holds([["x", ">=", 1]], {"x": None})
    assert not knowledge.holds([["x", "!=", ""]], {})
    assert knowledge.holds([["h", "has", "NGINX"]], {"h": "Server: nginx"})


@pytest.mark.parametrize("value,expected", [(30.05, 30), (60.5, 60), (44, None), (None, None)])
def test_round_timeouts(value, expected):
    assert causes._near(value, causes.ROUND_TIMEOUTS, 0.01) == expected


def test_each_language_has_every_cause(monkeypatch):
    for lang in knowledge.LANGUAGES:
        monkeypatch.setenv("PCAP_ANALYZER_LANGUAGE", lang)
        for cause in causes.CAUSES:
            assert knowledge.summary(cause, {"cause": cause})
    monkeypatch.setenv("PCAP_ANALYZER_LANGUAGE", "xx")
    with pytest.raises(knowledge.KnowledgeError):
        knowledge.label("normal")


def test_reset_code_reaches_the_explanation(a):
    with a.connect() as db:
        t = reports.transaction(db, _reset_request(db)["id"])
    assert any("9300" in line and "timeout" in line for line in t["guide"]["evidence"])
    assert any("30 seconds" in line for line in t["guide"]["evidence"])
    assert t["guide"]["sources"] and t["guide"]["checks"]


def test_lines_follow_the_capture():
    base = dict(cause="service", cause_share=0.9, service=2.0, answered=True, wait=2.0)
    near_server = knowledge.guide("service", causes.facts(base, dict(capture_point="near_server")))
    near_client = knowledge.guide("service", causes.facts(base, dict(capture_point="near_client")))
    assert near_server["evidence"] != near_client["evidence"]
    assert any("NetScaler" in line for line in near_client["evidence"])
    gap = causes.facts(dict(base, server_reported=0.5), dict(capture_point="near_server"))
    assert any("1.50 s" in line for line in knowledge.guide("service", gap)["evidence"])


@pytest.mark.parametrize("lang,label,text", [("de", "Verbindung zurückgesetzt", "Keine Antwort: der Server hat"), ("es", "Conexión reiniciada", "Sin respuesta: el servidor reinició")])
def test_other_languages(a, monkeypatch, lang, label, text):
    monkeypatch.setenv("PCAP_ANALYZER_LANGUAGE", lang)
    with a.connect() as db:
        t = _reset_request(db)
        guide = reports.transaction(db, t["id"])["guide"]
    assert t["cause_label"] == label and t["explanation"].startswith(text)
    assert guide["meaning"] and guide["checks"] and guide["evidence"]


def test_turkish_text(a, monkeypatch):
    monkeypatch.setenv("PCAP_ANALYZER_LANGUAGE", "tr")
    with a.connect() as db:
        t = _reset_request(db)
        titles = {i["key"]: i["title"] for i in reports.issues(db, a.meta)}
    assert t["cause_label"] == "Bağlantı sıfırlandı"
    assert t["explanation"].startswith("Cevap yok: sunucu, istekten")
    assert titles["resets"] == "Sıfırlanan bağlantılar"
    assert "(%100)" in knowledge.summary("service", dict(pct="100", service=2.0))


def test_other_knowledge_file(tmp_path, monkeypatch):
    data = knowledge.unpack(knowledge.BUNDLED.read_bytes())
    data["topics"]["normal"]["label"]["en"] = "Fine"
    path = tmp_path / "team.bin"
    path.write_bytes(knowledge.pack(data))
    monkeypatch.setenv("PCAP_ANALYZER_KNOWLEDGE", str(path))
    assert knowledge.label("normal") == "Fine"
