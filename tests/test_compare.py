import pytest

from pcap_analyzer import compare, engine, exports, reports
from pcap_analyzer.reports import Inspect


@pytest.fixture
def ns(samples, settings):
    return (engine.analyze(samples / "netscaler_front.pcap", keylog=samples / "netscaler_front.keylog", settings=settings),
            engine.analyze(samples / "netscaler_back.pcap", settings=settings))


def test_two_point_matching(ns):
    f, b = ns
    with f.connect() as da, b.connect() as db:
        r = compare.two_point(da, db)
    assert (r["exact"], r["likely"], r["unmatched_a"], r["unmatched_b"]) == (2, 2, 0, 0)
    assert r["clock_known"] and abs(r["clock_offset"]) < 1
    top = r["rows"][0]
    assert top["uri"] == "/api/b/3" and top["match"] == "likely" and top["added"] == pytest.approx(0.8, abs=0.06)


def test_clock_offset_from_exact_matches():
    a = [dict(req_start=100.0), dict(req_start=200.0)]
    b = [dict(req_start=97.0), dict(req_start=197.0)]
    assert compare._clock_offset(list(zip(a, b))) == 3.0
    assert compare._clock_offset([]) == 0.0


def test_compare_captures(samples, settings):
    a = engine.analyze(samples / "http_scenarios.pcap", settings=settings)
    b = engine.analyze(samples / "netscaler_back.pcap", settings=settings)
    with a.connect() as da, b.connect() as db:
        r = compare.captures(da, db, Inspect(), Inspect())
    rows = {s["key"]: s for s in r["summary"]}
    assert rows["requests"]["a"] == 18 and rows["requests"]["b"] == 4 and rows["requests"]["delta"] == -14
    assert any(u["only_in"] == "A" for u in r["urls"]) and any(u["only_in"] == "B" for u in r["urls"])
    assert any("fewer than" in n for n in r["notes"])
    assert len(r["phases"]) == len(compare.PHASE_AVG)


def test_compare_same_capture_has_no_change(samples, settings):
    a = engine.analyze(samples / "http_scenarios.pcap", settings=settings)
    with a.connect() as da, a.connect() as db:
        r = compare.captures(da, db, Inspect(), Inspect())
    assert all(not u["delta"] for u in r["urls"] if u["delta"] is not None)


def test_exports(samples, settings):
    a = engine.analyze(samples / "http_scenarios.pcap", settings=settings)
    with a.connect() as db:
        for name in exports.TABLES:
            rows = exports.table(db, name, a.meta)
            assert rows and exports.render(rows, "csv") and exports.render(rows, "xlsx")[:2] == b"PK" and exports.render(rows, "json")
        cols = list(exports.table(db, "requests", a.meta)[0])
    assert "req_headers" not in cols and "resp_body" not in cols


def test_csv_blocks_formulas():
    out = exports.render([dict(u="=HYPERLINK(1)", v=1)], "csv").decode()
    assert "'=HYPERLINK" in out
