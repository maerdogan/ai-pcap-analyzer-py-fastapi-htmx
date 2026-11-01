import pytest

from pcap_analyzer import engine, reports
from pcap_analyzer.reports import Inspect


@pytest.fixture
def a(samples, settings):
    return engine.analyze(samples / "http_scenarios.pcap", settings=settings)


def test_overview(a):
    with a.connect() as db:
        o = reports.overview(db, a.meta)
    assert o["http"]["requests"] == 18 and o["tcp"]["connections"] == 12
    assert {s["class"] for s in o["statuses"]} >= {"2xx", "4xx", "5xx", "none"}
    assert o["http"]["failed"] == 5


def test_url_groups(a):
    with a.connect() as db:
        g = {(x["method"], x["url"]): x for x in reports.url_groups(db)}
    users = g[("GET", "/api/users/{id}")]
    assert users["requests"] == 2 and users["avg_total"] == pytest.approx(0.055, abs=0.002)
    pay = g[("GET", "/api/pay")]
    assert [s["status"] for s in pay["statuses"]] == [502, 503, 504]


def test_connection_list_and_top(a):
    with a.connect() as db:
        c = reports.connections(db)
        assert len(c) == 12 and next(x for x in c if x["stream"] == 0)["requests"] == 4
        top = reports.connection_top(db, 0)
        assert top["total"] == 4 and len(top["top"]) == 4
        assert top["top"][0]["uri"] == "/api/orders"
        assert len(reports.connection_top(db, 0, percent=True)["top"]) == 1


def test_tcp_summary(a):
    with a.connect() as db:
        c = reports.connection_top(db, 2)["conn"]
    assert c["sack"] is True and c["retransmissions"] == 2 and c["byte_ratio_db"] > 30


def test_hosts(a, samples, settings):
    with a.connect() as db:
        h = reports.hosts(db)
    assert h[0]["host"] == "app.example.test" and h[0]["requests"] == 18
    tls = engine.analyze(samples / "https_tls13.pcap", settings=settings)
    with tls.connect() as db:
        assert reports.hosts(db)[0]["host"] == "app.example.test"


def test_inspect_pair(a):
    with a.connect() as db:
        r = reports.inspect(db, Inspect(src="10.10.1.50", dst="10.20.2.10", port=8080))
    assert r["requests"]["requests"] == 18 and r["connections"]["connections"] == 12
    assert r["connections"]["http"] == 12 and r["connections"]["ok"] == 10
    assert len(r["slowest"]) == 10
    assert r["slowest"][0]["uri"] == "/api/pay" and r["slowest"][0]["status"] == 504
    assert r["slowest"][0]["explanation"].startswith("HTTP 504")


def test_inspect_no_match(a):
    with a.connect() as db:
        r = reports.inspect(db, Inspect(src="1.2.3.4"))
    assert r["requests"]["requests"] == 0 and r["slowest"] == [] and r["urls"] == []


def test_inspect_url_and_size(a):
    with a.connect() as db:
        assert reports.inspect(db, Inspect(url="/FILES/"))["requests"]["requests"] == 4
        big = reports.inspect(db, Inspect(min_size=150000, size_of="response"))
        assert [t["uri"] for t in big["slowest"]] == ["/files/large.bin"]
        assert reports.inspect(db, Inspect(min_size=15000, size_of="request"))["requests"]["requests"] == 1
        assert reports.inspect(db, Inspect(min_size=1000, size_of="packet"))["requests"]["requests"] > 0


def test_inspect_is_parameterized(a):
    with a.connect() as db:
        assert reports.inspect(db, Inspect(url="' OR 1=1 --"))["requests"]["requests"] == 0


def test_bad_size_type(a):
    with a.connect() as db, pytest.raises(ValueError):
        reports.inspect(db, Inspect(min_size=1, size_of="x"))


def test_issues(a):
    with a.connect() as db:
        keys = {i["key"]: i["count"] for i in reports.issues(db, a.meta)}
    assert keys["no_response"] == 1 and keys["resets"] == 2 and keys["truncated"] == 1 and keys["gateway"] == 3
    assert keys["delayed_ack"] == 1 and keys["queueing"] == 1 and keys["small_mss"] == 1 and keys["slow_dns"] == 1


def test_histogram(a):
    with a.connect() as db:
        h = reports.histogram(db)
    assert sum(b["requests"] for b in h) == 17


def test_transaction_detail(a):
    with a.connect() as db:
        tid = reports.rows(db, "SELECT id FROM http_transactions WHERE uri='/api/users/123'")[0]["id"]
        t = reports.transaction(db, tid)
    assert "Host: app.example.test" in t["req_headers"] and '{"id":123}' in t["resp_body"]
    assert t["conn"]["stream"] == 0 and any(p["name"] == "connect_time" for p in t["phases"])
    assert reports.transaction  # silence linters when run alone
