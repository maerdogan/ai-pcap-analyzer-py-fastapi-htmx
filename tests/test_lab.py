"""Real Linux traffic with known delays, from tools/lab.py. Skipped where namespaces are not allowed."""
import json
import statistics
import subprocess
import sys
from pathlib import Path

import pytest

from pcap_analyzer import compare, engine, reports

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="session")
def lab(tmp_path_factory):
    out = tmp_path_factory.mktemp("lab")
    done = subprocess.run([sys.executable, ROOT / "tools/lab.py", out], capture_output=True, text=True)
    if done.returncode == 3:
        pytest.skip("network namespaces or tcpdump are not available here")
    assert done.returncode == 0, done.stderr
    return out


@pytest.fixture(scope="session")
def truth(lab):
    return json.loads((lab / "truth.json").read_text())


@pytest.fixture(scope="session")
def analyzed(lab, tmp_path_factory):
    from pcap_analyzer.config import Settings
    settings = Settings(workdir=tmp_path_factory.mktemp("work"))
    return lambda name: engine.analyze(lab / f"{name}.pcap", settings=settings)


def _column(a, sql):
    with a.connect() as db:
        return db.execute(sql).fetchall()


def _tshark_count(path, expr):
    out = subprocess.run(["tshark", "-r", str(path), "-Y", expr, "-T", "fields", "-e", "frame.number"], capture_output=True, text=True, check=True)
    return out.stdout.count("\n")


@pytest.mark.parametrize("name", ["back_id", "back_noid"])
def test_service_time_is_the_real_delay(analyzed, truth, name):
    a = analyzed(name)
    assert a.meta["transactions"] == 18
    for ms in truth["service_delays_ms"]:
        rows = _column(a, f"SELECT service FROM http_transactions WHERE uri LIKE '/api/wait/{ms}?%'")
        assert len(rows) == 5
        assert statistics.median(r[0] for r in rows) == pytest.approx(ms / 1000, abs=0.006)


@pytest.mark.parametrize("name", ["id", "noid"])
def test_total_matches_what_the_client_measured(analyzed, truth, name):
    got = _column(analyzed(f"front_{name}"), "SELECT total FROM http_transactions ORDER BY req_start")
    measured = truth[f"two_sides_{name}"]
    assert len(got) == len(measured)
    late = truth["link_delay_ms"] / 1000  # tcpdump sees a packet after the link delay, the client program before it
    for (total,), m in list(zip(got, measured))[1:]:  # the client's first timing also holds the TCP handshake
        assert total == pytest.approx(m["seconds"] - late, abs=0.004)


@pytest.mark.parametrize("name,exact,likely", [("id", 18, 0), ("noid", 0, 18)])
def test_added_time_of_the_proxy(analyzed, truth, name, exact, likely):
    with analyzed(f"front_{name}").connect() as a, analyzed(f"back_{name}").connect() as b:
        p = compare.two_point(a, b)
    assert (p["exact"], p["likely"], p["unmatched_a"], p["unmatched_b"]) == (exact, likely, 0, 0)
    delay = 2 * (truth["proxy_delay_s"] + truth["link_delay_ms"] / 1000)
    assert statistics.median(r["added"] for r in p["rows"]) == pytest.approx(delay, abs=0.04)


@pytest.mark.parametrize("name", ["id", "noid"])
def test_both_directions_are_split_evenly(analyzed, truth, name):
    with analyzed(f"front_{name}").connect() as a, analyzed(f"back_{name}").connect() as b:
        rows = compare.two_point(a, b)["rows"]
    one_way = truth["proxy_delay_s"] + truth["link_delay_ms"] / 1000
    assert statistics.median(r["forward"] for r in rows) == pytest.approx(one_way, abs=0.02)
    assert statistics.median(r["back"] for r in rows if r["back"] is not None) == pytest.approx(one_way, abs=0.02)


def test_real_capture_is_trusted(analyzed):
    a = analyzed("back_id")
    assert reports.quality(a.meta)["level"] == "high"


@pytest.mark.parametrize("kind", ["vxlan", "geneve"])
@pytest.mark.parametrize("capture", ["node", "uplink"])
def test_tunnels_show_pod_addresses(analyzed, kind, capture):
    a = analyzed(f"{capture}_{kind}")
    assert a.meta["transactions"] == 6 and "tunnel_seen" in a.meta["warnings"]
    assert _column(a, "SELECT DISTINCT client_ip, server_ip FROM tcp_connections") == [("10.244.1.1", "10.244.1.2")]
    assert _column(a, "SELECT sum(retrans_count) FROM http_transactions") == [(0,)]
    assert statistics.median(r[0] for r in _column(a, "SELECT service FROM http_transactions")) == pytest.approx(0.15, abs=0.02)


@pytest.mark.parametrize("kind", ["vxlan", "geneve"])
def test_any_interface_copies_are_not_retransmissions(lab, analyzed, kind):
    a = analyzed(f"node_{kind}")
    assert a.meta["copies"] > 0 and "copies_removed" in a.meta["warnings"]
    assert _tshark_count(lab / f"node_{kind}.pcap", "tcp.analysis.retransmission") > 0


def test_real_loss_is_counted_like_wireshark(lab, analyzed):
    a = analyzed("pod")
    assert a.meta["transactions"] == 6
    seen = _tshark_count(lab / "pod.pcap", "tcp.analysis.retransmission or tcp.analysis.fast_retransmission")
    assert seen > 0 and _column(a, "SELECT sum(retransmissions) FROM tcp_connections") == [(seen,)]
    assert _column(a, "SELECT count(*) FROM http_transactions WHERE retrans_count > 0")[0][0] > 0
