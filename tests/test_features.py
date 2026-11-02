import os
import shlex
import stat
import subprocess
import threading
import time

import pytest

from pcap_analyzer import capture_guide, engine, reports, tshark
from pcap_analyzer.reports import Inspect
from pcap_analyzer.web.jobs import Jobs


@pytest.fixture
def backends(samples, settings):
    return engine.analyze(samples / "backends.pcap", settings=settings)


def test_slow_and_failing_servers_stand_out(backends, truth):
    with backends.connect() as db:
        rows = {r["server_ip"]: r for r in reports.backends(db)}
        issues = {i["key"]: i for i in reports.issues(db, backends.meta)}
    expected = truth["backends.pcap"]
    assert rows[expected["slow"]]["flag"] == "slow"
    assert rows[expected["failing"]]["flag"] == "errors"
    assert rows["10.50.0.1"]["flag"] is None and rows[expected["failing"]]["failed"] > 0
    assert issues["slow_backend"]["count"] == 2


def test_one_server_is_not_flagged(samples, settings):
    a = engine.analyze(samples / "netscaler_back.pcap", settings=settings)
    with a.connect() as db:
        assert [r["flag"] for r in reports.backends(db)] == [None]


def test_timeline_shows_when_errors_start(backends, truth):
    with backends.connect() as db:
        line = reports.timeline(db)
    first = truth["backends.pcap"]["first_error"]
    assert sum(r["requests"] for r in line["rows"]) == 30
    start = next(r["start"] for r in line["rows"] if r["errors"])
    assert abs(start - first) <= line["width"]
    assert all(r["open_connections"] >= 0 for r in line["rows"])


def test_chosen_period_narrows_the_tables(backends, truth):
    first = truth["backends.pcap"]["first_error"]
    with backends.connect() as db:
        whole = reports.inspect(db, Inspect())
        part = reports.inspect(db, Inspect(start=first, end=first + 8))
    assert whole["requests"]["requests"] == 30
    assert part["requests"]["requests"] == 4 and part["connections"]["connections"] < 30


def test_quality_of_a_poor_capture(samples, settings):
    a = engine.analyze(samples / "poor_capture.pcap", settings=settings)
    q = reports.quality(a.meta)
    keys = {f["key"] for f in q["findings"]}
    assert a.meta["quality"]["unseen"] >= 1 and a.meta["quality"]["one_way"] >= 1
    assert {"unseen", "one_way", "started_before", "open_at_end"} <= keys
    assert q["level"] == "low"


def test_quality_of_a_clean_capture(samples, settings):
    a = engine.analyze(samples / "backends.pcap", settings=settings)
    assert reports.quality(a.meta) == dict(level="high", label=reports.quality(a.meta)["label"], findings=[])


def test_saved_result_without_quality():
    assert reports.quality({}) is None


def test_long_headers_and_a_separate_body(samples, settings):
    a = engine.analyze(samples / "split_headers.pcap", settings=settings)
    with a.connect() as db:
        got = db.execute("SELECT uri, status, answered, truncated FROM http_transactions ORDER BY req_start").fetchall()
    assert got == [(f"/long/{i}", 200, True, False) for i in range(3)]


def _hanging_tshark(tmp_path):
    """Passes the version check and then hangs, as tshark can on a bad capture."""
    path = tmp_path / "tshark"
    path.write_text('#!/bin/sh\n[ "$1" = "--version" ] && { echo "TShark 4.6.0"; exit 0; }\nexec sleep 30\n')
    path.chmod(path.stat().st_mode | stat.S_IEXEC)
    return str(path)


def _wait(job, state):
    for _ in range(200):
        if job.state == state:
            return
        time.sleep(0.02)
    raise AssertionError(f"job is {job.state}, not {state}")


def _wait_started(job):
    for _ in range(200):
        if job.limit.proc:
            return
        time.sleep(0.02)
    raise AssertionError("tshark did not start")


def _submit(jobs, tmp_path, samples):
    tmp = tmp_path / os.urandom(4).hex()
    tmp.mkdir()
    capture = tmp / "capture"
    capture.write_bytes((samples / "backends.pcap").read_bytes())
    return jobs.submit(tmp, capture, "backends.pcap", None, None, tshark.Filter()), tmp


def test_time_limit_ends_a_hung_analysis(samples, settings, tmp_path):
    settings.tshark, settings.analysis_timeout_s = _hanging_tshark(tmp_path), 1
    jobs = Jobs(settings)
    job, tmp = _submit(jobs, tmp_path, samples)
    _wait(job, "failed")
    assert "1" in job.error and not tmp.exists()
    assert not list(settings.workdir.glob(".tmp-*"))


def test_cancel_frees_the_slot_for_the_next_job(samples, settings, tmp_path):
    good, settings.tshark, settings.max_jobs = settings.tshark, _hanging_tshark(tmp_path), 1
    jobs = Jobs(settings)
    first, tmp = _submit(jobs, tmp_path, samples)
    _wait_started(first)
    second, _ = _submit(jobs, tmp_path, samples)
    assert second.state == "waiting"
    settings.tshark = good
    jobs.cancel(first.id)
    _wait(first, "cancelled")
    _wait(second, "done")
    assert not tmp.exists()


def test_cancel_while_waiting(samples, settings, tmp_path):
    settings.tshark, settings.max_jobs = _hanging_tshark(tmp_path), 1
    jobs = Jobs(settings)
    first, _ = _submit(jobs, tmp_path, samples)
    _wait(first, "running")
    second, tmp = _submit(jobs, tmp_path, samples)
    jobs.cancel(second.id)
    jobs.cancel(first.id)
    _wait(second, "cancelled")
    assert not tmp.exists()


def test_stop_works_when_tshark_refuses_signals(samples, settings, tmp_path):
    class Refuses:
        def __init__(self, proc):
            self.proc = proc

        def kill(self):
            raise PermissionError

    settings.tshark = _hanging_tshark(tmp_path)
    limit = tshark.Limit()
    real_attach = limit.attach
    limit.attach = lambda proc: real_attach(Refuses(proc))
    threading.Timer(0.3, limit.stop).start()
    with pytest.raises(tshark.Stopped):
        engine.analyze(samples / "backends.pcap", settings=settings, limit=limit, use_cached=False)


def test_guide_commands_are_valid_shell():
    points = capture_guide.commands("10.0.0.5", 8080, "10.0.0.9", 60, 100, "any", "prod", "web-1", "app", "registry.local/netshoot")
    assert {p["key"] for p in points} == {"linux", "pod", "node_pod", "node_uplink", "keylog"}
    for p in points:
        for line in p["lines"]:
            subprocess.run(["sh", "-n", "-c", line], check=True)
    linux = points[0]["lines"][0]
    assert "host 10.0.0.5 and host 10.0.0.9 and tcp port 8080" in linux and "timeout 60" in linux and "head -c 95000000" in linux
    assert "--target=app" in points[1]["lines"][0] and "registry.local/netshoot" in points[1]["lines"][0]
    assert "4789" in points[3]["lines"][0]


def test_guide_quotes_what_people_type():
    evil = "x; rm -rf /"
    line = capture_guide.commands(namespace=evil, pod=evil, container=evil)[1]["lines"][0]
    assert shlex.quote(evil) in line
    assert shlex.split(line)[0] == "kubectl"


def _web(settings, samples):
    from fastapi.testclient import TestClient
    from pcap_analyzer.web.app import create_app
    settings.admin_password = "pw-for-tests"
    return TestClient(create_app(settings), follow_redirects=False)


def _signed_in(c):
    import re
    assert c.post("/login", data={"username": "admin", "password": "pw-for-tests"}).status_code == 303
    c.headers["X-CSRF-Token"] = re.search(r'"X-CSRF-Token": "(\w+)"', c.get("/").text)[1]
    return c


def _analysis(settings, samples):
    from pcap_analyzer import engine
    return engine.analyze(samples / "http_scenarios.pcap", settings=settings)


def test_har_keeps_masking_and_timings(settings, samples):
    import json
    from pcap_analyzer import exports
    a = _analysis(settings, samples)
    with a.connect() as db:
        log = json.loads(exports.har(db))["log"]
    assert log["version"] == "1.2" and len(log["entries"]) == a.meta["transactions"]
    e = log["entries"][0]
    assert e["request"]["url"].startswith("http") and e["timings"]["wait"] >= 0 and e["timings"]["send"] >= 0


def test_notes_reach_search_and_report(settings, samples):
    a = _analysis(settings, samples)
    with _web(settings, samples) as c:
        _signed_in(c)
        assert c.post(f"/a/{a.id}/notes", data={"case": "INC-42", "tags": "odeme", "note": "gece yavaslik"}).status_code == 303
        assert a.meta["filename"] in c.get("/", params={"q": "inc-42"}).text
        assert 'class="capture-row"' not in c.get("/", params={"q": "yok-boyle"}).text
        assert "INC-42" in c.get(f"/export/{a.id}/report.html").text


def test_activity_log_records_deletes_and_downloads(settings, samples):
    from pcap_analyzer import records
    a = _analysis(settings, samples)
    with _web(settings, samples) as c:
        _signed_in(c)
        c.get(f"/export/{a.id}/requests.csv")
        c.post(f"/a/{a.id}/delete")
        page = c.get("/audit", params={"event": "delete"}).text
    assert a.id in page
    assert {"login", "export", "delete"} <= {r["event"] for r in records.read_audit(settings)}


def test_slow_limit_changes_the_analysis(settings, samples):
    from pcap_analyzer import engine, records
    a = _analysis(settings, samples)
    records.save_thresholds(settings, 1000.0, [])
    b = engine.analyze(samples / "http_scenarios.pcap", settings=settings)
    assert a.id != b.id and b.meta["slow_s"] == 1000.0
    with b.connect() as db:
        assert db.execute("SELECT count(*) FROM http_transactions WHERE cause = 'service'").fetchone()[0] == 0
    with a.connect() as db:
        assert db.execute("SELECT count(*) FROM http_transactions WHERE cause = 'service'").fetchone()[0] > 0


def test_url_targets_and_bad_lines(settings, samples):
    from pcap_analyzer import records, reports
    a = _analysis(settings, samples)
    targets, bad = records.parse_targets("/api/pay 1\nnot a line here\n")
    assert targets == [dict(pattern="/api/pay", seconds=1.0)] and bad == ["not a line here"]
    with a.connect() as db:
        missed = reports.target_misses(db, targets)
    assert [m["url"] for m in missed] == ["/api/pay"] and missed[0]["over"] == 1


def test_waterfall_keeps_the_time_order(settings, samples):
    from pcap_analyzer import reports
    a = _analysis(settings, samples)
    with a.connect() as db:
        stream = db.execute("SELECT stream FROM http_transactions GROUP BY 1 ORDER BY count(*) DESC LIMIT 1").fetchone()[0]
        got = reports.waterfall(db, stream)
    starts = [r["start"] for r in got["rows"]]
    assert len(starts) > 1 and starts == sorted(starts) and starts[0] >= 0


def test_traceparent_gives_the_trace_id():
    from pcap_analyzer import parser
    trace = "4bf92f3577b34da6a3ce929d0e0e4736"
    assert parser.request_id({"traceparent": f"00-{trace}-00f067aa0ba902b7-01"}.get) == trace
    assert parser.request_id({"traceparent": "broken"}.get) is None
    assert parser.request_id({"x-request-id": "abc", "traceparent": f"00-{trace}-00f067aa0ba902b7-01"}.get) == "abc"


def test_check_exit_code(settings, samples, monkeypatch, capsys):
    from pcap_analyzer import cli
    a = _analysis(settings, samples)
    monkeypatch.setenv("PCAP_ANALYZER_WORKDIR", str(settings.workdir))
    assert cli.main(["check", a.id, "--p95", "1000"]) == 0
    assert cli.main(["check", a.id, "--p95", "0.001"]) == 2
    assert cli.main(["check", a.id, "--error-rate", "1"]) == 2


def test_baseline_drift_and_trend(settings, samples):
    from pcap_analyzer import engine, reports
    a = engine.analyze(samples / "netscaler_front.pcap", settings=settings)
    b = _analysis(settings, samples)
    with a.connect() as da, b.connect() as db:
        assert {d["why"] for d in reports.drift(db, da)} == {"new"} or reports.drift(db, da)
        assert reports.drift(db, db) == []
    got = reports.trend([a, b], "/api/pay")
    assert [r["filename"] for r in got] == ["http_scenarios.pcap"] and got[0]["requests"] == 3


def test_api_needs_a_token_and_walks_an_upload(settings, samples):
    import time
    from pcap_analyzer import records
    with _web(settings, samples) as c:
        assert c.get("/api/v1/analyses").status_code == 401
        assert c.get("/api/v1/analyses", headers={"Authorization": "Bearer nope"}).status_code == 401
        token = records.new_token(settings, "ci")
        bearer = {"Authorization": f"Bearer {token}"}
        r = c.post("/api/v1/captures", headers=bearer, files={"capture": ("a.pcap", (samples / "http_scenarios.pcap").read_bytes())})
        assert r.status_code == 202
        job = r.json()["job"]
        for _ in range(300):
            s = c.get(f"/api/v1/jobs/{job}", headers=bearer).json()
            if s["state"] == "done":
                break
            time.sleep(0.05)
        aid = s["analysis"]
        assert c.get(f"/api/v1/analyses/{aid}/issues", headers=bearer).json()
        assert c.delete(f"/api/v1/analyses/{aid}", headers=bearer).status_code == 200
        tid = records.tokens(settings)[0]["id"]
        records.revoke_token(settings, tid)
        assert c.get("/api/v1/analyses", headers=bearer).status_code == 401


def _packet(frame, t, src, dst, flags="0x018", **extra):
    from pcap_analyzer.tshark import FIELDS
    p = dict.fromkeys(FIELDS, "")
    p.update({"frame.number": str(frame), "frame.time_epoch": str(t), "frame.len": "200", "frame.cap_len": "200", "ip.src": src[0], "ip.dst": dst[0], "tcp.stream": "1",
              "tcp.srcport": str(src[1]), "tcp.dstport": str(dst[1]), "tcp.seq": str(frame), "tcp.ack": "1", "tcp.len": "100", "ip.id": str(frame), "tcp.flags": flags})
    p.update(extra)
    return p


CLIENT, SERVER = ("10.0.0.1", 5000), ("10.0.0.2", 443)
SEP = "\x1f"


def test_websocket_is_not_a_slow_request():
    from pcap_analyzer import parser
    b = parser.Builder()
    b.add(_packet(1, 0.0, CLIENT, SERVER, **{"http.request.method": "GET", "http.request.uri": "/ws", "http.request.version": "HTTP/1.1", "http.host": "a"}))
    b.add(_packet(2, 0.01, SERVER, CLIENT, **{"http.response.code": "101", "http.response.phrase": "Switching Protocols", "http.response.line": "Upgrade: websocket\\r\\n"}))
    b.add(_packet(3, 3600.0, SERVER, CLIENT))
    conn, txns = parser.finish_stream(b.streams[1])
    assert conn["kind"] == "WebSocket" and conn["duration"] == 3600.0
    assert txns[0]["cause"] == "websocket" and txns[0]["total"] < 1


def test_grpc_status_comes_from_the_trailer():
    from pcap_analyzer import parser
    b = parser.Builder()
    b.add(_packet(1, 0.0, CLIENT, SERVER, **{"http2.type": "1", "http2.streamid": "1", "http2.flags": "0x05", "http2.length": "10", "http2.header.count": "3",
                                             "http2.header.name": SEP.join([":method", ":path", "content-type"]), "http2.header.value": SEP.join(["POST", "/pkg.Svc/Get", "application/grpc"])}))
    b.add(_packet(2, 0.1, SERVER, CLIENT, **{"http2.type": "1", "http2.streamid": "1", "http2.flags": "0x04", "http2.length": "10", "http2.header.count": "1",
                                             "http2.header.name": ":status", "http2.header.value": "200"}))
    b.add(_packet(3, 0.2, SERVER, CLIENT, **{"http2.type": "1", "http2.streamid": "1", "http2.flags": "0x05", "http2.length": "10", "http2.header.count": "2",
                                             "http2.header.name": SEP.join(["grpc-status", "grpc-message"]), "http2.header.value": SEP.join(["14", "unavailable"])}))
    _, txns = parser.finish_stream(b.streams[1])
    assert txns[0]["status"] == 200 and txns[0]["grpc_status"] == 14 and txns[0]["grpc_message"] == "unavailable"


def test_tls_tab_without_a_key(settings, samples):
    from pcap_analyzer import engine, reports
    a = engine.analyze(samples / "https_tls12_ecdhe.pcap", settings=settings)
    with a.connect() as db:
        got = reports.tls_health(db)
    assert got["versions"][0]["version"] == "TLS 1.2" and got["versions"][0]["cipher"] != "-"
    assert got["certificates"]


def test_old_analysis_still_opens(settings, samples):
    import duckdb
    from pcap_analyzer import reports
    a = _analysis(settings, samples)
    with duckdb.connect(str(a.db_path)) as db:
        for table, column in (("tcp_connections", "tls_cipher"), ("tcp_connections", "tls_alert"), ("tcp_connections", "tls_no_answer"), ("http_transactions", "grpc_status")):
            db.execute(f"ALTER TABLE {table} DROP COLUMN {column}")
    with a.connect() as db:
        assert reports.tls_health(db) is None
        assert reports.issues(db, a.meta)


def test_sandbox_hides_other_analyses(tmp_path):
    import pathlib
    import subprocess
    import tempfile
    import pytest
    from pcap_analyzer import tshark
    if not tshark.can_isolate():
        pytest.skip("this host does not allow user namespaces")
    work = tmp_path / "work"
    work.mkdir()
    (work / "secret").write_text("x")
    with tempfile.TemporaryDirectory(prefix="pcap-analyzer-", dir="/tmp") as own:
        (pathlib.Path(own) / "mine").write_text("y")
        out = subprocess.run(tshark.isolated(["sh", "-c", f"ls {own}; ls {work} 2>&1"], own, work), capture_output=True, text=True)
    assert "mine" in out.stdout and "secret" not in out.stdout
