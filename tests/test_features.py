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
