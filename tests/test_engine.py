import gzip
import os
import shutil
import time

import pytest

from pcap_analyzer import engine, parser, tshark

Filter = tshark.Filter


def txns(a, where="true"):
    with a.connect() as db:
        cur = db.execute(f"select * from http_transactions where {where} order by req_start, id")
        cols = [c[0] for c in cur.description]
        return [dict(zip(cols, r)) for r in cur.fetchall()]


def conns(a):
    with a.connect() as db:
        cur = db.execute("select * from tcp_connections order by stream")
        cols = [c[0] for c in cur.description]
        return [dict(zip(cols, r)) for r in cur.fetchall()]


def by_uri(a):
    return {t["uri"]: t for t in txns(a)}


@pytest.fixture
def http(samples, settings):
    return engine.analyze(samples / "http_scenarios.pcap", settings=settings)


def test_http_counts(http):
    assert http.meta["connections"] == 12
    assert http.meta["transactions"] == 18


def test_slow_service(http):
    t = by_uri(http)["/api/reports/2024"]
    assert t["wait"] == pytest.approx(2.5, abs=0.001)
    assert t["service"] == pytest.approx(2.498, abs=0.001)


def test_transfer_is_separate_from_wait(http):
    t = by_uri(http)["/files/large.bin"]
    assert t["wait"] == pytest.approx(0.05, abs=0.001)
    assert t["total"] == pytest.approx(0.877, abs=0.002)


def test_split_request_starts_at_first_segment(http):
    t = by_uri(http)["/api/nagle"]
    assert t["request_send"] == pytest.approx(0.201, abs=0.001)
    assert t["total"] == pytest.approx(0.25, abs=0.001)


def test_pipelining_pairs_in_order(http):
    q = by_uri(http)
    assert q["/api/first"]["wait"] == pytest.approx(1.01, abs=0.002)
    assert q["/api/first"]["resp_frame"] < q["/api/second"]["resp_frame"]


def test_unanswered_request(http):
    t = by_uri(http)["/api/slow"]
    assert t["answered"] is False and t["status"] is None
    c = conns(http)[t["stream"]]
    assert (c["close_type"], c["closed_by"]) == ("RST", "server")


def test_truncated_response_is_visible(http):
    t = by_uri(http)["/files/cut.bin"]
    assert t["status"] == 200 and t["resp_content_length"] == 10000 and t["resp_bytes"] < 10000


def test_gateway_statuses(http):
    assert [t["status"] for t in txns(http, "uri='/api/pay'")] == [502, 503, 504]


def test_connection_reuse(http):
    rows = txns(http, "stream=0")
    assert [t["new_conn"] for t in rows] == [True, False, False, False]
    assert rows[0]["connect_time"] == pytest.approx(0.003, abs=0.0001) and rows[1]["connect_time"] is None


def test_server_timing_and_encoding(http):
    t = by_uri(http)["/api/items"]
    assert t["server_timing"] == "app;dur=120.5"
    assert (t["content_encoding"], t["transfer_encoding"]) == ("gzip", "chunked")


def test_tcp_events(http):
    with http.connect() as db:
        ev = dict(db.execute("select event, count(*) from tcp_events group by 1").fetchall())
        dns = db.execute("select name, duration from dns_queries").fetchall()
    assert ev["retransmission"] == 2 and ev["zero_window"] == 1
    assert dns == [("app.example.test", pytest.approx(0.12, abs=0.001))]


def test_small_mss(http):
    assert conns(http)[by_uri(http)["/files/mss.bin"]["stream"]]["mss"] == 536


def test_high_rtt_goes_to_network_not_service(http):
    t = by_uri(http)["/api/far"]
    c = conns(http)[t["stream"]]
    assert c["rtt_server"] == pytest.approx(0.3, abs=0.001)
    assert c["capture_point"] == "near_client"
    assert t["service"] == pytest.approx(0.01, abs=0.001)


@pytest.mark.parametrize("name", ["https_tls13", "https_tls12_ecdhe"])
def test_keylog_decrypts(samples, settings, truth, name):
    a = engine.analyze(samples / f"{name}.pcap", keylog=samples / f"{name}.keylog", settings=settings)
    assert a.meta["warnings"] == []
    got = by_uri(a)
    for e in truth[f"{name}.pcap"]["txns"]:
        assert got[e["uri"]]["status"] == e["status"]
        assert got[e["uri"]]["wait"] == pytest.approx(e["service"], abs=0.001)
        assert got[e["uri"]]["tls_time"] > 0


def test_tls_version(samples, settings):
    a = engine.analyze(samples / "https_tls13.pcap", keylog=samples / "https_tls13.keylog", settings=settings)
    c = conns(a)[0]
    assert (c["tls_version"], c["sni"], c["kind"]) == ("TLS 1.3", "app.example.test", "HTTPS")


def test_rsa_key_decrypts(samples, settings):
    a = engine.analyze(samples / "https_tls12_rsa.pcap", rsa_key=samples / "test_key.pem", settings=settings)
    assert len(txns(a)) == 3


def test_tls_without_key_warns(samples, settings):
    a = engine.analyze(samples / "https_tls13.pcap", settings=settings)
    assert a.meta["transactions"] == 0 and a.meta["warnings"] == ["tls_not_decrypted"]
    assert conns(a)[0]["sni"] == "app.example.test"


def test_wrong_key_warns(samples, settings):
    a = engine.analyze(samples / "https_tls13.pcap", keylog=samples / "https_h2.keylog", settings=settings)
    assert a.meta["warnings"] == ["tls_key_did_not_decrypt"]


def test_http2_streams(samples, settings, truth):
    a = engine.analyze(samples / "https_h2.pcap", keylog=samples / "https_h2.keylog", settings=settings)
    got = by_uri(a)
    assert len(got) == 3
    for e in truth["https_h2.pcap"]["streams"]:
        t = got[e["uri"]]
        assert (t["h2_stream"], t["status"], t["http_version"]) == (e["stream"], 200, "HTTP/2")
        assert t["ttfb"] == pytest.approx(e["ttfb"], abs=0.01)
    assert conns(a)[0]["kind"] == "HTTPS/2"


def test_netscaler_sides(samples, settings, truth):
    f = engine.analyze(samples / "netscaler_front.pcap", keylog=samples / "netscaler_front.keylog", settings=settings)
    b = engine.analyze(samples / "netscaler_back.pcap", settings=settings)
    front, back = by_uri(f), by_uri(b)
    assert b.meta["connections"] == 1 and len(back) == 4
    for e in truth["netscaler_front.pcap+netscaler_back.pcap"]:
        assert back[e["uri"]]["x_forwarded_for"] == e["client"]
        assert back[e["uri"]]["request_id"] == e["request_id"]
        assert front[e["uri"]]["request_id"] == e["request_id"]
        assert back[e["uri"]]["wait"] == pytest.approx(e["backend_service"], abs=0.002)
    assert front["/api/b/3"]["total"] - back["/api/b/3"]["total"] > 0.7


def test_prefilter_keeps_both_directions(samples, settings):
    a = engine.analyze(samples / "http_scenarios.pcap", flt=Filter(host_a="10.10.1.50", host_b="10.20.2.0/24", port=8080),
                       settings=settings)
    assert a.meta["connections"] == 12 and a.meta["transactions"] == 18


def test_prefilter_time_range(samples, settings):
    start = 1_790_000_002.0
    a = engine.analyze(samples / "http_scenarios.pcap", flt=Filter(start=start, end=start + 3), settings=settings)
    assert a.meta["connections"] == 1
    assert list(by_uri(a)) == ["/api/reports/2024"]


def test_bad_filter_is_rejected(samples, settings):
    with pytest.raises(tshark.TsharkError):
        engine.analyze(samples / "http_scenarios.pcap", flt=Filter(display="not a ) filter"), settings=settings)


def test_bad_ip_is_rejected(samples, settings):
    with pytest.raises(ValueError):
        engine.analyze(samples / "http_scenarios.pcap", flt=Filter(host_a="x; rm -rf /"), settings=settings)


def test_second_run_reopens_result(samples, settings):
    assert engine.analyze(samples / "http_scenarios.pcap", settings=settings).cached is False
    again = engine.analyze(samples / "http_scenarios.pcap", settings=settings)
    assert again.cached is True and len(txns(again)) == 18


def test_other_key_is_a_new_analysis(samples, settings):
    a = engine.analyze(samples / "https_tls13.pcap", settings=settings)
    b = engine.analyze(samples / "https_tls13.pcap", keylog=samples / "https_tls13.keylog", settings=settings)
    assert a.id != b.id and b.cached is False


def test_size_limit(samples, settings):
    settings.max_size_mb = 0
    with pytest.raises(engine.CaptureTooLarge):
        engine.analyze(samples / "http_scenarios.pcap", settings=settings)


def test_cut_short_capture_still_analyzes(samples, settings, tmp_path):
    cut = tmp_path / "cut.pcap"
    cut.write_bytes((samples / "http_scenarios.pcap").read_bytes()[:50000])
    a = engine.analyze(cut, settings=settings)
    assert "capture_truncated" in a.meta["warnings"] and a.meta["packets"] > 0


def test_not_a_capture(settings, tmp_path):
    bad = tmp_path / "bad.pcap"
    bad.write_bytes(b"this is not a capture")
    with pytest.raises(tshark.TsharkError):
        engine.analyze(bad, settings=settings)


def test_no_key_left_behind(samples, settings):
    a = engine.analyze(samples / "https_tls13.pcap", keylog=samples / "https_tls13.keylog", settings=settings)
    names = {p.name for p in a.dir.iterdir()}
    assert names == {"analysis.duckdb", "meta.json", "capture"}
    assert not list(__import__("pathlib").Path("/tmp").glob("pcap-analyzer-*"))


def test_list_delete_purge(samples, settings, tmp_path):
    a = engine.analyze(samples / "http_scenarios.pcap", settings=settings)
    assert [m["id"] for m in engine.list_analyses(settings)] == [a.id]
    assert engine.purge(settings, now=a.meta["created"] + 86400, tmp_root=tmp_path) == 0
    assert engine.purge(settings, now=a.meta["created"] + 8 * 86400, tmp_root=tmp_path) == 1
    assert engine.list_analyses(settings) == []
    assert engine.delete("missing", settings) is False


@pytest.mark.parametrize("srv,cli,want", [
    (0.1, 0.001, "near_client"), (0.001, 0.1, "near_server"), (0.05, 0.05, "middle"),
    (0.0001, 0.0001, "unknown"), (None, 0.1, "unknown"),
])
def test_capture_point(srv, cli, want):
    assert parser.capture_point(srv, cli) == want


def test_rtt_uses_lowest_sample():
    assert parser.pick_rtt(0.911, [0.561, 0.7]) == 0.561
    assert parser.pick_rtt(None, []) is None


def test_negative_service_is_not_reported():
    p = parser.Packet(1, 10.0, 60, ("a", 1), 10, 0x18, False, False)
    r = parser.Packet(2, 10.771, 60, ("b", 2), 10, 0x18, False, False)
    s = parser.Stream(0, ("a", 1), ("b", 2))
    row = parser._row(s, "GET", "/", None, "HTTP/1.1", 200, None, p, p, r, r, 0.911, 0, 0, None, None, None, None, None, None, None, None, None)
    assert row["wait"] == pytest.approx(0.771) and row["service"] is None


def causes_by_uri(a):
    return {t["uri"]: t["cause"] for t in txns(a)}


@pytest.mark.parametrize("uri,cause", [
    ("/api/reports/2024", "service"), ("/files/large.bin", "loss"), ("/files/big2.bin", "slow_client"),
    ("/api/slow", "connection_reset"), ("/api/nagle", "delayed_ack"), ("/files/cut.bin", "truncated"),
    ("/api/second", "queueing"), ("/api/far", "network"), ("/api/users/123", "normal"), ("/api/items", "normal"),
])
def test_cause(http, uri, cause):
    assert causes_by_uri(http)[uri] == cause


def test_gateway_cause(http):
    assert {t["cause"] for t in txns(http, "uri='/api/pay'")} == {"gateway"}


def test_stall_times(http):
    q = by_uri(http)
    assert q["/files/large.bin"]["retrans_count"] == 2 and q["/files/large.bin"]["retrans_time"] == pytest.approx(0.8, abs=0.01)
    assert q["/files/big2.bin"]["zero_window_time"] == pytest.approx(1.2, abs=0.01)
    assert q["/api/nagle"]["delayed_ack_time"] == pytest.approx(0.201, abs=0.01)
    assert q["/api/second"]["queue_time"] == pytest.approx(1.0, abs=0.01)
    assert q["/api/first"]["queue_time"] == 0


def test_truncated_flag_and_dns(http):
    q = by_uri(http)
    assert q["/files/cut.bin"]["truncated"] is True and q["/files/cut.bin"]["body_bytes"] == 6000
    assert q["/files/large.bin"]["truncated"] is False
    assert q["/api/users/123"]["dns_time"] == pytest.approx(0.12, abs=0.001)
    assert q["/api/users/456"]["dns_time"] is None


def test_server_reported_time(http):
    assert by_uri(http)["/api/items"]["server_reported"] == pytest.approx(0.1205)


def test_small_mss_flag(http):
    assert "small_mss" in by_uri(http)["/files/mss.bin"]["flags"]


def test_url_template():
    from pcap_analyzer.urls import template
    assert template("/users/123/orders?x=1") == "/users/{id}/orders"
    assert template("/a/550e8400-e29b-41d4-a716-446655440000/b") == "/a/{id}/b"
    assert template("/static/app.js") == "/static/app.js"
    assert template("http://h.example/x/9") == "/x/{id}"
    assert template("/") == "/"


def test_masking():
    from pcap_analyzer import privacy
    assert privacy.mask_uri("/a?user=x&password=abc&token=z") == "/a?user=x&password=***&token=***"
    assert privacy.mask_header("Cookie", "a=b") == "***" and privacy.mask_header("Accept", "x") == "x"
    assert privacy.mask_body('{"password":"abc","x":1}') == '{"password":"***","x":1}'
    assert privacy.mask_body("user=a&passwd=b") == "user=a&passwd=***"


def test_secrets_are_not_stored(samples, settings, tmp_path):
    a = engine.analyze(samples / "https_tls13.pcap", keylog=samples / "https_tls13.keylog", settings=settings)
    assert all("sample-gen" in t["req_headers"] for t in txns(a))


@pytest.mark.parametrize("magic", [b"\x28\xb5\x2f\xfd", b"\x04\x22\x4d\x18"])
def test_compressed_capture_is_refused(settings, tmp_path, magic):
    p = tmp_path / "c.pcap"
    p.write_bytes(magic + b"data")
    with pytest.raises(engine.CompressedCapture, match="Decompress"):
        engine.analyze(p, settings=settings)


def test_gzip_capture_opens(samples, settings, tmp_path):
    p = tmp_path / "c.pcap.gz"
    p.write_bytes(gzip.compress((samples / "http_scenarios.pcap").read_bytes()))
    a = engine.analyze(p, settings=settings)
    assert a.meta["filename"] == "c.pcap" and a.meta["transactions"] == 18


def test_gzip_stops_at_the_limit_while_unpacking(settings, tmp_path):
    settings.max_size_mb = 1
    p = tmp_path / "bomb.pcap.gz"
    p.write_bytes(gzip.compress(bytes(3 << 20)))
    with pytest.raises(engine.CaptureTooLarge):
        engine.analyze(p, settings=settings)


def test_damaged_gzip_is_refused(settings, tmp_path):
    p = tmp_path / "c.pcap.gz"
    p.write_bytes(gzip.compress(bytes(1000))[:20])
    with pytest.raises(engine.CompressedCapture):
        engine.analyze(p, settings=settings)


def test_parts_become_one_capture(samples, settings, tmp_path):
    a = samples / "http_scenarios.pcap"
    gz = tmp_path / "b.pcap.gz"
    gz.write_bytes(gzip.compress((samples / "https_tls13.pcap").read_bytes()))
    joined = engine.join_parts([a, gz], tmp_path, settings)
    got = engine.analyze(joined, settings=settings, display_name="both")
    assert got.meta["packets"] > engine.analyze(a, settings=settings).meta["packets"]


def test_purge_removes_stale_temp_files_only(settings, tmp_path):
    root = tmp_path / "tmp"
    stale = [root / "pcap-upload-a", root / "pcap-analyzer-b", root / "pcap-export-c", settings.workdir / ".tmp-d"]
    fresh = root / "pcap-upload-new"
    other = root / "someone-else"
    for d in stale + [fresh, other]:
        d.mkdir(parents=True)
        (d / "keylog").write_text("secret")
    old = time.time() - 7 * 3600
    for d in stale + [other]:
        os.utime(d, (old, old))
    engine.purge(settings, tmp_root=root)
    assert not any(d.exists() for d in stale)
    assert fresh.exists() and other.exists()
