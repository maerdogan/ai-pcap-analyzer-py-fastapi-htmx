import re
import time

import pytest
from fastapi.testclient import TestClient

from pcap_analyzer.web.app import create_app
from pcap_analyzer.web.auth import Auth, hash_password, verify_password

PW = "test-pass-for-unit-tests"


@pytest.fixture
def anon(settings):
    settings.admin_password = PW
    with TestClient(create_app(settings), follow_redirects=False, base_url="https://testserver") as c:
        yield c


@pytest.fixture
def client(anon):
    r = anon.post("/login", data={"username": "admin", "password": PW})
    assert r.status_code == 303
    return anon


def upload(client, path, extra_files=None, **form):
    files = {"capture": (path.name, path.read_bytes())}
    for k, p in (extra_files or {}).items():
        files[k] = (p.name, p.read_bytes())
    r = client.post("/upload", files=files, data=form)
    assert r.status_code == 200, r.text
    jid = re.search(r"/jobs/([0-9a-f]+)", r.text)
    if not jid:
        return r.text
    for _ in range(300):
        s = client.get(f"/jobs/{jid[1]}")
        if "HX-Redirect" in s.headers:
            return s.headers["HX-Redirect"]
        if 'class="error"' in s.text:
            return s.text
        time.sleep(0.05)
    raise AssertionError("analysis did not finish")


def test_needs_a_password(settings):
    with pytest.raises(ValueError):
        create_app(settings)


def test_pages_need_login(anon):
    assert anon.get("/").headers["location"] == "/login"
    assert anon.get("/api/a/0/urls").status_code == 401
    assert anon.get("/a/00000000000000000000").status_code == 303
    assert anon.get("/healthz").json()["status"] == "ok"


def test_wrong_password_and_lockout(anon):
    for _ in range(5):
        assert anon.post("/login", data={"username": "admin", "password": "wrong"}).status_code == 401
    assert anon.post("/login", data={"username": "admin", "password": PW}).status_code == 429


def test_cookie_flags_and_logout(anon):
    r = anon.post("/login", data={"username": "admin", "password": PW})
    c = r.headers["set-cookie"].lower()
    assert "httponly" in c and "samesite=strict" in c
    assert anon.post("/logout").status_code == 303
    assert anon.get("/").status_code == 303


def test_password_hash():
    h = hash_password("x")
    assert verify_password("x", h) and not verify_password("y", h) and not verify_password("x", "junk")
    assert Auth("a", password_hash=h).login("c", "a", "x")


def test_security_headers(client):
    h = client.get("/").headers
    assert "default-src 'self'" in h["content-security-policy"] and h["x-content-type-options"] == "nosniff"


def test_cross_site_post_refused(client):
    assert client.post("/logout", headers={"Sec-Fetch-Site": "cross-site"}).status_code == 403


def test_upload_and_all_views(client, samples):
    home = upload(client, samples / "http_scenarios.pcap")
    assert home.startswith("/a/")
    aid = home.rsplit("/", 1)[1]
    assert "http_scenarios.pcap" in client.get("/").text
    page = client.get(home).text
    assert "Where the time went" in page and "Slow service" in page
    for tab, word in (("issues", "Requests without a response"), ("urls", "data-grid"), ("connections", "data-grid"), ("hosts", "data-grid")):
        assert word in client.get(f"{home}?tab={tab}").text
        assert word in client.get(f"{home}?tab={tab}", headers={"HX-Request": "true"}).text
    assert client.get(f"{home}?tab=nope").status_code == 404
    assert "/api/users/{id}" in str(client.get(f"/api/a/{aid}/urls").json())
    assert len(client.get(f"/api/a/{aid}/connections").json()) == 12
    assert client.get(f"/api/a/{aid}/hosts").json()[0]["host"] == "app.example.test"
    assert sum(b["requests"] for b in client.get(f"/api/a/{aid}/histogram").json()) == 17
    assert client.get(f"/api/a/{aid}/statuses").status_code == 200
    assert client.get(f"/api/a/{aid}/nope").status_code == 404
    assert "HTTP 504" in client.get(f"{home}/issue/gateway").text
    assert "Connection" in client.get(f"{home}/issue/resets").text
    assert client.get(f"{home}/issue/nope").status_code == 404
    conn = client.get(f"{home}/conn/0").text
    assert "Slowest requests" in conn and "Window scale" in conn
    assert client.get(f"{home}/conn/999").status_code == 404
    tid = re.search(r"/txn/(\d+)", conn)[1]
    detail = client.get(f"{home}/txn/{tid}").text
    assert "Host: app.example.test" in detail and "are masked" in detail
    assert client.get(f"{home}/txn/99999").status_code == 404
    assert client.post(f"{home}/delete").status_code == 303
    assert client.get(home).status_code == 404


def test_inspect_and_saved_filters(client, samples):
    home = upload(client, samples / "http_scenarios.pcap")
    r = client.get(f"{home}/inspect", params=dict(src="10.10.1.50", dst="10.20.2.10", port=8080))
    assert "Slowest 10 requests" in r.text
    partial = client.get(f"{home}/inspect", params=dict(url="/files/", min_size=150000, size_of="response"), headers={"HX-Request": "true"})
    assert "large.bin" in partial.text and "<html" not in partial.text
    assert "Nothing in this capture matches" in client.get(f"{home}/inspect", params=dict(src="9.9.9.9")).text
    assert client.get(f"{home}/inspect", params=dict(port="abc")).status_code == 400
    assert client.post("/filters", data=dict(name="Orders", url="/orders", back=f"{home}/inspect")).status_code == 303
    page = client.get(f"{home}/inspect").text
    assert "Orders" in page and "url=/orders" in page.replace("%2F", "/")
    fid = re.search(r"/filters/([0-9a-f]+)/delete", page)[1]
    client.post(f"/filters/{fid}/delete", data=dict(back=f"{home}/inspect"))
    assert "Orders" not in client.get(f"{home}/inspect").text


def test_keylog_upload(client, samples):
    home = upload(client, samples / "https_tls13.pcap", {"keylog": samples / "https_tls13.keylog"})
    assert "/secure/report/{id}" in str(client.get(home.replace("/a/", "/api/a/") + "/urls").json())


def test_display_filter_rejected_with_message(client, samples):
    text = upload(client, samples / "http_scenarios.pcap", display_filter="not a ) filter")
    assert 'class="error"' in text


def test_bad_ip_rejected(client, samples):
    r = client.post("/upload", files={"capture": ("a.pcap", b"x")}, data={"host_a": "nope"})
    assert "not a valid IP" in r.text


def test_upload_size_limit(client, samples, settings):
    settings.max_size_mb = 0
    r = client.post("/upload", files={"capture": ("a.pcap", b"x" * (3 * 1024 * 1024))})
    assert r.status_code == 413


def test_garbage_file_shows_error(client, tmp_path):
    bad = tmp_path / "bad.pcap"
    bad.write_bytes(b"not a capture at all")
    assert 'class="error"' in upload(client, bad)


def test_html_is_escaped(client, samples, tmp_path):
    p = tmp_path / "<script>x.pcap"
    p.write_bytes((samples / "http_scenarios.pcap").read_bytes())
    upload(client, p)
    assert "<script>x" not in client.get("/").text
