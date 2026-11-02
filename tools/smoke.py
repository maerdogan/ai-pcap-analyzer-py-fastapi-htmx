#!/usr/bin/env python3
"""Walk through a running pcap-analyzer the way a person would, and stop at the first failure.

Signs in, uploads a capture, opens every page, downloads each export, deletes the analysis and signs out.
It needs only Python. The password comes from PCAP_ANALYZER_SMOKE_PASSWORD, and a wrong form token must be refused.

Usage: smoke.py URL CAPTURE [--user NAME] [--cafile CERT]
"""
import argparse
import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

TABS = ("overview", "issues", "urls", "connections", "hosts", "backends")
TABLES = ("requests", "urls", "connections", "hosts", "issues")
FORMATS = ("csv", "json", "xlsx")
ANALYSIS_LIMIT_S = 180


class Failed(Exception):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_):
        return None


class Browser:
    def __init__(self, url, cafile):
        self.url = url.rstrip("/")
        self.cookies = {}
        context = ssl.create_default_context(cafile=cafile)
        self.opener = urllib.request.build_opener(NoRedirect, urllib.request.HTTPSHandler(context=context))

    def call(self, path, data=None, headers=None, expect=200):
        headers = dict(headers or {})
        if self.cookies:
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
        request = urllib.request.Request(self.url + path, data=data, headers=headers)
        try:
            response = self.opener.open(request, timeout=60)
        except urllib.error.HTTPError as e:  # also every redirect, since they are not followed
            response = e
        body = response.read()
        for cookie in response.headers.get_all("set-cookie") or ():
            name, value = cookie.split(";", 1)[0].split("=", 1)
            self.cookies[name] = value
        if response.status != expect:
            raise Failed(f"{path}: got {response.status}, expected {expect}: {body[:200]!r}")
        return response, body

    def form(self, path, fields, expect=303):
        return self.call(path, urllib.parse.urlencode(fields).encode(), {"Content-Type": "application/x-www-form-urlencoded"}, expect)


def _multipart(name, filename, content):
    boundary = uuid.uuid4().hex
    head = f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"; filename="{filename}"\r\n\r\n'.encode()
    return head + content + f"\r\n--{boundary}--\r\n".encode(), f"multipart/form-data; boundary={boundary}"


def _check_headers(response, secure):
    names = ["content-security-policy", "x-content-type-options"] + ["strict-transport-security"] * secure
    missing = [n for n in names if not response.headers.get(n)]
    if missing:
        raise Failed(f"missing response headers: {', '.join(missing)}")


def walk(b, user, password, capture):
    _, body = b.call("/healthz")
    print("health:", body.decode())
    b.call("/login")
    login, _ = b.form("/login", dict(username=user, password=password))
    secure = "secure" in ";".join(login.headers.get_all("set-cookie")).lower()
    response, home = b.call("/")
    _check_headers(response, secure)
    print("signed in, cookie secure:", secure)

    token = re.search(rb'"X-CSRF-Token": "(\w+)"', home)
    if not token:
        raise Failed("the home page has no form token")
    token = token[1].decode()
    b.form("/logout", {}, expect=403)
    print("post without a form token: refused")

    with open(capture, "rb") as f:
        data, content_type = _multipart("capture", os.path.basename(capture), f.read())
    _, body = b.call("/upload", data, {"Content-Type": content_type, "X-CSRF-Token": token, "HX-Request": "true"})
    job = re.search(rb"/jobs/([0-9a-f]+)", body)
    if not job:
        raise Failed(f"upload was not accepted: {body[:200]!r}")
    deadline = time.time() + ANALYSIS_LIMIT_S
    while True:
        response, body = b.call(f"/jobs/{job[1].decode()}", headers={"HX-Request": "true"})
        home = response.headers.get("hx-redirect")
        if home:
            break
        if b'class="error"' in body or time.time() > deadline:
            raise Failed(f"analysis did not finish: {body[:300]!r}")
        time.sleep(0.5)
    print("analysis done:", home)

    for tab in TABS:
        b.call(f"{home}?tab={tab}")
    b.call(f"{home}/inspect")
    aid = home.rsplit("/", 1)[1]
    _, urls = b.call(f"/api/a/{aid}/urls")
    requests = sum(u["requests"] for u in json.loads(urls))
    if not requests:
        raise Failed("the analysis found no requests")
    print("requests found:", requests)

    for name in TABLES:
        for fmt in FORMATS:
            _, body = b.call(f"/export/{aid}/{name}.{fmt}")
            if not body:
                raise Failed(f"{name}.{fmt} is empty")
    _, report = b.call(f"/export/{aid}/report.html")
    _, connections = b.call(f"/api/a/{aid}/connections")
    _, packets = b.call(f"/export/{aid}/conn/{json.loads(connections)[0]['stream']}.pcapng")
    print(f"exports done, report {len(report)} bytes, connection {len(packets)} bytes")

    b.form(f"{home}/delete", dict(csrf_token=token))
    b.call(home, expect=404)
    b.form("/logout", dict(csrf_token=token))
    b.call("/", expect=303)
    print("deleted and signed out")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("url")
    ap.add_argument("capture")
    ap.add_argument("--user", default="admin")
    ap.add_argument("--cafile", help="certificate to trust, for a self-signed server")
    args = ap.parse_args()
    password = os.environ.get("PCAP_ANALYZER_SMOKE_PASSWORD")
    if not password:
        sys.exit("set PCAP_ANALYZER_SMOKE_PASSWORD first")
    try:
        walk(Browser(args.url, args.cafile), args.user, password, args.capture)
    except (Failed, OSError) as e:
        sys.exit(f"FAILED: {e}")
    print("OK")


if __name__ == "__main__":
    main()
