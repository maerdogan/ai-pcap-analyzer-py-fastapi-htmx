"""Web interface. Pages use HTMX; tables and charts load JSON from /api."""
import datetime
import ipaddress
import os
import re
import shutil
import tempfile
from pathlib import Path

from fastapi import FastAPI, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .. import __version__, compare, engine, exports, reports, tshark
from ..config import Settings
from . import saved
from .auth import Auth
from .jobs import Jobs, QueueFull

HERE = Path(__file__).parent
COOKIE = "pcap_session"
OPEN_PATHS = ("/login", "/healthz", "/static/")
CHUNK = 1 << 20
FORM_OVERHEAD = 2 * CHUNK  # key files and form fields on top of the capture
KEY_LIMIT = CHUNK
TABS = {"overview": "Overview", "issues": "Issues", "urls": "URLs", "connections": "Connections", "hosts": "Hosts"}
CSP = ("default-src 'self'; img-src 'self' data:; font-src 'self' data:; style-src 'self' 'unsafe-inline'; object-src 'none'; "
       "base-uri 'none'; frame-ancestors 'none'; form-action 'self'")


def seconds(v):
    if v is None:
        return "–"
    return f"{v * 1000:.1f} ms" if v < 1 else f"{v:.2f} s"


def size(v):
    if v is None:
        return "–"
    for unit in ("B", "KB", "MB", "GB"):
        if v < 1024 or unit == "GB":
            return f"{v:.0f} {unit}" if unit == "B" else f"{v:.1f} {unit}"
        v /= 1024


def when(v):
    return datetime.datetime.fromtimestamp(v).strftime("%Y-%m-%d %H:%M:%S") if v else "–"


WARNINGS = {
    "frames_truncated": "Some packets were cut short by the capture, so body sizes may be incomplete.",
    "capture_truncated": "The capture file ends abruptly. Everything up to that point was analyzed.",
    "offload_suspected": "Packets larger than the MSS suggest capture on the sending host with segmentation offload. Timing inside a send can look better than reality.",
    "tls_not_decrypted": "Some TLS traffic stayed encrypted. Add a key log file to see URLs and HTTP timing.",
    "tls_key_did_not_decrypt": "The key did not decrypt some TLS traffic. It may belong to another session, or RSA keys cannot read this cipher.",
}


def _bad(message, code=400):
    raise HTTPException(code, message)


def _opt_int(v, name):
    if v in (None, ""):
        return None
    try:
        return int(v)
    except ValueError:
        _bad(f"{name} must be a whole number")


def _ip(v, name):
    v = (v or "").strip()
    if not v:
        return None
    try:
        ipaddress.ip_network(v, strict=False)
    except ValueError:
        _bad(f"{name} is not a valid IP address or network: {v}")
    return v


def _epoch(v):
    if not v:
        return None
    try:
        return datetime.datetime.fromisoformat(v).timestamp()
    except ValueError:
        _bad(f"Time is not valid: {v}")


async def _save(upload, path, limit, label):
    written = 0
    with open(path, "wb") as f:
        os.chmod(path, 0o600)
        while chunk := await upload.read(CHUNK):
            written += len(chunk)
            if written > limit:
                _bad(f"{label} is too large", 413)
            f.write(chunk)
    return written


def create_app(settings=None, secure_cookie=False):
    settings = settings or Settings()
    auth = Auth(settings.admin_user, settings.admin_password, settings.admin_password_hash)
    jobs = Jobs(settings)
    app = FastAPI(title="pcap-analyzer", version=__version__, docs_url=None, redoc_url=None, openapi_url=None)
    app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")
    templates = Jinja2Templates(directory=HERE / "templates")
    templates.env.filters.update(seconds=seconds, size=size, when=when)
    templates.env.globals.update(version=__version__, tabs=TABS, warning_text=WARNINGS)

    def page(request, name, **ctx):
        return templates.TemplateResponse(request, name, ctx)

    def capture_ctx(a):
        """What every capture page needs for its navigation."""
        with a.connect() as db:
            return dict(a=a, m=a.meta, issue_count=sum(i["count"] for i in reports.issues(db, a.meta) if i["severity"] == 1))

    def is_htmx(request):
        return request.headers.get("hx-request") == "true"

    def opened(aid):
        try:
            return engine.open_analysis(aid, settings)
        except engine.NotFound:
            _bad("This analysis does not exist. It may have passed its retention time.", 404)

    @app.middleware("http")
    async def guard(request, call_next):
        path = request.url.path
        if request.method not in ("GET", "HEAD") and request.headers.get("sec-fetch-site") == "cross-site":
            return Response("Cross-site request refused", 403)
        if request.method == "POST" and path == "/upload":
            length = request.headers.get("content-length")
            if length is None or not length.isdigit():
                return Response("Content-Length is required", 411)
            if int(length) > settings.max_size_mb * CHUNK + FORM_OVERHEAD:
                return Response(f"The capture is larger than the {settings.max_size_mb} MB limit.", 413)
        if not path.startswith(OPEN_PATHS) and not auth.valid(request.cookies.get(COOKIE)):
            if path.startswith("/api/"):
                return JSONResponse({"error": "login required"}, 401)
            if request.headers.get("hx-request"):
                return Response(status_code=204, headers={"HX-Redirect": "/login"})
            return RedirectResponse("/login", 303)
        response = await call_next(request)
        response.headers.update({"Content-Security-Policy": CSP, "X-Content-Type-Options": "nosniff",
                                 "Referrer-Policy": "no-referrer", "Cache-Control": "no-store" if not path.startswith("/static/") else "no-cache"})
        return response

    @app.exception_handler(HTTPException)
    async def http_error(request, exc):
        if request.url.path.startswith("/api/"):
            return JSONResponse({"error": exc.detail}, exc.status_code)
        if is_htmx(request):
            return HTMLResponse(f'<p class="error" role="alert">{_escape(exc.detail)}</p>', 200)
        return templates.TemplateResponse(request, "error.html", dict(message=exc.detail), status_code=exc.status_code)

    @app.get("/healthz")
    def healthz():
        return {"status": "ok", "version": __version__}

    @app.get("/login", response_class=HTMLResponse)
    def login_form(request: Request):
        if auth.valid(request.cookies.get(COOKIE)):
            return RedirectResponse("/", 303)
        return page(request, "login.html", error=None)

    @app.post("/login", response_class=HTMLResponse)
    def login(request: Request, username: str = Form(""), password: str = Form("")):
        client = request.client.host if request.client else "unknown"
        if auth.blocked(client):
            return templates.TemplateResponse(request, "login.html", dict(error="Too many failed attempts. Try again in 5 minutes."), status_code=429)
        token = auth.login(client, username, password)
        if not token:
            return templates.TemplateResponse(request, "login.html", dict(error="The user name or password is wrong."), status_code=401)
        resp = RedirectResponse("/", 303)
        resp.set_cookie(COOKIE, token, httponly=True, samesite="strict", secure=secure_cookie, max_age=12 * 3600)
        return resp

    @app.post("/logout")
    def logout(request: Request):
        auth.logout(request.cookies.get(COOKIE))
        resp = RedirectResponse("/login", 303)
        resp.delete_cookie(COOKIE)
        return resp

    @app.get("/", response_class=HTMLResponse)
    def home(request: Request):
        return page(request, "home.html", section="captures", analyses=engine.list_analyses(settings), max_mb=settings.max_size_mb, ttl=settings.ttl_days)

    @app.post("/upload", response_class=HTMLResponse)
    async def upload(request: Request, capture: UploadFile, keylog: UploadFile | None = None, rsa_key: UploadFile | None = None,
                     host_a: str = Form(""), host_b: str = Form(""), port: str = Form(""), start: str = Form(""),
                     end: str = Form(""), display_filter: str = Form("")):
        if not capture.filename:
            _bad("Choose a capture file.")
        flt = tshark.Filter(_ip(host_a, "First host"), _ip(host_b, "Second host"), _opt_int(port, "Port"), _epoch(start), _epoch(end),
                            display_filter.strip() or None)
        tmp = tempfile.mkdtemp(prefix="pcap-upload-", dir="/tmp")
        try:
            path = Path(tmp) / "capture"
            await _save(capture, path, settings.max_size_mb * CHUNK, "The capture")
            kl = rk = None
            if keylog and keylog.filename:
                kl = Path(tmp) / "keylog"
                await _save(keylog, kl, KEY_LIMIT * 8, "The key log")
            if rsa_key and rsa_key.filename:
                rk = Path(tmp) / "rsa.pem"
                await _save(rsa_key, rk, KEY_LIMIT, "The RSA key")
            job = jobs.submit(tmp, path, capture.filename, kl, rk, flt)
        except (HTTPException, QueueFull) as e:
            shutil.rmtree(tmp, ignore_errors=True)
            if isinstance(e, QueueFull):
                _bad("Too many analyses are waiting. Try again in a moment.", 429)
            raise
        return page(request, "_job.html", job=job)

    @app.get("/jobs/{jid}", response_class=HTMLResponse)
    def job_status(request: Request, jid: str):
        job = jobs.get(jid)
        if job is None:
            _bad("This analysis job is no longer known. Upload the capture again.", 404)
        if job.state == "done":
            return Response(status_code=200, headers={"HX-Redirect": f"/a/{job.analysis_id}"})
        return page(request, "_job.html", job=job)

    @app.post("/a/{aid}/delete")
    def delete(aid: str):
        engine.delete(aid, settings)
        return RedirectResponse("/", 303)

    def tab_context(a, tab):
        with a.connect() as db:
            if tab == "overview":
                return dict(o=reports.overview(db, a.meta), budget=reports.time_budget(db), slow=reports.slowest(db, limit=5))
            if tab == "issues":
                return dict(issues=reports.issues(db, a.meta))
        return {}

    @app.get("/a/{aid}", response_class=HTMLResponse)
    def analysis(request: Request, aid: str, tab: str = "overview"):
        if tab not in TABS:
            _bad("This view does not exist.", 404)
        a = opened(aid)
        name = "analysis.html" if not is_htmx(request) else f"_tab_{tab}.html"
        return page(request, name, tab=tab, **capture_ctx(a), **tab_context(a, tab))

    @app.get("/a/{aid}/issue/{key}", response_class=HTMLResponse)
    def issue(request: Request, aid: str, key: str):
        a = opened(aid)
        with a.connect() as db:
            d = reports.issue_detail(db, key)
        if d is None:
            _bad("This issue does not exist.", 404)
        return page(request, "issue.html", d=d, **capture_ctx(a))

    @app.get("/a/{aid}/conn/{stream}", response_class=HTMLResponse)
    def connection(request: Request, aid: str, stream: int, percent: bool = False):
        a = opened(aid)
        with a.connect() as db:
            d = reports.connection_top(db, stream, percent)
            if d["conn"] is None:
                _bad("This connection does not exist.", 404)
            d["top"] = [reports.describe(db, t) for t in d["top"]]
        return page(request, "connection.html", d=d, percent=percent, **capture_ctx(a))

    @app.get("/a/{aid}/txn/{tid}", response_class=HTMLResponse)
    def transaction(request: Request, aid: str, tid: int):
        a = opened(aid)
        with a.connect() as db:
            t = reports.transaction(db, tid)
        if t is None:
            _bad("This request does not exist.", 404)
        return page(request, "transaction.html", t=t, **capture_ctx(a))

    def inspect_filter(q):
        size_of = q.get("size_of") or "total"
        if size_of not in reports.SIZE_SQL:
            _bad("Size type is not valid.")
        return reports.Inspect((q.get("src") or "").strip() or None, (q.get("dst") or "").strip() or None, _opt_int(q.get("port"), "Port"),
                               q.get("kind") or None, (q.get("url") or "").strip() or None, _opt_int(q.get("min_size"), "Size"), size_of)

    @app.get("/a/{aid}/inspect", response_class=HTMLResponse)
    def inspect(request: Request, aid: str):
        a = opened(aid)
        q = dict(request.query_params)
        f = inspect_filter(q)
        with a.connect() as db:
            r = reports.inspect(db, f)
            pairs = reports.rows(db, """SELECT DISTINCT client_ip, server_ip, server_port, kind, count(*) AS connections
                FROM tcp_connections GROUP BY ALL ORDER BY connections DESC LIMIT 200""")
        ctx = dict(r=r, q=q, query=str(request.url.query), pairs=pairs, kinds=sorted({p["kind"] for p in pairs}), filters=saved.load(settings), **capture_ctx(a))
        return page(request, "_inspect_results.html" if is_htmx(request) else "inspect.html", **ctx)

    @app.post("/filters")
    async def filter_add(request: Request):
        form = await request.form()
        name = (form.get("name") or "").strip()
        back = form.get("back") or "/"
        if not back.startswith("/a/"):
            back = "/"
        if not name:
            _bad("Give the filter a name.")
        saved.add(settings, name[:80], {k: form.get(k) for k in saved.FIELDS})
        return RedirectResponse(back, 303)

    @app.post("/filters/{fid}/delete")
    async def filter_delete(request: Request, fid: str):
        form = await request.form()
        saved.remove(settings, fid)
        back = form.get("back") or "/"
        return RedirectResponse(back if back.startswith("/a/") else "/", 303)

    def side_filter(q, suffix):
        return inspect_filter({k: q.get(k + suffix) for k in ("src", "dst", "port", "kind", "url", "min_size", "size_of")})

    @app.get("/compare", response_class=HTMLResponse)
    def compare_page(request: Request):
        q = dict(request.query_params)
        ctx = dict(section="compare", q=q, analyses=engine.list_analyses(settings), result=None, points=None, a=None, b=None)
        if q.get("a") and q.get("b"):
            a, b = opened(q["a"]), opened(q["b"])
            ctx.update(a=a, b=b)
            with a.connect() as da, b.connect() as db:
                if q.get("mode") == "points":
                    ctx["points"] = compare.two_point(da, db)
                else:
                    fa = side_filter(q, "_a")
                    fb = side_filter({**{k[:-2] + "_b": v for k, v in q.items() if k.endswith("_a") and v}, **{k: v for k, v in q.items() if k.endswith("_b") and v}}, "_b")
                    ctx["result"] = compare.captures(da, db, fa, fb)
        return page(request, "compare.html", **ctx)

    @app.get("/export/{aid}/report.html")
    def export_report(request: Request, aid: str):
        a = opened(aid)
        with a.connect() as db:
            ctx = dict(a=a, m=a.meta, o=reports.overview(db, a.meta), budget=reports.time_budget(db), issues=reports.issues(db, a.meta), urls=reports.url_groups(db),
                       slow=reports.slowest(db), css=(HERE / "static/app.css").read_text())
        html = templates.get_template("report.html").render(ctx)
        return Response(html, media_type="text/html; charset=utf-8", headers=_attachment(a, "report.html"))

    @app.get("/export/{aid}/{name}.{fmt}")
    def export_table(aid: str, name: str, fmt: str):
        a = opened(aid)
        if name not in exports.TABLES or fmt not in exports.FORMATS:
            _bad("This export does not exist.", 404)
        with a.connect() as db:
            body = exports.render(exports.table(db, name, a.meta), fmt)
        return Response(body, media_type=exports.FORMATS[fmt], headers=_attachment(a, f"{name}.{fmt}"))

    @app.get("/export/{aid}/conn/{stream}.pcapng")
    def export_stream(aid: str, stream: int):
        a = opened(aid)
        capture = a.dir / "capture"
        if not capture.exists():
            _bad("The original capture was not kept, so packets cannot be exported.", 404)
        with a.connect() as db:
            if not reports.one(db, "SELECT stream FROM tcp_connections WHERE stream = ?", [stream]):
                _bad("This connection does not exist.", 404)
        with tempfile.TemporaryDirectory(prefix="pcap-export-", dir="/tmp") as tmp:
            out = Path(tmp) / "out.pcapng"
            try:
                tshark.extract_stream(capture, stream, out, settings.tshark)
            except tshark.TsharkError as e:
                _bad(str(e), 500)
            body = out.read_bytes()
        return Response(body, media_type="application/vnd.tcpdump.pcap", headers=_attachment(a, f"connection-{stream}.pcapng"))

    @app.get("/api/a/{aid}/{what}")
    def api(aid: str, what: str):
        a = opened(aid)
        with a.connect() as db:
            if what == "urls":
                data = reports.url_groups(db)
            elif what == "connections":
                data = reports.connections(db)
            elif what == "hosts":
                data = reports.hosts(db)
            elif what == "histogram":
                data = reports.histogram(db)
            elif what == "statuses":
                data = reports.overview(db, a.meta)["statuses"]
            else:
                _bad("Unknown data set.", 404)
        return data

    return app


def _attachment(a, name):
    stem = re.sub(r"[^A-Za-z0-9._-]+", "_", a.meta["filename"])[:60]
    return {"Content-Disposition": f'attachment; filename="{stem}-{name}"'}


def _escape(text):
    return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
