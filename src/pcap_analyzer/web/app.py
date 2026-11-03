"""Web interface. Pages use HTMX; tables and charts load JSON from /api."""
import contextlib
import datetime
import ipaddress
import json
import logging
import os
import re
import shutil
import tempfile
import threading
from pathlib import Path

import jinja2
from fastapi import Depends, FastAPI, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .. import __version__, capture_guide, compare, engine, exports, knowledge, records, reports, split, tshark
from ..config import Settings
from . import saved
from .auth import Auth
from .jobs import Jobs, QueueFull

HERE = Path(__file__).parent
COOKIE = "pcap_session"
OPEN_PATHS = ("/login", "/language", "/healthz", "/static/")
CHUNK = 1 << 20
FORM_OVERHEAD = 2 * CHUNK  # key files and form fields on top of the capture
KEY_LIMIT = CHUNK
PURGE_INTERVAL_S = 3600
MAX_CAPTURE_S = 3600
TAB_LABELS = {"overview": "Overview", "issues": "Issues", "urls": "URLs", "connections": "Connections", "hosts": "Hosts", "backends": "Servers", "tls": "TLS"}
LANGUAGE_NAMES = {"tr": "Türkçe", "en": "English", "de": "Deutsch", "es": "Español"}
LANGUAGE_COOKIE = "pcap_language"
LANGUAGE_DAYS = 365
FORM_TOKEN_HEADER = "x-csrf-token"
FORM_TOKEN_FIELD = "csrf_token"
RECENT_CAPTURES = 12
API_PREFIX = "/api/v1/"
API_SECTIONS = ("overview", "urls", "connections", "hosts", "issues", "slowest")
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


def day(v):
    return datetime.datetime.fromtimestamp(v).strftime("%Y-%m-%d")


def clock(v):
    return datetime.datetime.fromtimestamp(v).strftime("%H:%M")


def _bad(message, code=400):
    raise HTTPException(code, message)


def _opt_int(v, name):
    if v in (None, ""):
        return None
    try:
        return int(v)
    except ValueError:
        _bad(knowledge.t("{name} must be a whole number", name=knowledge.t(name)))


def _opt_float(v):
    try:
        return float(v) if v not in (None, "") else None
    except ValueError:
        _bad(knowledge.t("Time is not valid: {value}", value=v))


def _ip(v, name):
    v = (v or "").strip()
    if not v:
        return None
    try:
        ipaddress.ip_network(v, strict=False)
    except ValueError:
        _bad(knowledge.t("{name} is not a valid IP address or network: {value}", name=knowledge.t(name), value=v))
    return v


def _epoch(v):
    if not v:
        return None
    try:
        return datetime.datetime.fromisoformat(v).timestamp()
    except ValueError:
        _bad(knowledge.t("Time is not valid: {value}", value=v))


async def _save(upload, path, limit, label):
    written = 0
    with open(path, "wb") as f:
        os.chmod(path, 0o600)
        while chunk := await upload.read(CHUNK):
            written += len(chunk)
            if written > limit:
                _bad(knowledge.t("{name} is too large", name=knowledge.t(label)), 413)
            f.write(chunk)
    return written


def _purge_loop(settings, stop):
    """Enforce retention even when nobody uses the app. Runs at startup, then every hour."""
    while True:
        try:
            engine.purge(settings)
        except OSError:
            logging.exception("Cleanup failed, trying again at the next interval")
        if stop.wait(PURGE_INTERVAL_S):
            return


def create_app(settings=None, https=False):
    settings = settings or Settings()
    auth = Auth(settings.admin_user, settings.admin_password, settings.admin_password_hash)
    jobs = Jobs(settings)
    safety_headers = {"Content-Security-Policy": CSP, "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer"}
    if https:
        safety_headers["Strict-Transport-Security"] = f"max-age={settings.hsts_s}"

    async def from_this_session(request: Request):
        """Plain forms send the token as a field, and htmx sends it as a header."""
        if request.method in ("GET", "HEAD") or request.url.path.startswith(OPEN_PATHS + (API_PREFIX,)):
            return  # API calls carry a token that a browser never adds by itself
        sent = request.headers.get(FORM_TOKEN_HEADER)
        if sent is None:
            sent = (await request.form()).get(FORM_TOKEN_FIELD)
        if not auth.form_token_ok(request.cookies.get(COOKIE), sent):
            _bad(knowledge.t("This page is out of date. Reload it and try again."), 403)

    @contextlib.asynccontextmanager
    async def lifespan(_app):
        stop = threading.Event()
        threading.Thread(target=_purge_loop, args=(settings, stop), daemon=True, name="purge").start()
        yield
        stop.set()

    app = FastAPI(title="pcap-analyzer", version=__version__, docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan,
                  dependencies=[Depends(from_this_session)])
    app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")
    templates = Jinja2Templates(directory=HERE / "templates")
    templates.env.filters.update(seconds=seconds, size=size, when=when, day=day, clock=clock)

    def log(request, event, detail=""):
        records.audit(settings, event, request.client.host if request.client else "unknown", detail)

    words = re.findall(r'\bt\("([^"]+)"\)', (HERE / "static/app.js").read_text())
    templates.env.globals.update(version=__version__, tab_labels=TAB_LABELS, _=knowledge.t, warning_text=knowledge.warnings, lang=knowledge.language,
                                 languages=lambda: [(code, LANGUAGE_NAMES[code]) for code in knowledge.LANGUAGES],
                                 js_words=lambda: {w: knowledge.t(w) for w in words})

    @jinja2.pass_context
    def form_token(ctx):
        return auth.form_token(ctx["request"].cookies.get(COOKIE))

    @jinja2.pass_context
    def recent_captures(ctx):
        """Error pages also reach people who have not signed in, and they must not see file names."""
        return engine.list_analyses(settings)[:RECENT_CAPTURES] if auth.valid(ctx["request"].cookies.get(COOKIE)) else []

    templates.env.globals.update(form_token=form_token, recent_captures=recent_captures)

    def page(request, name, **ctx):
        return templates.TemplateResponse(request, name, ctx)

    def capture_ctx(a):
        """What every capture page needs for its navigation."""
        with a.connect() as db:
            return dict(a=a, m=a.meta, notes=records.notes(settings, a.id), issue_count=sum(i["count"] for i in reports.issues(db, a.meta) if i["severity"] == 1))

    def is_htmx(request):
        return request.headers.get("hx-request") == "true"

    def opened(aid):
        try:
            return engine.open_analysis(aid, settings)
        except engine.NotFound:
            _bad(knowledge.t("This analysis does not exist. It may have passed its retention time."), 404)

    def refusal(request):
        """The answer to a request that must not reach a route."""
        path = request.url.path
        if request.method not in ("GET", "HEAD") and request.headers.get("sec-fetch-site") == "cross-site":
            return Response(knowledge.t("Cross-site request refused"), 403)
        if request.method == "POST" and path in ("/upload", API_PREFIX + "captures"):
            length = request.headers.get("content-length")
            if length is None or not length.isdigit():
                return Response(knowledge.t("Content-Length is required"), 411)
            if int(length) > settings.max_size_mb * CHUNK + FORM_OVERHEAD:
                return Response(knowledge.t("The capture is larger than the {n} MB limit.", n=settings.max_size_mb), 413)
        if path.startswith(API_PREFIX):
            sent = request.headers.get("authorization", "")
            if not sent.startswith("Bearer ") or not records.token_name(settings, sent[7:]):
                return JSONResponse({"error": knowledge.t("A valid API token is required.")}, 401)
            return None
        if not path.startswith(OPEN_PATHS) and not auth.valid(request.cookies.get(COOKIE)):
            if path.startswith("/api/"):
                return JSONResponse({"error": knowledge.t("login required")}, 401)
            if request.headers.get("hx-request"):
                return Response(status_code=204, headers={"HX-Redirect": "/login"})
            return RedirectResponse("/login", 303)
        return None

    @app.middleware("http")
    async def guard(request, call_next):
        knowledge.set_language(request.cookies.get(LANGUAGE_COOKIE))
        response = refusal(request) or await call_next(request)
        response.headers.update(safety_headers)
        response.headers["Cache-Control"] = "no-cache" if request.url.path.startswith("/static/") else "no-store"
        return response

    @app.exception_handler(HTTPException)
    async def http_error(request, exc):
        if request.url.path.startswith("/api/"):
            return JSONResponse({"error": exc.detail}, exc.status_code)
        if is_htmx(request):
            return HTMLResponse(f'<p class="error" role="alert">{_escape(exc.detail)}</p>', 200)
        return templates.TemplateResponse(request, "error.html", dict(message=exc.detail), status_code=exc.status_code)

    @app.post("/language")
    def choose_language(language: str = Form(""), back: str = Form("/")):
        if language not in knowledge.LANGUAGES:
            _bad(knowledge.t("This language is not available."))
        resp = RedirectResponse(back if back.startswith("/") and not back.startswith(("//", "/\\")) else "/", 303)
        resp.set_cookie(LANGUAGE_COOKIE, language, httponly=True, samesite="lax", secure=https, max_age=LANGUAGE_DAYS * 86400)
        return resp

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
            return templates.TemplateResponse(request, "login.html", dict(error=knowledge.t("Too many failed attempts. Try again in 5 minutes.")), status_code=429)
        token = auth.login(client, username, password)
        if not token:
            log(request, "login_failed", username)
            return templates.TemplateResponse(request, "login.html", dict(error=knowledge.t("The user name or password is wrong.")), status_code=401)
        log(request, "login")
        resp = RedirectResponse("/", 303)
        resp.set_cookie(COOKIE, token, httponly=True, samesite="strict", secure=https, max_age=12 * 3600)
        return resp

    @app.post("/logout")
    def logout(request: Request):
        auth.logout(request.cookies.get(COOKIE))
        log(request, "logout")
        resp = RedirectResponse("/login", 303)
        resp.delete_cookie(COOKIE)
        return resp

    @app.get("/", response_class=HTMLResponse)
    def home(request: Request, q: str = ""):
        return page(request, "home.html", section="captures", analyses=records.search(settings, engine.list_analyses(settings), q), search=q, max_mb=settings.max_size_mb, ttl=settings.ttl_days)

    @app.post("/upload", response_class=HTMLResponse)
    async def upload(request: Request, capture: UploadFile, more: list[UploadFile] = (), keylog: UploadFile | None = None, rsa_key: UploadFile | None = None,
                     host_a: str = Form(""), host_b: str = Form(""), port: str = Form(""), start: str = Form(""),
                     end: str = Form(""), display_filter: str = Form("")):
        job = await accept(capture, keylog, rsa_key, host_a, host_b, port, start, end, display_filter, more)
        log(request, "upload", capture.filename)
        return page(request, "_job.html", job=job)

    async def accept(capture, keylog, rsa_key, host_a, host_b, port, start, end, display_filter, more=()):
        if not capture.filename:
            _bad(knowledge.t("Choose a capture file."))
        flt = tshark.Filter(_ip(host_a, "First host"), _ip(host_b, "Second host"), _opt_int(port, "Port"), _epoch(start), _epoch(end),
                            display_filter.strip() or None)
        tmp = tempfile.mkdtemp(prefix="pcap-upload-", dir="/tmp")
        try:
            path = Path(tmp) / "capture"
            await _save(capture, path, settings.max_size_mb * CHUNK, "Capture")
            parts = [path]
            for i, extra in enumerate(p for p in more if p.filename):
                parts.append(Path(tmp) / f"part-{i}")
                await _save(extra, parts[-1], settings.max_size_mb * CHUNK, "Capture")
            name = capture.filename if len(parts) == 1 else knowledge.t("{name} and {n} more", name=capture.filename, n=len(parts) - 1)
            path = engine.join_parts(parts, tmp, settings)
            kl = rk = None
            if keylog and keylog.filename:
                kl = Path(tmp) / "keylog"
                await _save(keylog, kl, KEY_LIMIT * 8, "Key log")
            if rsa_key and rsa_key.filename:
                rk = Path(tmp) / "rsa.pem"
                await _save(rsa_key, rk, KEY_LIMIT, "RSA key")
            job = jobs.submit(tmp, path, name.removesuffix(".gz"), kl, rk, flt)
        except (HTTPException, QueueFull, engine.CaptureTooLarge, engine.CompressedCapture, tshark.TsharkError) as e:
            shutil.rmtree(tmp, ignore_errors=True)
            if isinstance(e, QueueFull):
                _bad(knowledge.t("Too many analyses are waiting. Try again in a moment."), 429)
            if not isinstance(e, HTTPException):
                _bad(str(e), 413 if isinstance(e, engine.CaptureTooLarge) else 400)
            raise
        return job

    @app.get("/jobs/{jid}", response_class=HTMLResponse)
    def job_status(request: Request, jid: str):
        job = jobs.get(jid)
        if job is None:
            _bad(knowledge.t("This analysis job is no longer known. Upload the capture again."), 404)
        if job.state == "done":
            return Response(status_code=200, headers={"HX-Redirect": f"/a/{job.analysis_id}"})
        return page(request, "_job.html", job=job)

    @app.post("/jobs/{jid}/cancel", response_class=HTMLResponse)
    def job_cancel(request: Request, jid: str):
        job = jobs.cancel(jid)
        if job is None:
            _bad(knowledge.t("This analysis job is no longer known. Upload the capture again."), 404)
        return page(request, "_job.html", job=job)

    @app.post("/a/{aid}/delete")
    def delete(request: Request, aid: str):
        log(request, "delete", aid)
        engine.delete(aid, settings)
        return RedirectResponse("/", 303)

    def tab_context(a, tab):
        with a.connect() as db:
            if tab == "overview":
                ctx = dict(o=reports.overview(db, a.meta), budget=reports.time_budget(db), slow=reports.slowest(db, limit=5), quality=reports.quality(a.meta),
                           missed=reports.target_misses(db, records.thresholds(settings)["targets"]), base=None, drift=[])
                base_id = records.baseline(settings)
                if base_id and base_id != a.id:
                    try:
                        base = engine.open_analysis(base_id, settings)
                    except engine.NotFound:
                        return ctx
                    with base.connect() as bd:
                        ctx.update(base=base, drift=reports.drift(db, bd))
                return ctx
            if tab == "backends":
                return dict(backends=reports.backends(db))
            if tab == "issues":
                return dict(issues=reports.issues(db, a.meta))
            if tab == "tls":
                return dict(tls=reports.tls_health(db))
        return {}

    @app.get("/a/{aid}", response_class=HTMLResponse)
    def analysis(request: Request, aid: str, tab: str = "overview"):
        if tab not in TAB_LABELS:
            _bad(knowledge.t("This view does not exist."), 404)
        a = opened(aid)
        name = "analysis.html" if not is_htmx(request) else f"_tab_{tab}.html"
        return page(request, name, tab=tab, baseline=records.baseline(settings), **capture_ctx(a), **tab_context(a, tab))

    @app.post("/a/{aid}/notes")
    def save_notes(request: Request, aid: str, case: str = Form(""), tags: str = Form(""), note: str = Form("")):
        records.save_notes(settings, opened(aid).id, case, tags, note)
        log(request, "notes", aid)
        return RedirectResponse(f"/a/{aid}", 303)

    @app.post("/a/{aid}/baseline")
    def set_baseline(request: Request, aid: str):
        records.set_baseline(settings, opened(aid).id)
        log(request, "baseline", aid)
        return RedirectResponse(f"/a/{aid}", 303)

    @app.get("/a/{aid}/issue/{key}", response_class=HTMLResponse)
    def issue(request: Request, aid: str, key: str):
        a = opened(aid)
        with a.connect() as db:
            d = reports.issue_detail(db, key)
        if d is None:
            _bad(knowledge.t("This issue does not exist."), 404)
        return page(request, "issue.html", d=d, **capture_ctx(a))

    @app.get("/a/{aid}/conn/{stream}", response_class=HTMLResponse)
    def connection(request: Request, aid: str, stream: int, percent: bool = False):
        a = opened(aid)
        with a.connect() as db:
            d = reports.connection_top(db, stream, percent)
            if d["conn"] is None:
                _bad(knowledge.t("This connection does not exist."), 404)
            d["top"] = [reports.describe(db, t) for t in d["top"]]
        return page(request, "connection.html", d=d, percent=percent, **capture_ctx(a))

    @app.get("/a/{aid}/txn/{tid}", response_class=HTMLResponse)
    def transaction(request: Request, aid: str, tid: int):
        a = opened(aid)
        with a.connect() as db:
            t = reports.transaction(db, tid)
        if t is None:
            _bad(knowledge.t("This request does not exist."), 404)
        return page(request, "transaction.html", t=t, **capture_ctx(a))

    def inspect_filter(q):
        size_of = q.get("size_of") or "total"
        if size_of not in reports.SIZE_SQL:
            _bad(knowledge.t("Size type is not valid."))
        return reports.Inspect((q.get("src") or "").strip() or None, (q.get("dst") or "").strip() or None, _opt_int(q.get("port"), "Port"),
                               q.get("kind") or None, (q.get("url") or "").strip() or None, _opt_int(q.get("min_size"), "Size"), size_of,
                               _opt_float(q.get("start")), _opt_float(q.get("end")))

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
            _bad(knowledge.t("Give the filter a name."))
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

    @app.get("/trend", response_class=HTMLResponse)
    def trend_page(request: Request, url: str = ""):
        analyses = [engine.open_analysis(m["id"], settings) for m in engine.list_analyses(settings)]
        return page(request, "trend.html", section="trend", url=url, names=reports.url_names(analyses), rows=reports.trend(analyses, url) if url else [])

    def preferences(request, **extra):
        limits = records.thresholds(settings)
        return page(request, "preferences.html", section="preferences", limits=limits, targets="\n".join(f"{t['pattern']} {t['seconds']:g}" for t in limits["targets"]),
                    tokens=records.tokens(settings), new_token=None, error=None, **extra)

    @app.get("/preferences", response_class=HTMLResponse)
    def preferences_page(request: Request):
        return preferences(request)

    @app.post("/preferences")
    def preferences_save(request: Request, slow: str = Form(""), targets: str = Form("")):
        try:
            value = float(slow)
        except ValueError:
            _bad(knowledge.t("Enter the slow request limit in seconds."))
        if value <= 0:
            _bad(knowledge.t("Enter the slow request limit in seconds."))
        parsed, bad = records.parse_targets(targets)
        if bad:
            _bad(knowledge.t("This line is not a URL pattern and seconds: {value}", value=bad[0]))
        records.save_thresholds(settings, value, parsed)
        log(request, "thresholds")
        return RedirectResponse("/preferences", 303)

    @app.post("/tokens", response_class=HTMLResponse)
    def token_add(request: Request, name: str = Form("")):
        token = records.new_token(settings, name)
        log(request, "token_created", name)
        limits = records.thresholds(settings)
        return page(request, "preferences.html", section="preferences", limits=limits, targets="\n".join(f"{t['pattern']} {t['seconds']:g}" for t in limits["targets"]),
                    tokens=records.tokens(settings), new_token=token, error=None)

    @app.post("/tokens/{tid}/delete")
    def token_delete(request: Request, tid: str):
        records.revoke_token(settings, tid)
        log(request, "token_revoked", tid)
        return RedirectResponse("/preferences", 303)

    @app.get("/audit", response_class=HTMLResponse)
    def audit_page(request: Request, event: str = ""):
        return page(request, "audit.html", section="preferences", rows=records.read_audit(settings, event or None), event=event,
                    events=("login", "login_failed", "logout", "upload", "delete", "export", "notes", "baseline", "thresholds", "token_created", "token_revoked", "api_upload", "api_delete"))

    @app.post(API_PREFIX + "captures", status_code=202)
    async def api_upload(request: Request, capture: UploadFile, keylog: UploadFile | None = None, rsa_key: UploadFile | None = None,
                         host_a: str = Form(""), host_b: str = Form(""), port: str = Form(""), start: str = Form(""), end: str = Form(""), display_filter: str = Form("")):
        job = await accept(capture, keylog, rsa_key, host_a, host_b, port, start, end, display_filter)
        log(request, "api_upload", capture.filename)
        return dict(job=job.id, state=job.state)

    @app.get(API_PREFIX + "jobs/{jid}")
    def api_job(jid: str):
        job = jobs.get(jid)
        if job is None:
            _bad(knowledge.t("This analysis job is no longer known. Upload the capture again."), 404)
        return dict(job=job.id, state=job.state, analysis=job.analysis_id, error=job.error)

    @app.get(API_PREFIX + "analyses")
    def api_analyses():
        return [{k: m.get(k) for k in ("id", "filename", "created", "size", "packets", "connections", "transactions")} for m in engine.list_analyses(settings)]

    @app.get(API_PREFIX + "analyses/{aid}")
    def api_analysis(aid: str):
        return opened(aid).meta

    @app.delete(API_PREFIX + "analyses/{aid}")
    def api_delete(request: Request, aid: str):
        log(request, "api_delete", aid)
        engine.delete(opened(aid).id, settings)
        return dict(deleted=aid)

    @app.get(API_PREFIX + "analyses/{aid}/{section}")
    def api_section(aid: str, section: str):
        if section not in API_SECTIONS:
            _bad(knowledge.t("Unknown data set."), 404)
        a = opened(aid)
        with a.connect() as db:
            return JSONResponse(json.loads(json.dumps({"overview": lambda: reports.overview(db, a.meta), "urls": lambda: reports.url_groups(db), "connections": lambda: reports.connections(db),
                                                       "hosts": lambda: reports.hosts(db), "issues": lambda: reports.issues(db, a.meta), "slowest": lambda: reports.slowest(db)}[section](), default=str)))

    @app.get("/capture-guide", response_class=HTMLResponse)
    def guide_page(request: Request):
        q = dict(request.query_params)
        server, client = _ip(q.get("server"), "Server"), _ip(q.get("client"), "Client")
        seconds = _opt_int(q.get("seconds"), "Seconds") or capture_guide.DEFAULT_SECONDS
        if not 1 <= seconds <= MAX_CAPTURE_S:
            _bad(knowledge.t("Seconds must be between 1 and {n}.", n=MAX_CAPTURE_S))
        names = {k: (q.get(k) or "").strip() or d for k, d in (("namespace", "default"), ("pod", "POD"), ("container", "CONTAINER"), ("interface", "any"), ("image", capture_guide.DEFAULT_IMAGE))}
        points = capture_guide.commands(server, _opt_int(q.get("port"), "Port"), client, seconds, settings.max_size_mb, **names)
        return page(request, "capture_guide.html", section="guide", q=q, points=points, seconds=seconds, max_mb=settings.max_size_mb)

    @app.get("/export/{aid}/report.html")
    def export_report(request: Request, aid: str):
        a = opened(aid)
        log(request, "export", f"{aid} report")
        with a.connect() as db:
            ctx = dict(a=a, m=a.meta, o=reports.overview(db, a.meta), budget=reports.time_budget(db), issues=reports.issues(db, a.meta), urls=reports.url_groups(db),
                       slow=reports.slowest(db), quality=reports.quality(a.meta), backends=reports.backends(db), notes=records.notes(settings, aid), css=(HERE / "static/app.css").read_text())
        html = templates.get_template("report.html").render(ctx)
        return Response(html, media_type="text/html; charset=utf-8", headers=_attachment(a, "report.html"))

    @app.get("/export/{aid}/requests.har")
    def export_har(request: Request, aid: str):
        a = opened(aid)
        log(request, "export", f"{aid} har")
        flt = inspect_filter(dict(request.query_params))
        return StreamingResponse(_streamed(a, lambda db: exports.har_chunks(db, flt)), media_type="application/json", headers=_attachment(a, "requests.har"))

    @app.get("/export/{aid}/{name}.{fmt}")
    def export_table(request: Request, aid: str, name: str, fmt: str):
        a = opened(aid)
        log(request, "export", f"{aid} {name}.{fmt}")
        if name not in exports.TABLES or fmt not in exports.FORMATS:
            _bad(knowledge.t("This export does not exist."), 404)
        return StreamingResponse(_streamed(a, lambda db: exports.render_chunks(exports.each_row(db, name, a.meta), fmt)), media_type=exports.FORMATS[fmt],
                                 headers=_attachment(a, f"{name}.{fmt}"))

    @app.get("/export/{aid}/conn/{stream}.pcapng")
    def export_stream(request: Request, aid: str, stream: int):
        a = opened(aid)
        log(request, "export", f"{aid} connection {stream}")
        capture = a.dir / "capture"
        if not capture.exists():
            _bad(knowledge.t("The original capture was not kept, so packets cannot be exported."), 404)
        with a.connect() as db:
            if not reports.one(db, "SELECT stream FROM tcp_connections WHERE stream = ?", [stream]):
                _bad(knowledge.t("This connection does not exist."), 404)
            where = reports.one(db, "SELECT part, part_stream FROM stream_parts WHERE stream = ?", [stream]) if a.meta.get("parts") else None
        feed, number = None, stream
        if where:  # a capture read in parts: only the part that holds this connection goes through tshark
            plan = split.plan(capture, a.meta["parts"])
            feed, number = (lambda: split.feed(capture, plan, where["part"])), where["part_stream"]
        with tempfile.TemporaryDirectory(prefix="pcap-export-", dir="/tmp") as tmp:
            out = Path(tmp) / "out.pcapng"
            try:
                tshark.extract_stream(capture, number, out, settings.tshark, feed)
            except tshark.TsharkError as e:
                _bad(str(e), 500)
            body = out.read_bytes()
        return Response(body, media_type="application/vnd.tcpdump.pcap", headers=_attachment(a, f"connection-{stream}.pcapng"))

    @app.get("/api/a/{aid}/waterfall/{stream}")
    def api_waterfall(aid: str, stream: int):
        a = opened(aid)
        with a.connect() as db:
            data = reports.waterfall(db, stream)
        if data is None:
            _bad(knowledge.t("This connection does not exist."), 404)
        return data

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
            elif what == "timeline":
                data = reports.timeline(db)
            else:
                _bad(knowledge.t("Unknown data set."), 404)
        return data

    return app


def _streamed(a, make):
    """An export written while it is read from the database, so a large analysis does not sit in memory."""
    with a.connect() as db:
        yield from make(db)


def _attachment(a, name):
    stem = re.sub(r"[^A-Za-z0-9._-]+", "_", a.meta["filename"])[:60]
    return {"Content-Disposition": f'attachment; filename="{stem}-{name}"'}


def _escape(text):
    return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
