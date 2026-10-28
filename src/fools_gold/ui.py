"""Loopback-only authenticated dashboard. No files are served from disk.

Authentication is either a bearer token (scripts, API) or a short-lived
server-side session created from the login form. The token never appears in a
URL, log line, or persistent browser storage; the session cookie is HttpOnly
and SameSite=Strict.
"""

import hmac
import html
import json
import secrets
import threading
import time
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlencode, urlparse

from .assurance import assurance_report
from .core import ContractError, canonical, instant
from .reporting import incidents

MAX_BODY_BYTES = 4096
SESSION_TTL_SECONDS = 8 * 3600
MAX_SESSIONS = 1000
DEFAULT_PAGE_SIZE = 25
MAX_PAGE_SIZE = 100
COOKIE_NAME = "fg_session"
LOOPBACK_HOST = "127.0.0.1"
SOURCES = ("aws.cloudtrail.s3", "windows.security", "linux.audit")


class SessionStore:
    def __init__(self):
        self.lock = threading.Lock()
        self.entries = {}

    def create(self):
        sid = secrets.token_urlsafe(32)
        csrf = secrets.token_urlsafe(24)
        with self.lock:
            now = time.monotonic()
            for key in [k for k, (expiry, _) in self.entries.items() if expiry <= now]:
                del self.entries[key]
            while len(self.entries) >= MAX_SESSIONS:
                self.entries.pop(next(iter(self.entries)))
            self.entries[sid] = (now + SESSION_TTL_SECONDS, csrf)
        return sid, csrf

    def csrf(self, sid):
        with self.lock:
            entry = self.entries.get(sid)
            if entry is None:
                return None
            if entry[0] <= time.monotonic():
                del self.entries[sid]
                return None
            return entry[1]

    def drop(self, sid):
        with self.lock:
            self.entries.pop(sid, None)


def _escape(value):
    return html.escape(str(value), quote=True)


def _metrics(engine) -> str:
    counts = engine.report()
    outbox = engine.outbox_report()["outbox"]
    last = engine.last_assurance()
    rows = engine.db.execute(
        "SELECT MIN(updated_at) FROM outbox WHERE state='pending'"
    ).fetchone()
    oldest_pending = rows[0] if rows else None
    lines = [
        "# HELP fools_gold_alerts_total Retained alerts",
        "# TYPE fools_gold_alerts_total gauge",
        f"fools_gold_alerts_total {counts['decisions']['alert']}",
        f"fools_gold_alerts_acknowledged {counts['alerts_acknowledged']}",
    ]
    for payload_format, states in sorted(outbox.items()):
        for state, value in sorted(states.items()):
            lines.append(
                f'fools_gold_outbox{{format="{payload_format}",state="{state}"}} {value}'
            )
    if oldest_pending:
        age = (datetime.now(UTC) - instant(oldest_pending)).total_seconds()
        lines.append(f"fools_gold_outbox_oldest_pending_age_seconds {age:.0f}")
    lines.append(f"fools_gold_assurance_last_ok {1 if last and last['ok'] else 0}")
    return "\n".join(lines) + "\n"


def _layout(title, body, *, csrf=None, authenticated=False) -> str:
    logout = (
        "<a href='/logout'>log out</a>" if authenticated else ""
    )
    return (
        "<!doctype html><html><head><meta charset='utf-8'>"
        f"<title>{_escape(title)}</title><style>"
        "body{font-family:system-ui,sans-serif;margin:2rem;color:#1b1b1b}"
        ".cards{display:flex;gap:1rem;flex-wrap:wrap;margin:1rem 0}"
        ".card{border:1px solid #ccc;border-radius:6px;padding:.6rem .9rem;"
        "font-size:.85rem;min-width:9rem}"
        ".card b{display:block;font-size:1.2rem}"
        "table{border-collapse:collapse;width:100%;margin-top:1rem}"
        "th,td{border:1px solid #ccc;padding:.35rem .5rem;font-size:.85rem;"
        "text-align:left;vertical-align:top}"
        "th{background:#f2f2f2}nav a{margin-right:1rem}"
        "form.inline{display:inline}pre{background:#f6f6f6;padding:1rem;"
        "overflow:auto;font-size:.8rem}"
        "</style></head><body>"
        f"<nav><a href='/'>alerts</a><a href='/incidents'>incidents</a>"
        f"<a href='/metrics'>metrics</a>{logout}</nav>"
        f"<h1>{_escape(title)}</h1>{body}</body></html>\n"
    )


def _summary(engine) -> str:
    counts = engine.report()
    outbox = engine.outbox_report()["outbox"]
    last = engine.last_assurance()
    integrity = "not configured"
    if engine.mac_key is not None:
        integrity = "ok" if engine.verify_integrity()["ok"] else "FAILED"
    pending = sum(states.get("pending", 0) for states in outbox.values())
    failed = sum(states.get("failed", 0) for states in outbox.values())
    assurance = (
        ("ok" if last["ok"] else "failed") + f" @ {last['ran_at']}"
        if last
        else "never run"
    )
    return (
        "<div class='cards'>"
        f"<div class='card'>alerts<b>{counts['decisions']['alert']}</b></div>"
        f"<div class='card'>acknowledged<b>{counts['alerts_acknowledged']}</b></div>"
        f"<div class='card'>delivery pending<b>{pending}</b></div>"
        f"<div class='card'>delivery failed<b>{failed}</b></div>"
        f"<div class='card'>integrity<b>{_escape(integrity)}</b></div>"
        f"<div class='card'>assurance<b>{_escape(assurance)}</b></div>"
        "</div>"
    )


def _alert_filters(engine, params):
    clauses, values = [], []
    term = params.get("q", [""])[0].strip()
    if term:
        like = f"%{term[:128]}%"
        clauses.append("(actor LIKE ? OR decoy LIKE ? OR evidence LIKE ?)")
        values += [like, like, like]
    source = params.get("source", [""])[0]
    if source:
        if source not in SOURCES:
            raise ContractError("unknown source filter")
        clauses.append("json_extract(evidence,'$.event.source') = ?")
        values.append(source)
    decoy = params.get("decoy", [""])[0].strip()
    if decoy:
        clauses.append("decoy = ?")
        values.append(decoy[:128])
    route = params.get("route", [""])[0].strip()
    if route:
        clauses.append("route = ?")
        values.append(route[:64])
    ack = params.get("ack", [""])[0]
    if ack == "yes":
        clauses.append("acknowledged_at IS NOT NULL")
    elif ack == "no":
        clauses.append("acknowledged_at IS NULL")
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    return where, values


def _page_params(params):
    def number(name, default, low, high):
        raw = params.get(name, [str(default)])[0]
        if not raw.isdigit():
            raise ContractError(f"invalid {name}")
        value = int(raw)
        if not low <= value <= high:
            raise ContractError(f"{name} must be {low} to {high}")
        return value

    return number("page", 1, 1, 100000), number(
        "page_size", DEFAULT_PAGE_SIZE, 1, MAX_PAGE_SIZE
    )


def _alerts_page(engine, params, *, csrf) -> str:
    where, values = _alert_filters(engine, params)
    page, page_size = _page_params(params)
    # Bound parameters only; `where` is assembled from fixed fragments.
    total = engine.db.execute(  # nosemgrep: python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query
        "SELECT COUNT(*) FROM alerts" + where, values
    ).fetchone()[0]
    rows = engine.db.execute(  # nosemgrep: python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query
        "SELECT id,decoy,actor,received_at,acknowledged_at,evidence,route "
        "FROM alerts" + where + " ORDER BY received_at DESC, id DESC "
        "LIMIT ? OFFSET ?",
        values + [page_size, (page - 1) * page_size],
    ).fetchall()
    filters = (
        "<form method='get' action='/'>"
        f"<input name='q' placeholder='search' value='{_escape(params.get('q', [''])[0])}'>"
        "<select name='source'><option value=''>any source</option>"
        + "".join(
            f"<option value='{_escape(source)}'"
            + (" selected" if params.get("source", [""])[0] == source else "")
            + f">{_escape(source)}</option>"
            for source in SOURCES
        )
        + "</select>"
        f"<input name='decoy' placeholder='decoy id' value='{_escape(params.get('decoy', [''])[0])}'>"
        f"<input name='route' placeholder='route' value='{_escape(params.get('route', [''])[0])}'>"
        "<select name='ack'><option value=''>any</option>"
        "<option value='no'" + (" selected" if params.get("ack", [""])[0] == "no" else "") + ">unacknowledged</option>"
        "<option value='yes'" + (" selected" if params.get("ack", [""])[0] == "yes" else "") + ">acknowledged</option>"
        "</select><button type='submit'>filter</button></form>"
    )
    body = [_summary(engine), filters, "<table><thead><tr><th>Received</th>"
            "<th>Decoy</th><th>Actor</th><th>Route</th><th>Ack</th>"
            "<th>Actions</th></tr></thead><tbody>"]
    for alert_id, decoy, actor, received, acknowledged, evidence, route in rows:
        alert = json.loads(evidence)
        actions = ", ".join(alert["event"]["actions"])
        body.append(
            "<tr>"
            f"<td>{_escape(received)}</td>"
            f"<td><a href='/alert/{_escape(alert_id)}'>{_escape(decoy)}</a></td>"
            f"<td>{_escape(actor)}</td>"
            f"<td>{_escape(route or '')}</td>"
            f"<td>{_escape(acknowledged or 'no')}</td>"
            f"<td>{_escape(actions)}<form class='inline' method='post' "
            "action='/acknowledge'>"
            f"<input type='hidden' name='alert_id' value='{_escape(alert_id)}'>"
            f"<input type='hidden' name='csrf' value='{_escape(csrf or '')}'>"
            "<input name='analyst' placeholder='analyst' size='8'>"
            "<button type='submit'>ack</button></form></td>"
            "</tr>"
        )
    body.append("</tbody></table>")
    pages = max(1, (total + page_size - 1) // page_size)
    query = {
        key: params.get(key, [""])[0]
        for key in ("q", "source", "decoy", "route", "ack")
        if params.get(key, [""])[0]
    }
    links = []
    for number in sorted({1, page - 1, page, page + 1, pages}):
        if 1 <= number <= pages:
            links.append(
                f"<a href='/?{_escape(urlencode({**query, 'page': number, 'page_size': page_size}))}'>"
                f"{number}</a>"
            )
    body.append(
        f"<p>page {page} of {pages} ({total} alerts)</p><p>{' '.join(links)}</p>"
    )
    return _layout("Fool's Gold", "".join(body), csrf=csrf, authenticated=True)


def _alert_detail(engine, alert_id, *, csrf) -> str:
    row = engine.db.execute(
        "SELECT id,decoy,actor,opened_at,received_at,acknowledged_at,"
        "acknowledged_by,evidence,route FROM alerts WHERE id=?",
        (alert_id,),
    ).fetchone()
    if row is None:
        return _layout("Not found", "<p>No such alert.</p>", csrf=csrf, authenticated=True)
    (
        identifier,
        decoy,
        actor,
        opened_at,
        received_at,
        acknowledged_at,
        acknowledged_by,
        evidence,
        route,
    ) = row
    alert = json.loads(evidence)
    delivery = engine.db.execute(
        "SELECT payload_format,state,attempts,updated_at,last_error FROM outbox "
        "WHERE alert_id=? ORDER BY payload_format",
        (alert_id,),
    ).fetchall()
    rows = "".join(
        "<tr>"
        f"<td>{_escape(fmt)}</td><td>{_escape(state)}</td>"
        f"<td>{_escape(attempts)}</td><td>{_escape(updated)}</td>"
        f"<td>{_escape(error or '')}</td></tr>"
        for fmt, state, attempts, updated, error in delivery
    )
    ack = (
        f"<p>Acknowledged by {_escape(acknowledged_by)} at "
        f"{_escape(acknowledged_at)}</p>"
        if acknowledged_at
        else (
            "<form method='post' action='/acknowledge'>"
            f"<input type='hidden' name='alert_id' value='{_escape(identifier)}'>"
            f"<input type='hidden' name='csrf' value='{_escape(csrf or '')}'>"
            "<input name='analyst' placeholder='analyst'>"
            "<button type='submit'>acknowledge</button></form>"
        )
    )
    delivery_rows = rows or (
        "<tr><td colspan='5'>not enqueued</td></tr>"
    )
    body = (
        "<div class='cards'>"
        f"<div class='card'>event time<b>{_escape(alert['event']['time'])}</b></div>"
        f"<div class='card'>received<b>{_escape(alert['observed_at'])}</b></div>"
        f"<div class='card'>opened<b>{_escape(opened_at)}</b></div>"
        f"<div class='card'>acknowledged<b>{_escape(acknowledged_at or 'no')}</b></div>"
        "</div>"
        f"<p>decoy <b>{_escape(decoy)}</b> &middot; actor <b>{_escape(actor)}</b>"
        f" &middot; route <b>{_escape(route or '')}</b></p>"
        f"{ack}"
        "<h2>Delivery</h2><table><thead><tr><th>Format</th><th>State</th>"
        f"<th>Attempts</th><th>Updated</th><th>Error</th></tr></thead><tbody>"
        f"{delivery_rows}</tbody></table>"
        "<h2>Evidence</h2>"
        f"<pre>{_escape(json.dumps(alert, indent=2, sort_keys=True))}</pre>"
        "<p><a href='/'>back</a></p>"
    )
    return _layout(f"Alert {identifier}", body, csrf=csrf, authenticated=True)


def _login_page(error="") -> str:
    error_html = f"<p role='alert'>{_escape(error)}</p>" if error else ""
    return _layout(
        "Fool's Gold login",
        "<form method='post' action='/login'>"
        "<label>Access token <input type='password' name='token' autofocus></label>"
        "<button type='submit'>sign in</button></form>" + error_html,
    )


def make_server(engine, token: str, port: int = 0) -> HTTPServer:
    if (
        not isinstance(token, str)
        or not 16 <= len(token) <= 256
        or any(ord(c) < 32 for c in token)
    ):
        raise ContractError(
            "dashboard token must be 16 to 256 printable characters"
        )
    if type(port) is not int or not 0 <= port <= 65535:
        raise ContractError("dashboard port must be an integer from 0 to 65535")
    lock = threading.Lock()
    sessions = SessionStore()

    class Handler(BaseHTTPRequestHandler):
        def setup(self):
            super().setup()
            try:
                self.connection.settimeout(10)
            except OSError:
                pass

        def _send(self, status, body: bytes, content_type: str, headers=None):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Cache-Control", "no-store")
            for name, value in (headers or {}).items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(body)

        def _json(self, status, value):
            self._send(status, canonical(value).encode(), "application/json")

        def _html(self, status, value, headers=None):
            self._send(
                200 if status == 200 else status,
                value.encode(),
                "text/html; charset=utf-8",
                headers,
            )

        def _redirect(self, location, headers=None):
            self._send(
                303, b"", "text/plain; charset=utf-8",
                {"Location": location, **(headers or {})},
            )

        def _bearer(self):
            header = self.headers.get("Authorization", "")
            return header.startswith("Bearer ") and hmac.compare_digest(
                header[7:], token
            )

        def _session(self):
            cookie = self.headers.get("Cookie", "")
            for part in cookie.split(";"):
                name, _, value = part.strip().partition("=")
                if name == COOKIE_NAME and value:
                    csrf = sessions.csrf(value)
                    if csrf is not None:
                        return value, csrf
            return None

        def _authorized(self):
            return self._bearer() or self._session() is not None

        def _read_form(self):
            length = self.headers.get("Content-Length", "")
            if not length.isdigit() or int(length) > MAX_BODY_BYTES:
                raise ContractError("invalid content length")
            body = self.rfile.read(int(length)).decode("utf-8", "replace")
            return {key: values[0] for key, values in parse_qs(body).items()}

        def do_GET(self):
            parsed = urlparse(self.path)
            path, query = parsed.path, parse_qs(parsed.query)
            if path == "/healthz":
                return self._json(200, {"ok": True})
            if path == "/login":
                return self._html(200, _login_page())
            if not self._authorized():
                if path.startswith("/api/") or path == "/metrics":
                    return self._json(401, {"error": "unauthorized"})
                return self._redirect("/login")
            session = self._session()
            csrf = session[1] if session else None
            with lock:
                if path == "/":
                    try:
                        return self._html(
                            200, _alerts_page(engine, query, csrf=csrf)
                        )
                    except ContractError as exc:
                        return self._html(
                            400,
                            _layout(
                                "Bad request",
                                f"<p>{_escape(exc)}</p><p><a href='/'>back</a></p>",
                                csrf=csrf,
                                authenticated=True,
                            ),
                        )
                if path.startswith("/alert/"):
                    return self._html(
                        200, _alert_detail(engine, path[len("/alert/"):], csrf=csrf)
                    )
                if path == "/incidents":
                    data = incidents(engine)
                    rows = "".join(
                        "<tr>"
                        f"<td>{_escape(item['actor'])}</td>"
                        f"<td>{_escape(item['first_seen'])}</td>"
                        f"<td>{_escape(item['last_seen'])}</td>"
                        f"<td>{_escape(item['alert_count'])}</td>"
                        f"<td>{_escape(', '.join(item['decoys']))}</td>"
                        f"<td>{_escape(', '.join(item['mitre_techniques']))}</td>"
                        f"<td>{_escape(item['acknowledged'])}</td></tr>"
                        for item in data["incidents"]
                    )
                    return self._html(
                        200,
                        _layout(
                            "Incidents",
                            "<table><thead><tr><th>Actor</th><th>First</th>"
                            "<th>Last</th><th>Alerts</th><th>Decoys</th>"
                            f"<th>ATT&amp;CK</th><th>Ack</th></tr></thead><tbody>{rows}</tbody></table>",
                            csrf=csrf,
                            authenticated=True,
                        ),
                    )
                if path == "/logout":
                    if session:
                        sessions.drop(session[0])
                    return self._redirect(
                        "/login",
                        {"Set-Cookie": f"{COOKIE_NAME}=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict"},
                    )
                if path == "/api/alerts":
                    limit_param = query.get("limit", ["200"])[0]
                    if not limit_param.isdigit() or not 1 <= int(limit_param) <= 5000:
                        return self._json(400, {"error": "limit must be 1 to 5000"})
                    alerts = [
                        json.loads(row[0])
                        for row in engine.db.execute(
                            "SELECT evidence FROM alerts "
                            "ORDER BY received_at DESC LIMIT ?",
                            (int(limit_param),),
                        )
                    ]
                    return self._json(200, {"alerts": alerts})
                if path == "/api/report":
                    return self._json(200, engine.report())
                if path == "/api/integrity":
                    if engine.mac_key is None:
                        return self._json(200, {"configured": False})
                    return self._json(200, engine.verify_integrity())
                if path == "/api/incidents":
                    return self._json(200, incidents(engine))
                if path == "/api/assurance":
                    return self._json(200, assurance_report(engine))
                if path == "/metrics":
                    return self._send(
                        200, _metrics(engine).encode(), "text/plain; version=0.0.4"
                    )
            return self._json(404, {"error": "not found"})

        def do_POST(self):
            path = urlparse(self.path).path
            if path == "/login":
                try:
                    form = self._read_form()
                    supplied = form.get("token", "")
                except ContractError:
                    return self._html(400, _login_page("invalid request"))
                if not hmac.compare_digest(supplied, token):
                    return self._html(401, _login_page("invalid token"))
                sid, _csrf = sessions.create()
                return self._redirect(
                    "/",
                    {
                        "Set-Cookie": (
                            f"{COOKIE_NAME}={sid}; Path=/; HttpOnly; SameSite=Strict"
                        )
                    },
                )
            if not self._authorized():
                return self._json(401, {"error": "unauthorized"})
            if path == "/api/acknowledge":
                return self._api_acknowledge()
            if path == "/acknowledge":
                return self._form_acknowledge()
            return self._json(404, {"error": "not found"})

        def _api_acknowledge(self):
            if not self._bearer():
                return self._json(401, {"error": "bearer token required"})
            length = self.headers.get("Content-Length", "")
            if not length.isdigit() or int(length) > MAX_BODY_BYTES:
                return self._json(400, {"error": "invalid content length"})
            try:
                payload = json.loads(self.rfile.read(int(length)))
                if not isinstance(payload, dict):
                    raise ContractError("acknowledgment body must be an object")
                with lock:
                    engine.acknowledge(
                        payload["alert_id"], payload["analyst"], datetime.now(UTC)
                    )
            except (KeyError, TypeError, ValueError, ContractError) as exc:
                return self._json(400, {"error": str(exc)})
            return self._json(200, {"acknowledged": True})

        def _form_acknowledge(self):
            session = self._session()
            if session is None:
                return self._redirect("/login")
            try:
                form = self._read_form()
                if not hmac.compare_digest(form.get("csrf", ""), session[1]):
                    return self._html(400, _login_page("invalid session token"))
                with lock:
                    engine.acknowledge(
                        form["alert_id"], form["analyst"], datetime.now(UTC)
                    )
            except (KeyError, TypeError, ValueError, ContractError):
                return self._redirect("/")
            return self._redirect(f"/alert/{form['alert_id']}")

        def log_message(self, *_args):
            pass

    return HTTPServer((LOOPBACK_HOST, port), Handler)
