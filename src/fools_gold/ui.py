"""Local operations console for Fool's Gold.

Server-rendered HTML with a single inline stylesheet: no external assets,
scripts from other origins, analytics or client-side storage of secrets.
Authentication is a bearer token (scripts/API) or a short-lived server-side
session created from the login form. The token never appears in a URL or log.
"""

import hmac
import html
import json
import secrets
import threading
import time
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse

from .assurance import assurance_report
from .core import ContractError, canonical, instant
from .reporting import incidents
from .ui_assets import MARK, MASCOT_BYTES, MASCOT_ETAG, MASCOT_PATH, STYLES

MAX_BODY_BYTES = 4096
SESSION_TTL_SECONDS = 8 * 3600
MAX_SESSIONS = 1000
DEFAULT_PAGE_SIZE = 25
MAX_PAGE_SIZE = 100
COOKIE_NAME = "fg_session"
LOOPBACK_HOST = "127.0.0.1"
SOURCES = ("aws.cloudtrail.s3", "windows.security", "linux.audit")

SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; "
        "form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
    ),
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
}

NAV = (
    ("overview", "Overview", "/"),
    ("alerts", "Alerts", "/alerts"),
    ("incidents", "Incidents", "/incidents"),
    ("assurance", "Assurance", "/assurance"),
    ("evidence", "Evidence", "/evidence"),
)

SOURCE_LABELS = {
    "aws.cloudtrail.s3": "AWS S3",
    "windows.security": "Windows",
    "linux.audit": "Linux",
}
RESOURCE_NOUNS = {
    "aws.cloudtrail.s3": "S3 object",
    "windows.security": "Windows file",
    "linux.audit": "Linux file",
}
ACTION_WORDS = {
    "read": "read",
    "write": "write",
    "append": "append",
    "delete": "delete",
    "recon": "enumerated",
}
STAGE_LABELS = (
    ("synthetic", "Synthetic canary"),
    ("live", "Live sensor"),
    ("transport", "Transport acceptance"),
    ("ingestion", "SIEM ingestion (external)"),
    ("analyst_acknowledgment", "Analyst acknowledgment"),
)
DELIVERY_TONES = {
    "sent": ("Accepted", "ok"),
    "pending": ("Pending", "warn"),
    "failed": ("Failed", "bad"),
}


class SessionStore:
    def __init__(self):
        self.lock = threading.Lock()
        self.entries = {}

    def create(self):
        sid = secrets.token_urlsafe(32)
        csrf = secrets.token_urlsafe(24)
        with self.lock:
            now = time.monotonic()
            for key in [
                key for key, (expiry, _) in self.entries.items() if expiry <= now
            ]:
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


def _e(value) -> str:
    return html.escape(str(value if value is not None else ""), quote=True)


def _human_time(value) -> str:
    try:
        moment = instant(value)
    except (ContractError, TypeError, ValueError):
        return str(value or "—")
    return moment.strftime("%d %b %Y, %H:%M UTC")


def _relative(value, now) -> str:
    try:
        moment = instant(value)
    except (ContractError, TypeError, ValueError):
        return ""
    seconds = (now - moment).total_seconds()
    if seconds < 0:
        return "just now"
    if seconds < 90:
        return "moments ago"
    if seconds < 3600:
        return f"{int(seconds // 60)} min ago"
    if seconds < 36 * 3600:
        return f"{int(seconds // 3600)} h ago"
    return f"{int(seconds // 86400)} d ago"


def _source_label(source) -> str:
    return SOURCE_LABELS.get(source, "Unknown source")


def _actor_label(actor) -> str:
    if not actor:
        return "Unknown actor"
    if actor.startswith("arn:"):
        if ":assumed-role/" in actor:
            tail = actor.split(":assumed-role/", 1)[1]
            parts = tail.split("/")
            if len(parts) > 1:
                return f"{parts[0]} / {parts[1]}"
            return parts[0]
        return actor.rsplit("/", 1)[-1]
    if actor.startswith("uid:"):
        return f"uid {actor[4:]}"
    return actor


def _resource_label(alert) -> str:
    locator = (alert.get("event") or {}).get("locator") or {}
    if locator.get("arn"):
        return locator["arn"].rsplit("/", 1)[-1] or locator["arn"]
    if locator.get("path"):
        path = str(locator["path"]).replace("\\", "/")
        return path.rsplit("/", 1)[-1] or path
    return alert.get("decoy_id", "")


def _summary_title(alert) -> str:
    event = alert.get("event") or {}
    noun = RESOURCE_NOUNS.get(event.get("source"), "Decoy")
    actions = event.get("actions") or []
    words = [ACTION_WORDS.get(action, action) for action in actions]
    title = f"{noun} {', '.join(words) if words else 'access'}"
    return title + (" denied" if event.get("outcome") == "denied" else "")


def _badge(label, tone="neutral", dot=False) -> str:
    dot_html = "<span class='dot' aria-hidden='true'></span>" if dot else ""
    return (
        f"<span class='badge badge-{tone}'>{dot_html}{_e(label)}</span>"
    )


def _ack_badge(acknowledged_at) -> str:
    if acknowledged_at:
        return _badge("Acknowledged", "ok", dot=True)
    return _badge("Unacknowledged", "warn", dot=True)


def _outcome_badge(event) -> str:
    if event.get("outcome") == "denied":
        return _badge("Access denied", "warn")
    return _badge("Access succeeded", "bad")


def _delivery_badge(state) -> str:
    label, tone = DELIVERY_TONES.get(
        state, (state.replace("_", " ").title() if state else "Not queued", "neutral")
    )
    return _badge(label, tone)


def _stage_badge(status) -> str:
    mapping = {
        "pass": ("Passed", "ok"),
        "fail": ("Failed", "bad"),
        "not_run": ("Not run", "neutral"),
        "unverified": ("Unverified", "warn"),
        "operator_verified": ("Operator verified", "ok"),
    }
    label, tone = mapping.get(status, ("Unknown", "neutral"))
    return _badge(label, tone)


def _nav(active) -> str:
    links = []
    for key, label, href in NAV:
        current = ' aria-current="page"' if key == active else ""
        links.append(
            f"<a class='nav-link' href='{href}'{current}>"
            "<span class='nav-glyph' aria-hidden='true'></span>"
            f"{_e(label)}</a>"
        )
    return "".join(links)


def _shell(title, active, body, *, purpose="", meta="") -> str:
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        f"<link rel='icon' type='image/png' href='{MASCOT_PATH}'>"
        f"<title>{_e(title)} · Fool's Gold</title>"
        f"<style>{STYLES}</style></head><body>"
        "<a class='skip-link' href='#main'>Skip to content</a>"
        "<div class='shell'>"
        "<aside class='rail'>"
        "<a class='brand' href='/'>"
        f"{MARK}<span class='brand-text'><span class='brand-name'>Fool's Gold</span>"
        "<span class='brand-tag'>Decoy operations</span></span></a>"
        f"<nav class='nav' aria-label='Primary'>{_nav(active)}</nav>"
        "<div class='rail-foot'><p>Local console · single operator session</p>"
        "<a class='inline-link' href='/logout'>Log out</a></div>"
        "</aside>"
        "<div class='main'>"
        "<header class='topbar'><div>"
        f"<h1>{_e(title)}</h1>"
        + (f"<p class='purpose'>{purpose}</p>" if purpose else "")
        + "</div>"
        f"<div class='topbar-meta'>{meta}</div></header>"
        f"<main id='main' class='content'>{body}</main>"
        "</div></div></body></html>\n"
    )


def _login_page(error="") -> str:
    error_html = (
        f"<div class='form-error' role='alert'>{_e(error)}</div>" if error else ""
    )
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        f"<link rel='icon' type='image/png' href='{MASCOT_PATH}'>"
        "<title>Fool's Gold login</title>"
        f"<style>{STYLES}</style></head><body>"
        "<div class='login-shell'><main class='login-card'>"
        "<div class='login-brand'>"
        f"{MARK}<span class='brand-text'><span class='brand-name'>Fool's Gold</span>"
        "<span class='brand-tag'>Decoy operations</span></span></div>"
        "<h1 class='login-title'>Log in</h1>"
        "<p class='login-sub'>Operations console for the local Fool's Gold "
        "evidence database.</p>"
        "<form class='login-form' method='post' action='/login'>"
        "<div class='field'><label for='token'>Access token</label>"
        "<input class='input' id='token' name='token' type='password' "
        "autocomplete='current-password' required autofocus></div>"
        "<button class='btn' type='submit'>Sign in</button></form>"
        + error_html
        + "<p class='login-foot'>The token is configured on the server "
        "(FG_UI_TOKEN or --token-file) and is never shown here. Login sessions "
        "expire after eight hours.</p>"
        "</main></div></body></html>\n"
    )


def _metric_card(label, value, scope, href, *, tone="") -> str:
    tone_class = f" metric-{tone}" if tone else ""
    return (
        f"<article class='card{tone_class}'>"
        f"<div class='card-label'>{_e(label)}</div>"
        f"<div class='card-value'>{_e(value)}</div>"
        f"<p class='card-scope'>{_e(scope)}</p>"
        f"<p class='card-link'><a href='{_e(href)}'>View</a></p></article>"
    )


def _alert_row(alert_id, decoy, actor, received_at, acknowledged_at, evidence, now):
    try:
        alert = json.loads(evidence)
    except (TypeError, ValueError):
        alert = {}
    event = alert.get("event") or {}
    title = _summary_title(alert) if alert else "Decoy alert"
    meta = (
        f"<span class='src-chip'>{_e(_source_label(event.get('source')))}</span>"
        f"<span class='truncate' title='{_e(_resource_label(alert) or decoy)}'>"
        f"{_e(_resource_label(alert) or decoy)}</span>"
        f"<span class='sep' aria-hidden='true'>·</span>"
        f"<span class='truncate' title='{_e(actor)}'>{_e(_actor_label(actor))}</span>"
    )
    return (
        "<article class='alert-row'>"
        "<div class='alert-main'>"
        f"<div class='alert-title'><a href='/alert/{_e(alert_id)}'>{_e(title)}</a>"
        f"{_ack_badge(acknowledged_at)}</div>"
        f"<p class='alert-meta'>{meta}</p></div>"
        "<div class='alert-side'>"
        f"<div class='alert-when'><time datetime='{_e(received_at)}'>"
        f"{_e(_human_time(received_at))}</time>"
        f"<span class='small'>{_e(_relative(received_at, now))}</span></div>"
        f"<a class='btn btn-small' href='/alert/{_e(alert_id)}'>Investigate</a>"
        "</div></article>"
    )


def _empty(title, detail, action_html="") -> str:
    return (
        "<div class='empty'>"
        f"<strong>{_e(title)}</strong><span>{_e(detail)}</span>"
        + (f"<div style='margin-top:12px'>{action_html}</div>" if action_html else "")
        + "</div>"
    )


def _fetch(engine, sql, values):
    return engine.db.execute(sql, values).fetchall()


def _now():
    return datetime.now(UTC)


def _overview(engine, *, csrf):
    now = _now()
    retained = _fetch(engine, "SELECT COUNT(*) FROM alerts", ())[0][0]
    unacked = _fetch(
        engine, "SELECT COUNT(*) FROM alerts WHERE acknowledged_at IS NULL", ()
    )[0][0]
    outbox = engine.outbox_report()["outbox"]
    pending = sum(states.get("pending", 0) for states in outbox.values())
    failed = sum(states.get("failed", 0) for states in outbox.values())
    oldest_pending = _fetch(
        engine,
        "SELECT MIN(updated_at) FROM outbox WHERE state='pending'",
        (),
    )[0][0]
    last = engine.last_assurance()
    integrity = engine.verify_integrity() if engine.mac_key is not None else None
    integrity_label = "Not configured"
    integrity_tone = ""
    integrity_scope = "No evidence key supplied; hashes are comparison aids only."
    if integrity is not None:
        if integrity["ok"]:
            integrity_label = "Verified"
            integrity_tone = "ok"
            integrity_scope = f"{integrity['alerts']} alerts in the signed chain."
        else:
            integrity_label = "Failing"
            integrity_tone = "bad"
            integrity_scope = f"{len(integrity['failures'])} integrity failures."
    assurance_label = "Never run"
    assurance_tone = "warn"
    assurance_scope = "No assurance run has been recorded."
    if last is not None:
        assurance_label = "Passed" if last["ok"] else "Failed"
        assurance_tone = "ok" if last["ok"] else "bad"
        assurance_scope = (
            f"{last['mode'].title()} mode · "
            f"{_relative(last['ran_at'], now)}"
        )

    attention = []
    if unacked:
        attention.append(
            "<div class='status-row'><div>"
            f"<strong>{unacked} unacknowledged alert{'s' if unacked != 1 else ''}"
            "</strong><div class='detail'>Open the triage queue and confirm an "
            "analyst has reviewed each interaction.</div></div>"
            "<a class='btn btn-small' href='/alerts?ack=no'>Review</a></div>"
        )
    if failed:
        attention.append(
            "<div class='status-row'><div>"
            f"<strong>{failed} failed delivery packet{'s' if failed != 1 else ''}"
            "</strong><div class='detail'>Transport failures are retained in the "
            "outbox for an explicit retry.</div></div>"
            "<a class='btn btn-small' href='/evidence#delivery'>Inspect</a></div>"
        )
    if last is None or not last["ok"]:
        attention.append(
            "<div class='status-row'><div><strong>Assurance needs attention"
            "</strong><div class='detail'>The latest recorded run is missing or "
            "failed; synthetic success does not prove live collection.</div>"
            "</div><a class='btn btn-small' href='/assurance'>Open assurance</a></div>"
        )
    elif last["mode"] == "canary":
        attention.append(
            "<div class='status-row'><div><strong>Latest assurance was synthetic"
            "</strong><div class='detail'>The canary passed the local decision "
            "path. Review live collection and external acceptance separately."
            "</div></div><a class='btn btn-small btn-secondary' "
            "href='/assurance'>Review stages</a></div>"
        )
    if integrity is not None and not integrity["ok"]:
        attention.append(
            "<div class='status-row'><div><strong>Evidence chain failing</strong>"
            "<div class='detail'>Re-verify with the correct key and preserve the "
            "database before further writes.</div></div>"
            "<a class='btn btn-small' href='/evidence#integrity'>Investigate</a>"
            "</div>"
        )
    attention_html = (
        f"<div class='panel panel-pad status-list'>{''.join(attention)}</div>"
        if attention
        else _empty(
            "Nothing needs attention",
            "No unacknowledged alerts, delivery failures or assurance gaps are "
            "recorded.",
        )
    )

    unacked_rows = _fetch(
        engine,
        "SELECT id,decoy,actor,received_at,acknowledged_at,evidence FROM alerts "
        "WHERE acknowledged_at IS NULL ORDER BY received_at DESC LIMIT 5",
        (),
    )
    recent_rows = _fetch(
        engine,
        "SELECT id,decoy,actor,received_at,acknowledged_at,evidence FROM alerts "
        "ORDER BY received_at DESC LIMIT 8",
        (),
    )
    queue = (
        "<div class='panel queue'>"
        + "".join(_alert_row(*row, now) for row in unacked_rows)
        + "</div>"
        if unacked_rows
        else _empty(
            "No unacknowledged alerts",
            "Every retained alert has an analyst acknowledgment.",
            "<a class='btn btn-small btn-secondary' href='/alerts'>Open alerts</a>",
        )
    )
    recent = (
        "<div class='panel queue'>"
        + "".join(_alert_row(*row, now) for row in recent_rows)
        + "</div>"
        if recent_rows
        else _empty(
            "No retained alerts yet",
            "Ingest collection output to populate the queue.",
        )
    )

    pending_age = (
        f"Oldest pending {_relative(oldest_pending, now)}."
        if oldest_pending
        else "No packets waiting."
    )
    cards = "".join(
        [
            _metric_card(
                "Unacknowledged",
                unacked,
                "Open triage queue.",
                "/alerts?ack=no",
                tone="warn" if unacked else "",
            ),
            _metric_card(
                "Delivery pending",
                pending,
                pending_age,
                "/evidence#delivery",
                tone="warn" if pending else "",
            ),
            _metric_card(
                "Delivery failed",
                failed,
                "Packets awaiting an explicit retry.",
                "/evidence#delivery",
                tone="bad" if failed else "",
            ),
            _metric_card(
                "Evidence integrity",
                integrity_label,
                integrity_scope,
                "/evidence#integrity",
                tone=integrity_tone,
            ),
            _metric_card(
                "Assurance",
                assurance_label,
                assurance_scope,
                "/assurance",
                tone=assurance_tone,
            ),
            _metric_card(
                "Retained alerts",
                retained,
                "Evidence currently held in the local database.",
                "/alerts",
            ),
        ]
    )
    body = (
        f"<div class='cards metrics'>{cards}</div>"
        "<section class='section' aria-labelledby='attention'>"
        "<div class='section-head'><h2 id='attention'>Needs attention</h2>"
        "<p>Ordered by operational urgency, all scoped to this database.</p></div>"
        f"{attention_html}</section>"
        "<section class='section' aria-labelledby='unacked'>"
        "<div class='section-head'><h2 id='unacked'>Unacknowledged queue</h2>"
        "<p>Most recent interactions with no analyst acknowledgment.</p></div>"
        f"{queue}</section>"
        "<section class='section' aria-labelledby='recent'>"
        "<div class='section-head'><h2 id='recent'>Recent activity</h2>"
        "<p>Latest retained alerts across every decoy source.</p></div>"
        f"{recent}</section>"
    )
    return _shell(
        "Operations overview",
        "overview",
        body,
        purpose="What needs attention across decoy detection, delivery and "
        "evidence health.",
        meta="<span>Local database</span>",
    )


def _filter_state(params):
    return {
        "q": params.get("q", [""])[0].strip(),
        "source": params.get("source", [""])[0],
        "ack": params.get("ack", [""])[0],
        "decoy": params.get("decoy", [""])[0].strip(),
        "route": params.get("route", [""])[0].strip(),
    }


def _alert_where(state):
    clauses, values = [], []
    if state["q"]:
        like = f"%{state['q'][:128]}%"
        clauses.append("(actor LIKE ? OR decoy LIKE ? OR evidence LIKE ?)")
        values += [like, like, like]
    if state["source"]:
        if state["source"] not in SOURCES:
            raise ContractError("unknown source filter")
        clauses.append("json_extract(evidence,'$.event.source') = ?")
        values.append(state["source"])
    if state["decoy"]:
        clauses.append("decoy = ?")
        values.append(state["decoy"][:128])
    if state["route"]:
        clauses.append("route = ?")
        values.append(state["route"][:64])
    if state["ack"] == "yes":
        clauses.append("acknowledged_at IS NOT NULL")
    elif state["ack"] == "no":
        clauses.append("acknowledged_at IS NULL")
    return (" WHERE " + " AND ".join(clauses)) if clauses else "", values


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


def _alerts_url(state, **overrides):
    query = {
        key: value
        for key, value in state.items()
        if value and key not in overrides
    }
    query.update({key: value for key, value in overrides.items() if value})
    return "/alerts" + (("?" + urlencode(query)) if query else "")


def _alerts_page(engine, params, *, csrf):
    now = _now()
    state = _filter_state(params)
    where, values = _alert_where(state)
    page, page_size = _page_params(params)
    total = _fetch(engine, "SELECT COUNT(*) FROM alerts" + where, values)[0][0]
    rows = _fetch(
        engine,
        "SELECT id,decoy,actor,received_at,acknowledged_at,evidence FROM alerts"
        + where
        + " ORDER BY received_at DESC, id DESC LIMIT ? OFFSET ?",
        values + [page_size, (page - 1) * page_size],
    )
    source_options = "".join(
        f"<option value='{key}'{' selected' if state['source'] == key else ''}>"
        f"{_e(label)}</option>"
        for key, label in SOURCE_LABELS.items()
    )
    ack_options = "".join(
        f"<option value='{value}'{' selected' if state['ack'] == value else ''}>"
        f"{_e(label)}</option>"
        for value, label in (
            ("", "Any status"),
            ("no", "Unacknowledged"),
            ("yes", "Acknowledged"),
        )
    )
    chips = []
    labels = {
        "q": "Search",
        "source": "Source",
        "ack": "Status",
        "decoy": "Decoy",
        "route": "Route",
    }
    for key, value in state.items():
        if not value:
            continue
        shown = SOURCE_LABELS.get(value, value) if key == "source" else value
        if key == "ack":
            shown = "Unacknowledged" if value == "no" else "Acknowledged"
        chips.append(
            f"<a class='chip' href='{_e(_alerts_url(state, **{key: ''}))}'>"
            f"{_e(labels[key])}: {_e(shown)} "
            "<span class='x' aria-hidden='true'>×</span>"
            f"<span class='visually-hidden'>Remove filter</span></a>"
        )
    chips_html = (
        "<div class='chips'>"
        + "".join(chips)
        + "<a class='inline-link' href='/alerts'>Reset filters</a></div>"
        if chips
        else ""
    )
    filters = (
        "<form class='panel filters' method='get' action='/alerts' role='search'>"
        "<div class='filter-row'>"
        "<div class='field'><label for='q'>Search</label>"
        f"<input class='input' id='q' name='q' type='search' value='{_e(state['q'])}' "
        "placeholder='Actor, decoy or evidence text'></div>"
        "<div class='field'><label for='source'>Source</label>"
        f"<select class='select' id='source' name='source'><option value=''>"
        f"Any source</option>{source_options}</select></div>"
        "<div class='field'><label for='ack'>Status</label>"
        f"<select class='select' id='ack' name='ack'>{ack_options}</select></div>"
        "<div class='field'><label for='decoy'>Decoy</label>"
        f"<input class='input' id='decoy' name='decoy' value='{_e(state['decoy'])}' "
        "placeholder='Exact decoy ID'></div>"
        "<div class='field'><label for='route'>Route</label>"
        f"<input class='input' id='route' name='route' value='{_e(state['route'])}' "
        "placeholder='Exact route label'></div>"
        "<button class='btn' type='submit'>Apply filters</button>"
        "</div>"
        f"{chips_html}</form>"
    )
    if rows:
        queue = (
            "<div class='panel queue'>"
            + "".join(_alert_row(*row, now) for row in rows)
            + "</div>"
        )
    elif total:
        queue = _empty(
            "No alerts on this page",
            "The selected page is beyond the current result set.",
            "<a class='btn btn-small btn-secondary' href='"
            + _e(_alerts_url(state, page="1"))
            + "'>Back to first page</a>",
        )
    else:
        queue = _empty(
            "No alerts match these filters",
            "Adjust or reset the filters to see retained alerts.",
            "<a class='btn btn-small btn-secondary' href='/alerts'>Reset filters</a>",
        )
    pages = max(1, (total + page_size - 1) // page_size)
    links = []
    for number in sorted({1, page - 1, page, page + 1, pages}):
        if not 1 <= number <= pages:
            continue
        if number == page:
            links.append(f"<span class='current' aria-current='page'>{number}</span>")
        else:
            links.append(
                f"<a href='{_e(_alerts_url(state, page=number, page_size=page_size))}' "
                f"aria-label='Page {number}'>{number}</a>"
            )
    pager = (
        "<div class='pager'><span class='muted small'>"
        f"{total} alert{'s' if total != 1 else ''} · page {page} of {pages}</span>"
        f"<nav class='pages' aria-label='Pagination'>{''.join(links)}</nav></div>"
        if total
        else ""
    )
    body = (
        f"{filters}"
        "<section class='section' aria-labelledby='queue'>"
        "<div class='section-head'><h2 id='queue'>Triage queue</h2>"
        "<p>Every row is a retained decoy interaction. Investigate to acknowledge."
        "</p></div>"
        f"{queue}{pager}</section>"
    )
    return _shell(
        "Alerts",
        "alerts",
        body,
        purpose="Search, filter and investigate retained decoy interactions.",
        meta=f"<span>{total} matching</span>",
    )


def _alert_detail(engine, alert_id, *, csrf, error="", acknowledged=False):
    now = _now()
    row = _fetch(
        engine,
        "SELECT id,decoy,actor,opened_at,received_at,acknowledged_at,"
        "acknowledged_by,evidence,route FROM alerts WHERE id=?",
        (alert_id,),
    )
    if not row:
        return _shell(
            "Alert not found",
            "alerts",
            _empty(
                "Alert not found",
                "No retained alert has this identifier.",
                "<a class='btn btn-small btn-secondary' href='/alerts'>Back to alerts</a>",
            ),
            purpose="Investigate a retained decoy interaction.",
        )
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
    ) = row[0]
    try:
        alert = json.loads(evidence)
    except (TypeError, ValueError):
        alert = {}
    event = alert.get("event") or {}
    delivery = _fetch(
        engine,
        "SELECT destination,payload_format,state,attempts,updated_at,last_error "
        "FROM outbox WHERE alert_id=? ORDER BY destination",
        (alert_id,),
    )
    delivery_rows = "".join(
        "<tr>"
        f"<td>{_e(destination)}</td><td>{_e(payload_format)}</td>"
        f"<td>{_delivery_badge(state)}</td><td>{_e(attempts)}</td>"
        f"<td><time datetime='{_e(updated)}'>{_e(_human_time(updated))}</time></td>"
        f"<td class='small'>{_e(error_text or '—')}</td></tr>"
        for destination, payload_format, state, attempts, updated, error_text in delivery
    )
    delivery_table = (
        "<div class='table-wrap'><table class='data'><thead><tr>"
        "<th>Destination</th><th>Format</th><th>Status</th><th>Attempts</th>"
        "<th>Updated</th><th>Last error</th></tr></thead><tbody>"
        f"{delivery_rows}</tbody></table></div>"
        if delivery
        else "<p class='muted'>This alert has not been enqueued for delivery.</p>"
    )
    timeline = [
        "<li class='done'><div class='t'>Event occurred at the source</div>"
        f"<div class='when'>{_e(_human_time(event.get('time')))}</div>"
        "<div class='note'>Source timestamp from the collector contract.</div></li>",
        "<li class='done'><div class='t'>Received into local evidence</div>"
        f"<div class='when'>{_e(_human_time(alert.get('observed_at') or received_at))}"
        f" · {_e(_relative(alert.get('observed_at') or received_at, now))}</div>"
        "<div class='note'>When this database recorded the decision.</div></li>",
    ]
    if delivery:
        for destination, _fmt, state, _a, updated, _err in delivery:
            timeline.append(
                "<li class='done'><div class='t'>Delivery to "
                f"{_e(destination)}</div>"
                f"<div class='when'>{_e(_human_time(updated))} · "
                f"{_e(DELIVERY_TONES.get(state, (state, ''))[0])}</div></li>"
            )
    else:
        timeline.append(
            "<li><div class='t'>Not enqueued for delivery</div>"
            "<div class='note'>No named destination has queued this alert.</div></li>"
        )
    if acknowledged_at:
        timeline.append(
            "<li class='done'><div class='t'>Acknowledged by "
            f"{_e(acknowledged_by)}</div>"
            f"<div class='when'>{_e(_human_time(acknowledged_at))}</div></li>"
        )
    else:
        timeline.append(
            "<li><div class='t'>Awaiting analyst acknowledgment</div>"
            "<div class='note'>Use the form below to record a local "
            "acknowledgment.</div></li>"
        )
    if acknowledged_at:
        ack_panel = (
            "<div class='card ack-panel'><h2>Acknowledgment</h2>"
            f"<p class='card-scope'>Recorded by <strong>{_e(acknowledged_by)}</strong>"
            f" at {_e(_human_time(acknowledged_at))}.</p>"
            + (
                f"<div class='form-error' role='alert'>{_e(error)}</div>"
                if error
                else ""
            )
            + "</div>"
        )
    else:
        ack_panel = (
            "<div class='card ack-panel'><h2>Acknowledge this alert</h2>"
            "<p class='card-scope'>This is a local operator acknowledgment, not "
            "containment or case closure.</p>"
            "<form method='post' action='/acknowledge'>"
            f"<input type='hidden' name='alert_id' value='{_e(identifier)}'>"
            f"<input type='hidden' name='csrf' value='{_e(csrf or '')}'>"
            "<div class='form-row'><div class='field'>"
            "<label for='analyst'>Analyst name</label>"
            "<input class='input' id='analyst' name='analyst' required "
            "maxlength='200' autocomplete='off'></div>"
            "<button class='btn' type='submit'>Acknowledge alert</button></div>"
            "<p class='form-hint'>The name and time are stored with the evidence."
            "</p></form>"
            + (f"<div class='form-error' role='alert'>{_e(error)}</div>" if error else "")
            + "</div>"
        )
    flash = (
        "<div class='flash' role='status'>Acknowledgement recorded for this alert."
        "</div>"
        if acknowledged
        else ""
    )
    summary = "".join(
        [
            (
                "<div class='summary-item'><div class='k'>Outcome</div>"
                f"<div class='v'>{_outcome_badge(event)}</div></div>"
            ),
            (
                "<div class='summary-item'><div class='k'>Decoy</div>"
                f"<div class='v mono-id'>{_e(decoy)}</div></div>"
            ),
            (
                "<div class='summary-item'><div class='k'>Resource</div>"
                f"<div class='v'>{_e(_resource_label(alert) or '—')}</div></div>"
            ),
            (
                "<div class='summary-item'><div class='k'>Actor</div>"
                f"<div class='v mono-id'>{_e(actor)}</div></div>"
            ),
            (
                "<div class='summary-item'><div class='k'>Owner</div>"
                f"<div class='v'>{_e(alert.get('owner') or '—')}</div></div>"
            ),
            (
                "<div class='summary-item'><div class='k'>Route</div>"
                f"<div class='v'>{_e(route or '—')}</div></div>"
            ),
            (
                "<div class='summary-item' style='grid-column:1/-1'><div class='k'>"
                "Response procedure</div>"
                f"<div class='v'>{_e(alert.get('response_procedure') or '—')}"
                "</div></div>"
            ),
        ]
    )
    evidence_block = (
        "<div class='stack'>"
        "<details class='evidence'><summary>Normalized event</summary>"
        f"<pre>{_e(json.dumps(event, indent=2, sort_keys=True))}</pre></details>"
        "<details class='evidence'><summary>Evidence record</summary>"
        f"<pre>{_e(canonical(alert))}</pre></details>"
        "<details class='evidence'><summary>Hashes and identifiers</summary>"
        f"<pre>{_e(json.dumps({'alert_id': identifier, 'registry_sha256': alert.get('registry_sha256'), 'raw_event_sha256': alert.get('raw_event_sha256'), 'related_alert_id': alert.get('related_alert_id')}, indent=2, sort_keys=True))}</pre>"
        "</details></div>"
    )
    body = (
        flash
        + "<div class='split'><div class='panel panel-pad'>"
        "<div class='card-head'><h2>What happened</h2>"
        f"<div>{_outcome_badge(event)}{_ack_badge(acknowledged_at)}</div></div>"
        f"<div class='summary-grid'>{summary}</div>"
        "<h3 style='margin-top:22px'>Timeline</h3>"
        f"<ol class='timeline'>{''.join(timeline)}</ol>"
        "</div>"
        "<div class='stack'>"
        f"{ack_panel}"
        "<div class='card'><h2>Delivery</h2>"
        f"{delivery_table}</div>"
        "</div></div>"
        "<section class='section' aria-labelledby='evidence'><div class='section-head'>"
        "<h2 id='evidence'>Evidence</h2>"
        "<p>Full records are retained; open only when needed.</p></div>"
        f"{evidence_block}</section>"
        "<p style='margin-top:22px'><a class='inline-link' href='/alerts'>"
        "← Back to alerts</a></p>"
    )
    return _shell(
        "Alert investigation",
        "alerts",
        body,
        purpose="Understand one decoy interaction before acknowledging it.",
        meta=f"<span class='mono-id'>{_e(identifier)}</span>",
    )


def _incidents_page(engine, *, csrf):
    data = incidents(engine)
    rows = data.get("incidents") or []
    if rows:
        body_rows = "".join(
            "<tr>"
            f"<td><a href='{_e('/alerts?' + urlencode({'q': item['actor']}))}'>"
            f"{_e(_actor_label(item['actor']))}</a></td>"
            f"<td><time datetime='{_e(item['first_seen'])}'>"
            f"{_e(_human_time(item['first_seen']))}</time><br>"
            f"<span class='small muted'>to {_e(_human_time(item['last_seen']))}"
            "</span></td>"
            f"<td>{_e(item['alert_count'])}</td>"
            f"<td><div class='tag-list'>"
            + "".join(
                f"<span class='badge badge-neutral'>{_e(decoy)}</span>"
                for decoy in item["decoys"]
            )
            + "</div></td>"
            f"<td>{_e(item['acknowledged'])} of {_e(item['alert_count'])}</td>"
            f"<td class='small'>{_e(', '.join(item['mitre_techniques']) or '—')}"
            "</td></tr>"
            for item in rows
        )
        table = (
            "<div class='panel table-wrap'><table class='data'><thead><tr>"
            "<th>Actor</th><th>Window</th><th>Alerts</th><th>Affected decoys</th>"
            "<th>Acknowledged</th><th>ATT&amp;CK hints</th></tr></thead><tbody>"
            f"{body_rows}</tbody></table></div>"
        )
    else:
        table = _empty(
            "No incidents recorded",
            "Alerts are grouped per actor once interactions are retained.",
        )
    body = (
        "<div class='guidance' style='margin-bottom:20px'><h3>Activity groups, "
        "not attribution</h3><p class='small muted'>Incidents cluster retained "
        "alerts by the same actor within five minutes. A decoy interaction does "
        "not establish malicious intent; investigate before drawing "
        "conclusions.</p></div>"
        + table
    )
    return _shell(
        "Incidents",
        "incidents",
        body,
        purpose="Per-actor activity groups with acknowledgment progress.",
        meta=f"<span>{len(rows)} groups</span>",
    )


def _assurance_page(engine, *, csrf):
    report = assurance_report(engine)
    stages = report.get("stages") or {}
    stage_rows = []
    for key, label in STAGE_LABELS:
        default_status = (
            "unverified"
            if key in ("ingestion", "analyst_acknowledgment")
            else "not_run"
        )
        stage = stages.get(key) or {"status": default_status}
        status = stage.get("status", default_status)
        detail = {
            "synthetic": "Canary events exercised locally in a temporary database.",
            "live": "A real decoy file was probed and the resulting alert observed.",
            "transport": "A configured destination accepted a rendered packet.",
            "ingestion": "External SIEM receipt must be confirmed by an operator.",
            "analyst_acknowledgment": "A named analyst must confirm the workflow.",
        }[key]
        extra = stage.get("actor") or ""
        stage_rows.append(
            "<div class='status-row'><div><strong>"
            f"{_e(label)}</strong><div class='detail'>{_e(detail)}</div>"
            + (
                f"<div class='detail'>Recorded by {_e(extra)} at "
                f"{_e(_human_time(stage.get('recorded_at')))}</div>"
                if extra
                else ""
            )
            + "</div>"
            f"<div>{_stage_badge(status)}</div></div>"
        )
    latest = engine.last_assurance()
    latest_html = (
        "<div class='kv'>"
        f"<dt>Run</dt><dd class='mono-id'>{_e(latest['run_id'] or '—')}</dd>"
        f"<dt>Mode</dt><dd>{_e(latest['mode'])}</dd>"
        f"<dt>Recorded</dt><dd>{_e(_human_time(latest['ran_at']))}</dd>"
        f"<dt>Result</dt><dd>{_badge('Passed' if latest['ok'] else 'Failed', 'ok' if latest['ok'] else 'bad')}</dd>"
        f"<dt>Failed scenarios</dt><dd>{_e(latest['failed_scenarios'])}</dd>"
        "</div>"
        if latest
        else _empty(
            "No assurance runs recorded",
            "Run `fools-gold assure` (and `--live` with a configured sensor) to "
            "record a run.",
        )
    )
    history = engine.assurance_history(10)
    history_rows = "".join(
        "<tr>"
        f"<td class='mono-id'>{_e((run['run_id'] or '')[:12])}</td>"
        f"<td>{_e(run['mode'])}</td>"
        f"<td>{_e(_human_time(run['ran_at']))}</td>"
        f"<td>{_badge('Passed' if run['ok'] else 'Failed', 'ok' if run['ok'] else 'bad')}</td>"
        f"<td>{_e(run['failed_scenarios'])}</td></tr>"
        for run in history
    )
    history_html = (
        "<div class='table-wrap'><table class='data'><thead><tr>"
        "<th>Run</th><th>Mode</th><th>Recorded</th><th>Result</th>"
        "<th>Failed scenarios</th></tr></thead><tbody>"
        f"{history_rows}</tbody></table></div>"
        if history
        else "<p class='muted'>No runs yet.</p>"
    )
    mttd = report.get("mttd_seconds") or {}
    mtta = report.get("mtta_seconds") or {}
    metrics_rows = ""
    for label, values in (("Detection latency (event to receipt)", mttd), ("Acknowledgment latency", mtta)):
        if values.get("samples"):
            metrics_rows += (
                "<div class='stat-line'>"
                f"<span>{_e(label)}</span><span class='mono'>p50 {values['p50']:.1f}s · "
                f"p95 {values['p95']:.1f}s · max {values['max']:.1f}s "
                f"({_e(values['samples'])} samples)</span></div>"
            )
        else:
            metrics_rows += (
                "<div class='stat-line'><span>"
                f"{_e(label)}</span><span class='muted'>No samples yet</span></div>"
            )
    missing = [key for key, _label in STAGE_LABELS if (stages.get(key) or {}).get("status") in (None, "not_run", "unverified", "fail")]
    guidance_items = []
    if "live" in missing:
        guidance_items.append(
            "<li>Probe a real registered decoy and wait for its alert: "
            "<code>fools-gold ... assure --live --wait-seconds 30</code>.</li>"
        )
    if "transport" in missing:
        guidance_items.append(
            "<li>Register a destination and deliver: "
            "<code>destination add</code>, <code>deliver --destination NAME</code>.</li>"
        )
    if "ingestion" in missing:
        guidance_items.append(
            "<li>After confirming the alert in your SIEM: "
            "<code>accept --stage ingestion --note ... --actor ...</code>.</li>"
        )
    if "analyst_acknowledgment" in missing:
        guidance_items.append(
            "<li>After the real case workflow is confirmed: "
            "<code>accept --stage analyst_acknowledgment --note ... --actor ...</code>."
            "</li>"
        )
    guidance = (
        "<div class='guidance'><h3>Completing unverified stages</h3>"
        "<ul>" + "".join(guidance_items) + "</ul></div>"
        if guidance_items
        else "<div class='guidance'><h3>All recorded stages are covered</h3>"
        "<p class='small muted'>External confirmation remains an operator "
        "responsibility.</p></div>"
    )
    body = (
        "<div class='guidance' style='margin-bottom:20px'><h3>What these stages "
        "prove</h3><p class='small muted'>Synthetic canary success proves the "
        "local decision path, not live collection. Live, transport, ingestion and "
        "analyst stages are reported separately and must be verified in the real "
        "environment.</p></div>"
        "<div class='split'><div class='panel panel-pad'>"
        "<h2>Assurance stages</h2>"
        f"<div class='status-list'>{''.join(stage_rows)}</div></div>"
        "<div class='stack'><div class='card'><h2>Latest run</h2>"
        f"{latest_html}</div>"
        "<div class='card'><h2>Measured latencies</h2>"
        f"{metrics_rows}</div></div></div>"
        "<section class='section'><div class='section-head'><h2>Recent runs</h2>"
        "<p>Newest first; run identities are unique.</p></div>"
        f"{history_html}</section>"
        f"<section class='section'>{guidance}</section>"
    )
    return _shell(
        "Assurance",
        "assurance",
        body,
        purpose="What has actually been proved, stage by stage.",
        meta=f"<span>{report.get('runs', 0)} runs</span>",
    )


def _evidence_page(engine, *, csrf):
    now = _now()
    integrity = None
    if engine.mac_key is not None:
        integrity = engine.verify_integrity()
    if integrity is None:
        integrity_card = (
            "<div class='card'><div class='card-head'><h2>Evidence integrity</h2>"
            + _badge("Not configured", "warn")
            + "</div><p class='card-scope'>No evidence key was supplied. Hashes "
            "remain comparison aids; supply <code>--evidence-key-file</code> to "
            "verify the HMAC chain.</p></div>"
        )
    elif integrity["ok"]:
        integrity_card = (
            "<div class='card'><div class='card-head'><h2>Evidence integrity</h2>"
            + _badge("Verified", "ok")
            + f"</div><div class='kv'><dt>Alerts</dt><dd>{_e(integrity['alerts'])}"
            f"</dd><dt>Checkpoints applied</dt>"
            f"<dd>{_e(integrity['retention']['applied'])}</dd>"
            f"<dt>Checkpoints stored</dt>"
            f"<dd>{_e(integrity['retention']['checkpoints'])}</dd></div></div>"
        )
    else:
        failures = "".join(
            f"<li class='mono-id'>{_e(item['alert_id'])}: {_e(item['reason'])}</li>"
            for item in integrity["failures"][:10]
        )
        integrity_card = (
            "<div class='card metric-bad'><div class='card-head'>"
            "<h2>Evidence integrity</h2>" + _badge("Failing", "bad")
            + f"</div><p class='card-scope'>{len(integrity['failures'])} failures "
            f"across {_e(integrity['alerts'])} alerts.</p>"
            f"<ul class='small'>{failures}</ul></div>"
        )
    outbox = engine.outbox_report()["outbox"]
    destinations = engine.destinations()
    destination_cards = []
    for destination in destinations:
        name = destination["name"]
        states = outbox.get(name, {})
        oldest = _fetch(
            engine,
            "SELECT MIN(updated_at) FROM outbox WHERE destination=? AND state='pending'",
            (name,),
        )[0][0]
        target = (
            f"{destination['host']}:{destination['port']}"
            if destination["payload_format"] == "splunk"
            else (Path(destination["path"]).name if destination["path"] else "—")
        )
        destination_cards.append(
            "<div class='card'><div class='card-head'>"
            f"<h3>{_e(name)}</h3>"
            f"{_badge(destination['payload_format'].title(), 'info')}</div>"
            f"<div class='stat-line'><span>Target</span>"
            f"<span class='mono small'>{_e(target)}</span></div>"
            f"<div class='stat-line'><span>Pending</span>"
            f"<span>{_e(states.get('pending', 0))}</span></div>"
            f"<div class='stat-line'><span>Accepted</span>"
            f"<span>{_e(states.get('sent', 0))}</span></div>"
            f"<div class='stat-line'><span>Failed</span>"
            f"<span>{_e(states.get('failed', 0))}</span></div>"
            + (
                "<div class='stat-line'><span>Oldest pending</span>"
                f"<span>{_e(_relative(oldest, now))}</span></div>"
                if oldest
                else ""
            )
            + "</div>"
        )
    delivery_cards = (
        "<div class='cards'>" + "".join(destination_cards) + "</div>"
        if destination_cards
        else _empty(
            "No named destinations",
            "Register one with `destination add` before delivering alerts.",
        )
    )
    routes = engine.routes()
    routes_html = (
        "<div class='table-wrap'><table class='data'><thead><tr>"
        "<th>Route</th><th>Destination</th></tr></thead><tbody>"
        + "".join(
            f"<tr><td class='mono'>{_e(item['route'])}</td>"
            f"<td>{_e(item['destination'])}</td></tr>"
            for item in routes
        )
        + "</tbody></table></div>"
        if routes
        else "<p class='muted small'>No route mappings. Deliver with an explicit "
        "destination, or map registry routes with `route map`.</p>"
    )
    failed_rows = _fetch(
        engine,
        "SELECT alert_id,destination,state,attempts,updated_at,last_error "
        "FROM outbox WHERE state='failed' ORDER BY updated_at DESC LIMIT 10",
        (),
    )
    failed_html = (
        "<div class='table-wrap'><table class='data'><thead><tr>"
        "<th>Alert</th><th>Destination</th><th>Attempts</th><th>Updated</th>"
        "<th>Last error</th></tr></thead><tbody>"
        + "".join(
            "<tr>"
            f"<td><a class='mono-id' href='/alert/{_e(alert_id)}'>"
            f"{_e(alert_id)}</a></td>"
            f"<td>{_e(destination)}</td><td>{_e(attempts)}</td>"
            f"<td><time datetime='{_e(updated)}'>{_e(_human_time(updated))}</time>"
            f"</td><td class='small'>{_e(error_text or '—')}</td></tr>"
            for alert_id, destination, _state, attempts, updated, error_text in failed_rows
        )
        + "</tbody></table></div>"
        if failed_rows
        else "<p class='muted'>No failed packets. Retained failures would appear "
        "here with an explicit retry command.</p>"
    )
    retained = _fetch(engine, "SELECT COUNT(*) FROM alerts", ())[0][0]
    acknowledged = _fetch(
        engine, "SELECT COUNT(*) FROM alerts WHERE acknowledged_at IS NOT NULL", ()
    )[0][0]
    first_last = _fetch(
        engine, "SELECT MIN(received_at), MAX(received_at) FROM alerts", ()
    )[0]
    body = (
        "<div class='split'>"
        f"<div class='stack'>{integrity_card}"
        "<section id='delivery'><div class='section-head'>"
        "<h2>Delivery</h2><p>Named destinations and their retained outbox.</p>"
        f"</div>{delivery_cards}</section>"
        "<section><div class='section-head'><h2>Route mappings</h2>"
        "<p>Registry routes resolve to these destinations.</p></div>"
        f"<div class='panel panel-pad'>{routes_html}</div></section></div>"
        "<div class='stack'><div class='card'><h2>Retained evidence</h2>"
        f"<div class='stat-line'><span>Alerts</span><span>{_e(retained)}</span></div>"
        f"<div class='stat-line'><span>Acknowledged</span>"
        f"<span>{_e(acknowledged)}</span></div>"
        f"<div class='stat-line'><span>Oldest receipt</span>"
        f"<span>{_e(_human_time(first_last[0]) if first_last[0] else '—')}</span>"
        f"</div><div class='stat-line'><span>Newest receipt</span>"
        f"<span>{_e(_human_time(first_last[1]) if first_last[1] else '—')}</span>"
        "</div></div>"
        "<div class='guidance'><h3>Export and recovery</h3><ul>"
        "<li>Create a signed evidence bundle: "
        "<code>fools-gold ... bundle --out case.zip</code>.</li>"
        "<li>Verify it later: <code>verify-bundle --file case.zip</code>.</li>"
        "<li>Back up with <code>backup --out snapshot.sqlite</code>; restore "
        "requires no open session.</li></ul></div>"
        "<div class='guidance'><h3>Retrying failures</h3><ul>"
        "<li>Inspect the failed packet above, then run "
        "<code>deliver --retry-failed</code> for that destination.</li>"
        "<li>Retries are at-least-once; deduplicate on alert ID downstream.</li>"
        "</ul></div></div></div>"
        "<section class='section'><div class='section-head'>"
        "<h2>Failed packets</h2><p>Most recent retained transport failures.</p>"
        f"</div><div class='panel panel-pad'>{failed_html}</div></section>"
    )
    return _shell(
        "Evidence and delivery",
        "evidence",
        body,
        purpose="Integrity, retention and delivery state for retained evidence.",
        meta=f"<span>{retained} alerts</span>",
    )


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
            extra = {**SECURITY_HEADERS, **(headers or {})}
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Cache-Control", extra.pop("Cache-Control", "no-store"))
            for name, value in extra.items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(body)

        def _json(self, status, value):
            self._send(status, canonical(value).encode(), "application/json")

        def _html(self, status, value):
            self._send(status, value.encode(), "text/html; charset=utf-8")

        def _redirect(self, location, headers=None):
            self._send(
                303,
                b"",
                "text/plain; charset=utf-8",
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
            if path == MASCOT_PATH:
                # One fixed public package asset; never a filesystem path
                # derived from a request. Its fingerprint permits safe caching.
                headers = {"Cache-Control": "public, max-age=31536000, immutable", "ETag": MASCOT_ETAG}
                if self.headers.get("If-None-Match") == MASCOT_ETAG:
                    return self._send(304, b"", "image/png", headers)
                return self._send(200, MASCOT_BYTES, "image/png", headers)
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
            try:
                with lock:
                    if path in ("/", "/overview"):
                        return self._html(200, _overview(engine, csrf=csrf))
                    if path == "/alerts":
                        return self._html(
                            200, _alerts_page(engine, query, csrf=csrf)
                        )
                    if path.startswith("/alert/"):
                        return self._html(
                            200,
                            _alert_detail(
                                engine,
                                path[len("/alert/"):],
                                csrf=csrf,
                                acknowledged=query.get("ack", [""])[0] == "1",
                            ),
                        )
                    if path == "/incidents":
                        return self._html(200, _incidents_page(engine, csrf=csrf))
                    if path == "/assurance":
                        return self._html(200, _assurance_page(engine, csrf=csrf))
                    if path == "/evidence":
                        return self._html(200, _evidence_page(engine, csrf=csrf))
                    if path == "/logout":
                        if session:
                            sessions.drop(session[0])
                        return self._redirect(
                            "/login",
                            {
                                "Set-Cookie": f"{COOKIE_NAME}=; Path=/; Max-Age=0; "
                                "HttpOnly; SameSite=Strict"
                            },
                        )
                    if path == "/api/alerts":
                        limit_param = query.get("limit", ["200"])[0]
                        if not limit_param.isdigit() or not 1 <= int(limit_param) <= 5000:
                            return self._json(
                                400, {"error": "limit must be 1 to 5000"}
                            )
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
            except ContractError as exc:
                return self._html(
                    400,
                    _shell(
                        "Invalid request",
                        "",
                        f"<div class='form-error' role='alert'>{_e(exc)}</div>"
                        "<p style='margin-top:16px'><a class='inline-link' "
                        "href='/alerts'>Back to alerts</a></p>",
                        purpose="The request could not be interpreted.",
                    ),
                )
            if path.startswith("/api/"):
                return self._json(404, {"error": "not found"})
            return self._html(
                404,
                _shell(
                    "Page not found",
                    "",
                    _empty(
                        "Page not found",
                        "This local console has no such page.",
                        "<a class='btn btn-small btn-secondary' href='/'>"
                        "Go to overview</a>",
                    ),
                    purpose="The requested page does not exist.",
                ),
            )

        def do_POST(self):
            path = urlparse(self.path).path
            if path == "/login":
                try:
                    form = self._read_form()
                    supplied = form.get("token", "")
                except ContractError:
                    return self._html(400, _login_page("Invalid request."))
                if not hmac.compare_digest(supplied, token):
                    return self._html(401, _login_page("The token was not accepted."))
                sid, _csrf = sessions.create()
                return self._redirect(
                    "/",
                    {"Set-Cookie": f"{COOKIE_NAME}={sid}; Path=/; "
                     "HttpOnly; SameSite=Strict"},
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
                    raise ContractError(
                        "Your session token did not match; reload the page and retry."
                    )
                with lock:
                    engine.acknowledge(
                        form["alert_id"], form["analyst"], datetime.now(UTC)
                    )
            except (KeyError, TypeError, ValueError, ContractError) as exc:
                alert_id = ""
                try:
                    alert_id = form.get("alert_id", "")
                except NameError:
                    pass
                if alert_id:
                    with lock:
                        page = _alert_detail(
                            engine,
                            alert_id,
                            csrf=session[1],
                            error=str(exc),
                        )
                    return self._html(400, page)
                return self._html(400, _login_page(str(exc)))
            return self._redirect(f"/alert/{form['alert_id']}?ack=1")

        def log_message(self, *_args):
            pass

    return HTTPServer((LOOPBACK_HOST, port), Handler)
