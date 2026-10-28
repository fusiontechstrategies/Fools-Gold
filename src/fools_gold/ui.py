"""Loopback-only dashboard and metrics. Bearer-token authenticated, read-only
except for analyst acknowledgment; no files are served from disk."""

import hmac
import html
import json
import threading
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

from .assurance import assurance_report
from .core import ContractError, canonical
from .reporting import incidents

MAX_BODY_BYTES = 4096
LOOPBACK_HOST = "127.0.0.1"


def _metrics(engine) -> str:
    counts = engine.report()
    outbox = engine.outbox_report()["outbox"]
    last = engine.last_assurance()
    lines = [
        "# HELP fools_gold_alerts_total Retained alerts",
        "# TYPE fools_gold_alerts_total gauge",
        f"fools_gold_alerts_total {counts['decisions']['alert']}",
        "fools_gold_alerts_acknowledged "
        f"{counts['alerts_acknowledged']}",
    ]
    for payload_format, states in sorted(outbox.items()):
        for state, value in sorted(states.items()):
            lines.append(
                f'fools_gold_outbox{{format="{payload_format}",state="{state}"}} {value}'
            )
    lines.append(
        "fools_gold_assurance_last_ok "
        f"{1 if last and last['ok'] else 0}"
    )
    return "\n".join(lines) + "\n"


def _dashboard(engine) -> str:
    counts = engine.report()
    alerts = [
        json.loads(row[0])
        for row in engine.db.execute(
            "SELECT evidence FROM alerts ORDER BY received_at DESC LIMIT 200"
        )
    ]
    rows = "".join(
        "<tr>"
        f"<td>{html.escape(alert['alert_id'])}</td>"
        f"<td>{html.escape(alert['decoy_id'])}</td>"
        f"<td>{html.escape(alert['event']['actor'])}</td>"
        f"<td>{html.escape(', '.join(alert['event']['actions']))}</td>"
        f"<td>{html.escape(alert['event']['outcome'])}</td>"
        "</tr>"
        for alert in alerts
    )
    return (
        "<!doctype html><html><head><meta charset='utf-8'>"
        "<title>Fool's Gold</title><style>"
        "body{font-family:system-ui,sans-serif;margin:2rem}"
        "table{border-collapse:collapse;width:100%}"
        "th,td{border:1px solid #ccc;padding:.3rem .5rem;font-size:.85rem}"
        "th{background:#f2f2f2}</style></head><body>"
        "<h1>Fool's Gold</h1>"
        f"<p>Alerts: {counts['decisions']['alert']} &middot; Acknowledged: "
        f"{counts['alerts_acknowledged']} &middot; "
        f"<a href='/metrics'>metrics</a></p>"
        "<table><thead><tr><th>Alert</th><th>Decoy</th><th>Actor</th>"
        "<th>Actions</th><th>Outcome</th></tr></thead><tbody>"
        f"{rows}</tbody></table></body></html>\n"
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

    class Handler(BaseHTTPRequestHandler):
        def _send(self, status, body: bytes, content_type: str):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _json(self, status, value):
            self._send(status, canonical(value).encode(), "application/json")

        def _authorized(self):
            header = self.headers.get("Authorization", "")
            return header.startswith("Bearer ") and hmac.compare_digest(
                header[7:], token
            )

        def do_GET(self):
            parsed = urlparse(self.path)
            path, query = parsed.path, parse_qs(parsed.query)
            if path == "/healthz":
                return self._json(200, {"ok": True})
            if not self._authorized():
                return self._json(401, {"error": "unauthorized"})
            with lock:
                if path == "/":
                    return self._send(
                        200,
                        _dashboard(engine).encode(),
                        "text/html; charset=utf-8",
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
                        200,
                        _metrics(engine).encode(),
                        "text/plain; version=0.0.4",
                    )
            return self._json(404, {"error": "not found"})

        def do_POST(self):
            path = self.path.split("?", 1)[0]
            if not self._authorized():
                return self._json(401, {"error": "unauthorized"})
            length = self.headers.get("Content-Length", "")
            if not length.isdigit() or int(length) > MAX_BODY_BYTES:
                return self._json(400, {"error": "invalid content length"})
            body = self.rfile.read(int(length))
            if path != "/api/acknowledge":
                return self._json(404, {"error": "not found"})
            try:
                payload = json.loads(body)
                if not isinstance(payload, dict):
                    raise ContractError("acknowledgment body must be an object")
                with lock:
                    engine.acknowledge(
                        payload["alert_id"],
                        payload["analyst"],
                        datetime.now(UTC),
                    )
            except (KeyError, TypeError, ValueError, ContractError) as exc:
                return self._json(400, {"error": str(exc)})
            return self._json(200, {"acknowledged": True})

        def log_message(self, *_args):
            pass

    return HTTPServer((LOOPBACK_HOST, port), Handler)
