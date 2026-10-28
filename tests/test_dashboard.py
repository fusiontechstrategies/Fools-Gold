"""Browser authentication, filters, detail and form acknowledgment."""

import http.cookiejar
import json
import re
import tempfile
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from fools_gold.core import Engine, Registry
from fools_gold.ui import make_server
from tests.test_contracts_v2 import linux
from tests.test_pilot import NOW, registry, s3

TOKEN = "synthetic-dashboard-token"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        return None


def engine_in(folder):
    engine = Engine(
        Registry(registry()), Path(folder) / "db.sqlite", thread_safe=True
    )
    engine.process(s3(), NOW)
    engine.process(linux("501"), NOW)
    engine.outbox_enqueue("wazuh", NOW)
    return engine


class DashboardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.engine = engine_in(self.temp.name)
        self.server = make_server(self.engine, TOKEN, 0)
        self.thread = threading.Thread(
            target=self.server.serve_forever, daemon=True
        )
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar)
        )

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.engine.close()
        self.temp.cleanup()

    def get(self, path, opener=None):
        request = urllib.request.Request(self.base + path)
        with (opener or self.opener).open(request, timeout=5) as response:
            return response.status, response.read().decode(), response.headers

    def post(self, path, data, opener=None):
        body = urllib.parse.urlencode(data).encode()
        request = urllib.request.Request(self.base + path, data=body)
        request.add_header("Content-Type", "application/x-www-form-urlencoded")
        with (opener or self.opener).open(request, timeout=5) as response:
            return response.status, response.read().decode()

    def login(self):
        status, body = self.post("/login", {"token": TOKEN})
        self.assertEqual(status, 200)
        self.assertTrue(any(cookie.name == "fg_session" for cookie in self.jar))
        return body

    def test_login_rejects_bad_tokens_and_sets_a_strict_cookie(self):
        with self.assertRaises(urllib.error.HTTPError) as caught:
            self.post("/login", {"token": "wrong-token-value"})
        self.assertEqual(caught.exception.code, 401)
        raw = urllib.request.build_opener(NoRedirect)
        body = urllib.parse.urlencode({"token": TOKEN}).encode()
        request = urllib.request.Request(self.base + "/login", data=body)
        request.add_header("Content-Type", "application/x-www-form-urlencoded")
        with self.assertRaises(urllib.error.HTTPError) as caught:
            raw.open(request, timeout=5)
        self.assertEqual(caught.exception.code, 303)
        cookie = caught.exception.headers["Set-Cookie"]
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Strict", cookie)
        self.assertNotIn("Max-Age", cookie)

    def test_login_renders_filters_and_ack_controls(self):
        body = self.login()
        self.assertIn("Fool&#x27;s Gold", body)
        self.assertIn("synthetic-s3-backup", body)
        self.assertIn("filter", body)
        self.assertIn("name='csrf'", body)
        self.assertIn("/incidents", body)

    def test_filters_and_pagination(self):
        self.login()
        status, body, _ = self.get("/?source=linux.audit")
        self.assertIn("synthetic-linux-config", body)
        self.assertNotIn("synthetic-s3-backup", body)
        status, body, _ = self.get("/?ack=no")
        self.assertIn("synthetic-s3-backup", body)
        status, body, _ = self.get("/?page_size=1&page=2")
        self.assertIn("page 2 of 2", body)
        with self.assertRaises(urllib.error.HTTPError) as caught:
            self.get("/?page_size=999")
        self.assertEqual(caught.exception.code, 400)
        with self.assertRaises(urllib.error.HTTPError) as caught:
            self.get("/?source=unknown.source")
        self.assertEqual(caught.exception.code, 400)

    def test_alert_detail_shows_delivery_and_ack_state(self):
        self.login()
        alert = self.engine.export_alerts().__next__()
        status, body, _ = self.get("/alert/" + alert["alert_id"])
        self.assertEqual(status, 200)
        self.assertIn(alert["alert_id"], body)
        self.assertIn("Delivery", body)
        self.assertIn("wazuh", body)
        self.assertIn("evidence", body.lower())

    def test_form_acknowledgment_requires_csrf_and_updates_evidence(self):
        body = self.login()
        csrf = re.search(r"name='csrf' value='([^']+)'", body).group(1)
        alert = self.engine.export_alerts().__next__()
        with self.assertRaises(urllib.error.HTTPError) as caught:
            self.post(
                "/acknowledge",
                {"alert_id": alert["alert_id"], "analyst": "analyst", "csrf": "bad"},
            )
        self.assertEqual(caught.exception.code, 400)
        status, body = self.post(
            "/acknowledge",
            {
                "alert_id": alert["alert_id"],
                "analyst": "dashboard-analyst",
                "csrf": csrf,
            },
        )
        self.assertEqual(status, 200)
        self.assertIn("Acknowledged by dashboard-analyst", body)
        counts = self.engine.report()
        self.assertEqual(counts["alerts_acknowledged"], 1)

    def test_session_cookie_does_not_authorize_the_bearer_api(self):
        self.login()
        request = urllib.request.Request(
            self.base + "/api/acknowledge",
            data=b'{"alert_id": "x", "analyst": "y"}',
            method="POST",
        )
        request.add_header("Content-Type", "application/json")
        with self.assertRaises(urllib.error.HTTPError) as caught:
            self.opener.open(request, timeout=5)
        self.assertEqual(caught.exception.code, 401)

    def test_logout_invalidates_the_session(self):
        self.login()
        status, body, _ = self.get("/logout")
        self.assertIn("login", body.lower())
        status, body, _ = self.get("/")
        self.assertIn("login", body.lower())
        alert = self.engine.export_alerts().__next__()
        status, body, _ = self.get("/alert/" + alert["alert_id"])
        self.assertIn("login", body.lower())

    def test_bearer_access_still_works_for_scripts(self):
        request = urllib.request.Request(self.base + "/api/report")
        request.add_header("Authorization", f"Bearer {TOKEN}")
        with urllib.request.urlopen(request, timeout=5) as response:  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
            payload = json.loads(response.read())
        self.assertEqual(payload["decisions"]["alert"], 2)

    def test_healthz_is_open(self):
        status, body, _ = self.get("/healthz")
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(body)["ok"])

    def test_unknown_alert_and_path(self):
        self.login()
        status, body, _ = self.get("/alert/does-not-exist")
        self.assertIn("No such alert", body)
        with self.assertRaises(urllib.error.HTTPError) as caught:
            self.get("/api/unknown")
        self.assertEqual(caught.exception.code, 404)


if __name__ == "__main__":
    unittest.main()
