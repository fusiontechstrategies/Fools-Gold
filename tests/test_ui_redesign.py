"""Structural and honesty checks for the redesigned console."""

import json
import tempfile
import threading
import unittest
import urllib.parse
import urllib.request
from pathlib import Path

from fools_gold.core import Engine, Registry
from fools_gold.ui import make_server
from fools_gold.ui_assets import STYLES
from tests.test_pilot import NOW, registry, s3

TOKEN = "synthetic-redesign-token"


class RedesignTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        pass

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        folder = Path(self.temp.name)
        self.engine = Engine(
            Registry(registry()), folder / "db.sqlite", thread_safe=True
        )
        self.engine.process(s3("redesign-1"), NOW)
        self.server = make_server(self.engine, TOKEN, 0)
        self.thread = threading.Thread(
            target=self.server.serve_forever, daemon=True
        )
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.request_headers = {"Authorization": f"Bearer {TOKEN}"}

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.engine.close()
        self.temp.cleanup()

    def get(self, path):
        request = urllib.request.Request(self.base + path)
        for name, value in self.request_headers.items():
            request.add_header(name, value)
        with urllib.request.urlopen(request, timeout=10) as response:
            return response, response.read().decode()

    def login_page(self):
        with urllib.request.urlopen(self.base + "/login", timeout=10) as response:
            return response, response.read().decode()

    def test_pages_are_self_contained_and_accessible(self):
        for path in ("/", "/alerts", "/incidents", "/assurance", "/evidence"):
            with self.subTest(path=path):
                response, body = self.get(path)
                self.assertEqual(response.status, 200)
                self.assertIn("lang='en'", body)
                self.assertIn("name='viewport'", body)
                self.assertIn("class='skip-link'", body)
                self.assertIn("id='main'", body)
                self.assertIn("aria-label='Primary'", body)
                self.assertNotIn("href='#'", body)
                self.assertNotIn("<script", body)
                self.assertNotIn("http://", body)
                self.assertNotIn("https://", body)
                self.assertNotIn("localStorage", body)
                self.assertNotIn("sessionStorage", body)
                self.assertIn("X-Content-Type-Options", response.headers)
                self.assertEqual(
                    response.headers["X-Content-Type-Options"], "nosniff"
                )
                csp = response.headers["Content-Security-Policy"]
                self.assertIn("default-src 'none'", csp)
                self.assertIn("frame-ancestors 'none'", csp)

    def test_login_page_has_labelled_form_and_no_secrets(self):
        response, body = self.login_page()
        self.assertEqual(response.status, 200)
        self.assertIn("Log in", body)
        self.assertIn("<label for='token'>Access token</label>", body)
        self.assertIn("type='password'", body)
        self.assertNotIn(TOKEN, body)
        self.assertNotIn("FG_UI_TOKEN=", body)
        self.assertEqual(response.headers["Referrer-Policy"], "no-referrer")

    def test_stylesheet_defines_responsive_and_focus_states(self):
        self.assertIn("@media (max-width: 980px)", STYLES)
        self.assertIn("@media (max-width: 640px)", STYLES)
        self.assertIn(":focus-visible", STYLES)
        self.assertIn("prefers-reduced-motion", STYLES)
        self.assertNotIn("@import", STYLES)
        self.assertNotIn("url(http", STYLES)
        self.assertIn("--gold", STYLES)

    def test_filters_are_labelled_and_values_are_escaped(self):
        response, body = self.get("/alerts?q=%3Cscript%3Ealert(1)%3C/script%3E")
        for label in ("Search", "Source", "Status", "Decoy", "Route"):
            self.assertIn(f">{label}</label>", body)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", body)
        self.assertNotIn("<script>alert(1)</script>", body)
        self.assertIn("Reset filters", body)

    def test_assurance_never_presents_synthetic_as_live(self):
        response, body = self.get("/assurance")
        self.assertIn("Synthetic canary", body)
        self.assertIn("Live sensor", body)
        self.assertIn("Not run", body)
        self.assertIn("Unverified", body)
        self.assertIn("proves the local decision path, not", body)
        self.assertNotIn("production ready", body.lower())
        # No stage card may claim live success with no recorded run.
        self.assertNotIn("Live sensor</strong><div class='detail'>A real decoy "
                         "file was probed and the resulting alert observed.</div>"
                         "</div><div><span class='badge badge-ok'>Passed", body)

    def test_overview_and_evidence_empty_states_are_explicit(self):
        response, body = self.get("/evidence")
        self.assertIn("Not configured", body)
        self.assertIn("No named destinations", body)
        self.assertIn("Failed packets", body)
        self.assertIn("export", body.lower())
        self.assertIn("backup", body.lower())
        self.engine.record_assurance(
            NOW, "canary", True, 0, {"stages": {"synthetic": {"status": "pass"}}}
        )
        response, body = self.get("/assurance")
        self.assertIn("Recent runs", body)

    def test_alert_detail_keeps_raw_evidence_secondary(self):
        alert = next(self.engine.export_alerts())
        response, body = self.get("/alert/" + alert["alert_id"])
        self.assertEqual(response.status, 200)
        self.assertIn("<details class='evidence'>", body)
        self.assertIn("What happened", body)
        self.assertIn("Timeline", body)
        self.assertIn("Acknowledge alert", body)
        self.assertIn("Response procedure", body)
        # Raw hashes are present but collapsed inside details/pre.
        self.assertIn(alert["raw_event_sha256"], body)
        self.assertIn("<pre>", body)

    def test_api_surface_and_headers_remain_scriptable(self):
        response = urllib.request.Request(self.base + "/api/report")
        for name, value in self.request_headers.items():
            response.add_header(name, value)
        with urllib.request.urlopen(response, timeout=10) as answer:
            payload = json.loads(answer.read())
            self.assertEqual(
                answer.headers["Content-Security-Policy"].split(";")[0],
                "default-src 'none'",
            )
        self.assertEqual(payload["decisions"]["alert"], 1)
        with urllib.request.urlopen(self.base + "/healthz", timeout=10) as answer:
            self.assertTrue(json.loads(answer.read())["ok"])
        metrics = urllib.request.Request(self.base + "/metrics")
        for name, value in self.request_headers.items():
            metrics.add_header(name, value)
        with urllib.request.urlopen(metrics, timeout=10) as answer:
            self.assertIn("fools_gold_alerts_total 1", answer.read().decode())


if __name__ == "__main__":
    unittest.main()
