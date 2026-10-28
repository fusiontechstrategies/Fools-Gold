"""Console flows: login, overview, alerts, investigation, acknowledgment, pages."""

import http.cookiejar
import json
import re
import tempfile
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request
from datetime import timedelta
from pathlib import Path

from fools_gold.core import Engine, Registry
from fools_gold.ui import make_server
from tests.test_contracts_v2 import linux
from tests.test_pilot import NOW, registry, s3, windows

TOKEN = "synthetic-dashboard-token"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        return None


def make_engine(folder):
    engine = Engine(
        Registry(registry()), Path(folder) / "db.sqlite", thread_safe=True
    )
    engine.process(s3("ui-1"), NOW)
    engine.process(linux("501"), NOW + timedelta(seconds=1))
    acked = engine.process(s3("ui-acked"), NOW + timedelta(seconds=2))["alert"]
    engine.acknowledge(
        acked["alert_id"], "analyst-a", NOW + timedelta(minutes=1)
    )
    engine.outbox_enqueue("wazuh", NOW)
    engine.record_assurance(
        NOW,
        "canary",
        True,
        0,
        {
            "stages": {
                "synthetic": {"status": "pass"},
                "live": {"status": "not_run"},
                "transport": {"status": "not_run"},
                "ingestion": {"status": "unverified"},
                "analyst_acknowledgment": {"status": "unverified"},
            }
        },
    )
    return engine


class ConsoleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.folder = Path(self.temp.name)
        self.engine = make_engine(self.folder)
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
        with (opener or self.opener).open(request, timeout=10) as response:
            return response.status, response.read().decode(), response.headers

    def post(self, path, data, opener=None):
        body = urllib.parse.urlencode(data).encode()
        request = urllib.request.Request(self.base + path, data=body)
        request.add_header("Content-Type", "application/x-www-form-urlencoded")
        with (opener or self.opener).open(request, timeout=10) as response:
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
            raw.open(request, timeout=10)
        self.assertEqual(caught.exception.code, 303)
        cookie = caught.exception.headers["Set-Cookie"]
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Strict", cookie)
        self.assertNotIn("Max-Age", cookie)

    def test_overview_prioritizes_real_attention_items(self):
        self.login()
        status, body, _ = self.get("/")
        self.assertEqual(status, 200)
        for label in (
            "Unacknowledged",
            "Delivery pending",
            "Delivery failed",
            "Evidence integrity",
            "Assurance",
            "Retained alerts",
        ):
            self.assertIn(label, body)
        self.assertIn("Needs attention", body)
        self.assertIn("/alerts?ack=no", body)
        self.assertIn("/evidence#delivery", body)
        self.assertIn("/assurance", body)
        self.assertIn("2 unacknowledged alerts", body)

    def test_primary_navigation_reaches_every_page(self):
        self.login()
        pages = {
            "/": "Operations overview",
            "/alerts": "Triage queue",
            "/incidents": "Activity groups",
            "/assurance": "Assurance stages",
            "/evidence": "Evidence integrity",
        }
        for path, heading in pages.items():
            with self.subTest(path=path):
                status, body, _ = self.get(path)
                self.assertEqual(status, 200)
                self.assertIn(heading, body)
                active = re.findall(
                    r"<a class='nav-link'[^>]*aria-current=\"page\"", body
                )
                self.assertEqual(len(active), 1)
        status, body, _ = self.get("/alerts")
        self.assertIn('aria-current="page"', body)

    def test_alerts_filters_titles_chips_and_pagination(self):
        self.login()
        status, body, _ = self.get("/alerts")
        self.assertIn("S3 object read", body)
        self.assertIn("Linux file read", body)
        self.assertIn("Investigate", body)
        self.assertNotIn("name='analyst'", body)  # no per-row analyst forms
        status, body, _ = self.get("/alerts?source=linux.audit")
        self.assertIn("config-export.txt", body)
        self.assertNotIn("inventory.txt", body)
        self.assertIn("Source: Linux", body)
        self.assertIn("Reset filters", body)
        status, body, _ = self.get("/alerts?ack=no")
        self.assertIn("Unacknowledged", body)
        status, body, _ = self.get("/alerts?q=synthetic-intrusion")
        self.assertIn("S3 object read", body)
        status, body, _ = self.get("/alerts?page_size=1&page=2")
        self.assertIn("page 2 of 3", body)
        with self.assertRaises(urllib.error.HTTPError) as caught:
            self.get("/alerts?page_size=999")
        self.assertEqual(caught.exception.code, 400)
        with self.assertRaises(urllib.error.HTTPError) as caught:
            self.get("/alerts?source=unknown.source")
        self.assertEqual(caught.exception.code, 400)
        self.assertIn("Invalid request", caught.exception.read().decode())

    def test_filter_chip_removal_keeps_other_filters(self):
        self.login()
        status, body, _ = self.get("/alerts?source=linux.audit&ack=no")
        self.assertIn("Source: Linux", body)
        self.assertIn("href='/alerts?ack=no'", body)
        self.assertIn("Reset filters", body)
        status, filtered, _ = self.get("/alerts?ack=no")
        self.assertIn("Unacknowledged", filtered)
        self.assertNotIn("Source: Linux", filtered)

    def test_incidents_group_actors_without_attribution(self):
        self.login()
        status, body, _ = self.get("/incidents")
        self.assertIn("not attribution", body)
        self.assertIn("synthetic-intrusion-test", body)
        self.assertIn("/alerts?q=", body)
        self.assertIn("of", body)

    def test_assurance_separates_stages_and_guidance(self):
        self.login()
        status, body, _ = self.get("/assurance")
        self.assertIn("Synthetic canary", body)
        self.assertIn("Live sensor", body)
        self.assertIn("SIEM ingestion (external)", body)
        self.assertIn("Analyst acknowledgment", body)
        self.assertIn("Not run", body)
        self.assertIn("Unverified", body)
        self.assertIn("proves the local decision path, not live collection", body)
        self.assertIn("Completing unverified stages", body)
        self.engine.record_acceptance(
            NOW, "ingestion", "confirmed in index", "analyst-b"
        )
        status, body, _ = self.get("/assurance")
        self.assertIn("Operator verified", body)

    def test_evidence_page_reports_integrity_and_delivery_honestly(self):
        self.login()
        status, body, _ = self.get("/evidence")
        self.assertIn("Not configured", body)
        self.assertIn("No named destinations", body)
        self.assertIn("Route mappings", body)
        self.assertIn("Export and recovery", body)
        self.assertIn("Failed packets", body)

    def test_evidence_page_verifies_chain_and_scopes_destinations(self):
        engine = Engine(
            Registry(registry()),
            self.folder / "keyed.sqlite",
            mac_key=b"k" * 32,
            thread_safe=True,
        )
        try:
            engine.process(s3("k-1"), NOW)
            sink = self.folder / "feed.log"
            engine.add_destination(NOW, "soc-a", "wazuh", path=str(sink))
            engine.outbox_enqueue("soc-a", NOW)
            alert_id = engine.outbox_batch("soc-a", 10)[0][0]
            engine.outbox_mark("soc-a", alert_id, "failed", NOW, error="sink down")
            server = make_server(engine, TOKEN, 0)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            base = f"http://127.0.0.1:{server.server_address[1]}"
            jar = http.cookiejar.CookieJar()
            opener = urllib.request.build_opener(
                urllib.request.HTTPCookieProcessor(jar)
            )
            body = urllib.parse.urlencode({"token": TOKEN}).encode()
            request = urllib.request.Request(base + "/login", data=body)
            request.add_header(
                "Content-Type", "application/x-www-form-urlencoded"
            )
            opener.open(request, timeout=10).read()
            with opener.open(base + "/evidence", timeout=10) as response:
                page = response.read().decode()
            self.assertIn("Verified", page)
            self.assertIn("soc-a", page)
            self.assertIn("feed.log", page)
            self.assertNotIn(str(sink), page)  # protected path not exposed
            self.assertIn("sink down", page)
            self.assertIn(f"/alert/{alert_id}", page)
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
        finally:
            engine.close()

    def test_investigation_detail_reads_summary_timeline_and_evidence(self):
        self.login()
        alert = next(self.engine.export_alerts())
        status, body, _ = self.get("/alert/" + alert["alert_id"])
        self.assertEqual(status, 200)
        for label in (
            "What happened",
            "Timeline",
            "Event occurred at the source",
            "Received into local evidence",
            "Delivery to wazuh",
            "Response procedure",
            "Evidence",
            "Normalized event",
            "Hashes and identifiers",
        ):
            self.assertIn(label, body)
        self.assertIn('details', body)
        self.assertIn("Analyst name", body)
        self.assertIn("Acknowledge alert", body)

    def test_acknowledgment_flow_requires_csrf_and_reports_duplicates(self):
        self.login()
        alert = next(self.engine.export_alerts())
        status, body, _ = self.get("/alert/" + alert["alert_id"])
        csrf = re.search(r"name='csrf' value='([^']+)'", body).group(1)
        with self.assertRaises(urllib.error.HTTPError) as caught:
            self.post(
                "/acknowledge",
                {"alert_id": alert["alert_id"], "analyst": "a", "csrf": "bad"},
            )
        self.assertEqual(caught.exception.code, 400)
        self.assertIn(
            "session token", caught.exception.read().decode()
        )
        status, body = self.post(
            "/acknowledge",
            {
                "alert_id": alert["alert_id"],
                "analyst": "console-analyst",
                "csrf": csrf,
            },
        )
        self.assertEqual(status, 200)
        self.assertIn("Acknowledgement recorded", body)
        self.assertIn("console-analyst", body)
        with self.assertRaises(urllib.error.HTTPError) as caught:
            self.post(
                "/acknowledge",
                {
                    "alert_id": alert["alert_id"],
                    "analyst": "again",
                    "csrf": csrf,
                },
            )
        self.assertEqual(caught.exception.code, 400)
        self.assertIn("already been acknowledged", caught.exception.read().decode())

    def test_bearer_access_still_works_for_scripts(self):
        request = urllib.request.Request(self.base + "/api/report")
        request.add_header("Authorization", f"Bearer {TOKEN}")
        with urllib.request.urlopen(request, timeout=10) as response:
            payload = json.loads(response.read())
        self.assertEqual(payload["decisions"]["alert"], 3)
        request = urllib.request.Request(self.base + "/")
        request.add_header("Authorization", f"Bearer {TOKEN}")
        with urllib.request.urlopen(request, timeout=10) as response:
            self.assertIn("Operations overview", response.read().decode())

    def test_healthz_is_open_and_logout_invalidates(self):
        status, body, _ = self.get("/healthz")
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(body)["ok"])
        self.login()
        status, body, _ = self.get("/logout")
        self.assertIn("login", body.lower())
        status, body, _ = self.get("/")
        self.assertIn("login", body.lower())

    def test_hostile_values_are_escaped(self):
        hostile = windows("950")
        hostile["subject_sid"] = "<script>alert(1)</script>"
        self.engine.process(hostile, NOW + timedelta(seconds=5))
        self.login()
        status, body, _ = self.get("/alerts?q=950")
        self.assertIn("&lt;script&gt;", body)
        self.assertNotIn("<script>alert(1)</script>", body)
        alert_id = next(
            alert["alert_id"]
            for alert in self.engine.export_alerts()
            if alert["event"]["actor"] == "<script>alert(1)</script>"
        )
        status, body, _ = self.get("/alert/" + alert_id)
        self.assertIn("&lt;script&gt;", body)
        self.assertNotIn("<script>alert(1)</script>", body)

    def test_empty_states_and_unknown_pages(self):
        self.engine.db.execute("DELETE FROM alerts")
        self.engine.db.commit()
        self.login()
        status, body, _ = self.get("/alerts")
        self.assertIn("No alerts match these filters", body)
        status, body, _ = self.get("/alert/does-not-exist")
        self.assertIn("Alert not found", body)
        with self.assertRaises(urllib.error.HTTPError) as caught:
            self.get("/api/unknown")
        self.assertEqual(caught.exception.code, 404)
        with self.assertRaises(urllib.error.HTTPError) as caught:
            self.get("/no-such-page")
        self.assertEqual(caught.exception.code, 404)


if __name__ == "__main__":
    unittest.main()
