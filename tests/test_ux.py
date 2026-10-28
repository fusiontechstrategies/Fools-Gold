"""Doctor, onboarding (init/plant/demo) and dashboard tests."""

import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from datetime import timedelta
from pathlib import Path

from fools_gold.core import Engine, Registry
from fools_gold.doctor import run_doctor
from fools_gold.onboarding import create_demo, write_decoy, write_key, write_registry
from fools_gold.ui import make_server
from tests.test_pilot import NOW, registry, s3

TOKEN = "synthetic-dashboard-token"


def engine_in(folder, **kwargs):
    return Engine(Registry(registry()), Path(folder) / "db.sqlite", **kwargs)


class DoctorTests(unittest.TestCase):
    def test_healthy_state_passes(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = engine_in(folder, mac_key=b"k" * 32)
            try:
                engine.process(s3(), NOW)
                engine.record_assurance(NOW, "canary", True, 0, {})
                outcome = run_doctor(
                    engine, max_assurance_hours=24, now=NOW
                )
                self.assertTrue(outcome["ok"])
                names = {check["name"] for check in outcome["checks"]}
                self.assertIn("evidence_integrity", names)
                self.assertIn("delivery_outbox", names)
                self.assertIn("assurance", names)
            finally:
                engine.close()

    def test_missing_assurance_and_inbox_fail(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = engine_in(folder)
            try:
                outcome = run_doctor(
                    engine,
                    inbox=str(Path(folder) / "nope"),
                    max_assurance_hours=24,
                    now=NOW,
                )
                self.assertFalse(outcome["ok"])
                failing = {
                    check["name"]
                    for check in outcome["checks"]
                    if check["status"] == "fail"
                }
                self.assertIn("assurance", failing)
                self.assertIn("trail_inbox", failing)
            finally:
                engine.close()

    def test_expired_decoy_warns_and_failed_outbox_warns(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = engine_in(folder)
            try:
                engine.process(s3(), NOW)
                engine.outbox_enqueue("wazuh", NOW)
                alert_id = engine.outbox_batch("wazuh", 10)[0][0]
                engine.outbox_mark("wazuh", alert_id, "failed", NOW, error="x")
                outcome = run_doctor(engine, now=NOW + timedelta(days=40))
                statuses = {check["name"]: check["status"] for check in outcome["checks"]}
                self.assertEqual(statuses["registry"], "warn")
                self.assertEqual(statuses["delivery_outbox"], "warn")
            finally:
                engine.close()


class OnboardingTests(unittest.TestCase):
    def test_init_writes_valid_registry_and_key(self):
        with tempfile.TemporaryDirectory() as folder:
            path = write_registry(
                folder,
                owner="synthetic-soc",
                s3={
                    "bucket": "synthetic-decoy-bucket",
                    "key": "backups/inventory.txt",
                    "account": "000000000000",
                    "region": "us-gov-west-1",
                },
                windows={
                    "host": "synthetic-fs01",
                    "path": "C:\\SyntheticDecoys\\config-export.txt",
                },
                linux={
                    "host": "synthetic-linux01",
                    "path": "/opt/decoys/config-export.txt",
                },
                now=NOW,
            )
            document = json.loads(Path(path).read_text(encoding="utf-8"))
            snapshot = Registry(document)
            self.assertEqual(len(snapshot.decoys), 3)
            key_path = write_key(folder)
            key_text = Path(key_path).read_text(encoding="ascii").strip()
            self.assertRegex(key_text, r"^[0-9a-f]{64}$")
            with self.assertRaises(Exception):
                write_registry(folder, owner="x", windows={"host": "h", "path": "C:\\x"}, now=NOW)
            with self.assertRaises(Exception):
                write_key(folder)

    def test_init_requires_a_decoy(self):
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaises(Exception):
                write_registry(folder, owner="synthetic-soc", now=NOW)

    def test_plant_writes_watermarked_decoys(self):
        with tempfile.TemporaryDirectory() as folder:
            for kind in ("aws-credentials", "ssh-key", "config-export"):
                target = Path(folder) / f"{kind}.txt"
                write_decoy(kind, target)
                content = target.read_text(encoding="utf-8")
                self.assertIn("SYNTHETIC", content)
                self.assertLess(len(content), 4096)
                with self.assertRaises(Exception):
                    write_decoy(kind, target)
                write_decoy(kind, target, force=True)
            with self.assertRaises(Exception):
                write_decoy("honeypot-executable", Path(folder) / "x")

    def test_demo_produces_report_and_database(self):
        with tempfile.TemporaryDirectory() as folder:
            result = create_demo(folder, now=NOW)
            report = Path(result["report"]).read_text(encoding="utf-8")
            self.assertEqual(result["alerts"], 2)
            self.assertIn("Fool's Gold demo report", report)
            self.assertIn("Synthetic canary", report)
            database = Path(result["database"])
            engine = Engine(
                Registry(
                    json.loads(
                        Path(result["registry"]).read_text(encoding="utf-8")
                    )
                ),
                database,
            )
            try:
                self.assertEqual(engine.report()["decisions"]["alert"], 2)
                self.assertEqual(engine.report()["alerts_acknowledged"], 2)
            finally:
                engine.close()
            with self.assertRaises(Exception):
                create_demo(folder, now=NOW)


class DashboardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.engine = engine_in(self.temp.name, thread_safe=True)
        self.engine.process(s3(), NOW)
        self.server = make_server(self.engine, TOKEN, 0)
        self.thread = threading.Thread(
            target=self.server.serve_forever, daemon=True
        )
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.engine.close()
        self.temp.cleanup()

    def get(self, path, token=None):
        request = urllib.request.Request(self.base + path)
        if token:
            request.add_header("Authorization", f"Bearer {token}")
        with urllib.request.urlopen(request, timeout=5) as response:  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
            return response.status, response.read().decode()

    def post(self, path, payload, token=None):
        request = urllib.request.Request(
            self.base + path,
            data=json.dumps(payload).encode(),
            method="POST",
        )
        request.add_header("Content-Type", "application/json")
        if token:
            request.add_header("Authorization", f"Bearer {token}")
        with urllib.request.urlopen(request, timeout=5) as response:  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
            return response.status, response.read().decode()

    def test_healthz_is_open_and_binds_loopback(self):
        self.assertEqual(self.server.server_address[0], "127.0.0.1")
        status, _ = self.get("/healthz")
        self.assertEqual(status, 200)

    def test_unauthenticated_browsing_redirects_to_login(self):
        request = urllib.request.Request(self.base + "/")
        with urllib.request.urlopen(request, timeout=5) as response:  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
            self.assertEqual(response.status, 200)
            self.assertIn("login", response.read().decode().lower())
        for path in ("/api/alerts", "/metrics"):
            with self.subTest(path=path), self.assertRaises(urllib.error.HTTPError) as caught:
                self.get(path)
            self.assertEqual(caught.exception.code, 401)

    def test_authenticated_reads(self):
        status, body = self.get("/api/alerts", TOKEN)
        self.assertEqual(status, 200)
        self.assertEqual(len(json.loads(body)["alerts"]), 1)
        status, body = self.get("/metrics", TOKEN)
        self.assertIn("fools_gold_alerts_total 1", body)
        status, body = self.get("/api/report", TOKEN)
        self.assertEqual(json.loads(body)["decisions"]["alert"], 1)
        status, body = self.get("/api/incidents", TOKEN)
        self.assertEqual(len(json.loads(body)["incidents"]), 1)
        status, body = self.get("/", TOKEN)
        self.assertIn("alerts", body)

    def test_acknowledge_via_api_and_double_ack_fails(self):
        alerts = list(self.engine.export_alerts())
        alert_id = alerts[0]["alert_id"]
        status, body = self.post(
            "/api/acknowledge",
            {"alert_id": alert_id, "analyst": "dashboard-analyst"},
            TOKEN,
        )
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(body)["acknowledged"])
        with self.assertRaises(urllib.error.HTTPError) as caught:
            self.post(
                "/api/acknowledge",
                {"alert_id": alert_id, "analyst": "again"},
                TOKEN,
            )
        self.assertEqual(caught.exception.code, 400)

    def test_bad_payloads_and_unknown_paths(self):
        with self.assertRaises(urllib.error.HTTPError) as caught:
            self.post("/api/acknowledge", {"alert_id": "missing"}, TOKEN)
        self.assertEqual(caught.exception.code, 400)
        with self.assertRaises(urllib.error.HTTPError) as caught:
            self.get("/api/unknown", TOKEN)
        self.assertEqual(caught.exception.code, 404)

    def test_server_rejects_weak_tokens(self):
        for token in ("", "short", "x" * 257, "bad\ntoken" + "x" * 10):
            with self.assertRaises(Exception):
                make_server(self.engine, token, 0)


if __name__ == "__main__":
    unittest.main()
