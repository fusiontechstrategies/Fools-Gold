"""Regression tests for defects found in the adversarial self-review."""

import json
import shutil
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
import zipfile
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

from fools_gold.core import ContractError, Engine, Registry, restore_database
from fools_gold.doctor import run_doctor
from fools_gold.reporting import build_bundle, verify_bundle
from fools_gold.transport import deliver
from fools_gold.ui import make_server
from tests.test_contracts_v2 import linux
from tests.test_pilot import NOW, registry, s3


def engine_in(folder, **kwargs):
    return Engine(Registry(registry()), Path(folder) / "db.sqlite", **kwargs)


class PruneOrphanTests(unittest.TestCase):
    def test_prune_removes_outbox_rows_whose_alert_was_deleted(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = engine_in(folder)
            try:
                engine.process(s3(), NOW)
                engine.outbox_enqueue("wazuh", NOW)
                engine.db.execute("DELETE FROM alerts")
                engine.db.commit()
                counts = engine.prune(NOW + timedelta(days=1), 30)
                self.assertGreaterEqual(counts["outbox"], 1)
                self.assertEqual(engine.outbox_report()["outbox"], {})
            finally:
                engine.close()


class RestoreSafetyTests(unittest.TestCase):
    def test_restore_rejects_source_with_uncommitted_wal(self):
        with tempfile.TemporaryDirectory() as folder:
            source = engine_in(folder)
            try:
                source.process(s3(), NOW)
            finally:
                source.close()
            live = Path(folder) / "live.sqlite"
            shutil.copy(Path(folder) / "db.sqlite", live)
            Path(str(live) + "-wal").write_bytes(b"pending")
            with self.assertRaises(ContractError):
                restore_database(live, Path(folder) / "restored.sqlite")


class RouteBatchTests(unittest.TestCase):
    def test_batch_filters_by_route_even_when_other_routes_are_pending(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = engine_in(folder)
            try:
                engine.process(s3(), NOW)
                engine.process(linux(), NOW)
                engine.outbox_enqueue("wazuh", NOW)
                self.assertEqual(len(engine.outbox_batch("wazuh", 10)), 2)
                routed = engine.outbox_batch("wazuh", 10, route="soc-primary")
                self.assertEqual(len(routed), 1)
                self.assertEqual(routed[0][1]["route"], "soc-primary")
                with tempfile.TemporaryDirectory() as sink_folder:
                    sink = Path(sink_folder) / "route.log"
                    summary = deliver(
                        engine, "wazuh", NOW, wazuh_output=str(sink),
                        route="soc-primary",
                    )
                    self.assertTrue(summary["complete"])
                    self.assertEqual(summary["sent"], 1)
                    records = [
                        json.loads(line)
                        for line in sink.read_text(encoding="utf-8").splitlines()
                    ]
                    self.assertEqual(len(records), 1)
                    self.assertEqual(records[0]["fg_actor"], "uid:1001")
            finally:
                engine.close()


class DashboardHardeningTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.engine = engine_in(self.temp.name, thread_safe=True)
        for index in range(3):
            self.engine.process(s3(f"synthetic-u-{index}"), NOW)
        self.server = make_server(self.engine, "synthetic-token-123456", 0)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.engine.close()
        self.temp.cleanup()

    def get(self, path):
        request = urllib.request.Request(self.base + path)
        request.add_header("Authorization", "Bearer synthetic-token-123456")
        with urllib.request.urlopen(request, timeout=5) as response:  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
            return response, response.read().decode()

    def test_alerts_endpoint_is_bounded(self):
        response, body = self.get("/api/alerts?limit=1")
        self.assertEqual(len(json.loads(body)["alerts"]), 1)
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(response.headers["Cache-Control"], "no-store")
        for bad in ("0", "5001", "abc"):
            with self.subTest(limit=bad), self.assertRaises(urllib.error.HTTPError) as caught:
                self.get(f"/api/alerts?limit={bad}")
            self.assertEqual(caught.exception.code, 400)


class DoctorHostMismatchTests(unittest.TestCase):
    def test_file_decoys_for_another_host_warn(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = engine_in(folder)
            try:
                with patch(
                    "fools_gold.doctor.platform.node", return_value="other-host"
                ):
                    outcome = run_doctor(engine, now=NOW)
                statuses = {
                    check["name"]: check["status"] for check in outcome["checks"]
                }
                self.assertEqual(statuses["decoy_files"], "warn")
            finally:
                engine.close()

    def test_bad_max_assurance_hours_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = engine_in(folder)
            try:
                for value in (-1, 87601, "24"):
                    with self.assertRaises(ContractError):
                        run_doctor(engine, max_assurance_hours=value, now=NOW)
            finally:
                engine.close()


class BundleManifestHardeningTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.folder = Path(self.temp.name)
        self.engine = engine_in(self.temp.name)
        self.engine.process(s3(), NOW)
        self.bundle = self.folder / "case.zip"
        build_bundle(self.engine, self.bundle, now=NOW)

    def tearDown(self):
        self.engine.close()
        self.temp.cleanup()

    def _rewrite(self, name, manifest_edit=None, extra=None):
        with zipfile.ZipFile(self.bundle) as source:
            entries = [(name, source.read(name)) for name in source.namelist()]
        if manifest_edit is not None:
            entries = [
                (
                    entry_name,
                    (
                        json.dumps(
                            manifest_edit(json.loads(data)),
                            sort_keys=True,
                            separators=(",", ":"),
                        ).encode()
                        if entry_name == "manifest.json"
                        else data
                    ),
                )
                for entry_name, data in entries
            ]
        target = self.folder / name
        with zipfile.ZipFile(target, "x") as destination:
            for entry_name, data in entries:
                destination.writestr(entry_name, data)
        if extra is not None:
            with zipfile.ZipFile(target, "a") as destination:
                destination.writestr(extra, b"duplicate")
        return target

    def test_unsupported_schema_is_rejected(self):
        target = self._rewrite(
            "schema.zip",
            manifest_edit=lambda manifest: {**manifest, "schema_version": 2},
        )
        with self.assertRaises(ContractError):
            verify_bundle(target)

    def test_invalid_integrity_flag_is_rejected(self):
        target = self._rewrite(
            "flag.zip",
            manifest_edit=lambda manifest: {**manifest, "integrity_ok": "yes"},
        )
        with self.assertRaises(ContractError):
            verify_bundle(target)

    def test_duplicate_entries_are_rejected(self):
        target = self._rewrite("dupe.zip", extra="alerts.jsonl")
        with self.assertRaises(ContractError):
            verify_bundle(target)


if __name__ == "__main__":
    unittest.main()
