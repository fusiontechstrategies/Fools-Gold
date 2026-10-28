"""Named destinations, route mappings, scoped retries and outbox migration."""

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from fools_gold.core import ContractError, Engine, Registry
from fools_gold.transport import deliver
from tests.test_contracts_v2 import linux
from tests.test_pilot import NOW, registry, s3


def engine_in(folder):
    return Engine(Registry(registry()), Path(folder) / "db.sqlite")


class DestinationTests(unittest.TestCase):
    def test_add_and_list_destinations(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = engine_in(folder)
            try:
                sink = Path(folder) / "a.log"
                engine.add_destination(
                    NOW, "soc-a", "wazuh", path=str(sink)
                )
                engine.add_destination(
                    NOW, "hec-b", "splunk", host="hec.example", port=8088
                )
                names = [item["name"] for item in engine.destinations()]
                self.assertEqual(names, ["hec-b", "soc-a"])
                self.assertEqual(
                    engine.destination("soc-a")["payload_format"], "wazuh"
                )
                with self.assertRaises(ContractError):
                    engine.add_destination(NOW, "soc-a", "wazuh", path=str(sink))
            finally:
                engine.close()

    def test_destination_validation(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = engine_in(folder)
            try:
                cases = (
                    ("Bad Name", "wazuh", {"path": "x"}),
                    ("x", "email", {"path": "x"}),
                    ("x", "splunk", {"path": "x"}),
                    ("x", "splunk", {"host": "h", "port": 0}),
                    ("x", "wazuh", {}),
                    ("x", "wazuh", {"host": "h", "path": "x"}),
                    ("x", "splunk", {"host": "http://h", "port": 8088}),
                )
                for name, fmt, kwargs in cases:
                    with self.subTest(case=(name, fmt, kwargs)), self.assertRaises(
                        ContractError
                    ):
                        engine.add_destination(NOW, name, fmt, **kwargs)
            finally:
                engine.close()

    def test_route_mapping_requires_a_destination(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = engine_in(folder)
            try:
                with self.assertRaises(ContractError):
                    engine.map_route(NOW, "soc-primary", "missing")
                engine.add_destination(
                    NOW, "soc-a", "wazuh", path=str(Path(folder) / "a.log")
                )
                engine.map_route(NOW, "soc-primary", "soc-a")
                self.assertEqual(
                    engine.route_destination("soc-primary"), "soc-a"
                )
                self.assertEqual(
                    [item["route"] for item in engine.routes()], ["soc-primary"]
                )
            finally:
                engine.close()


class ScopedDestinationTests(unittest.TestCase):
    def test_each_destination_has_its_own_queue(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = engine_in(folder)
            try:
                engine.process(s3(), NOW)
                engine.process(linux("501"), NOW)
                first = Path(folder) / "first.log"
                second = Path(folder) / "second.log"
                engine.add_destination(NOW, "first", "wazuh", path=str(first))
                engine.add_destination(NOW, "second", "wazuh", path=str(second))
                self.assertEqual(engine.outbox_enqueue("first", NOW), 2)
                self.assertEqual(engine.outbox_enqueue("second", NOW), 2)
                summary = deliver(engine, "first", NOW)
                self.assertTrue(summary["complete"])
                self.assertEqual(summary["destination"], "first")
                self.assertEqual(len(first.read_text(encoding="utf-8").splitlines()), 2)
                self.assertFalse(second.exists())
                report = engine.outbox_report()["outbox"]
                self.assertEqual(report["first"], {"sent": 2})
                self.assertEqual(report["second"], {"pending": 2})
            finally:
                engine.close()

    def test_route_filter_scopes_enqueue_per_destination(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = engine_in(folder)
            try:
                engine.process(s3(), NOW)
                engine.process(linux("502"), NOW)
                sink = Path(folder) / "routed.log"
                engine.add_destination(NOW, "routed", "wazuh", path=str(sink))
                self.assertEqual(
                    engine.outbox_enqueue("routed", NOW, route="soc-primary"), 1
                )
                batch = engine.outbox_batch("routed", 10)
                self.assertEqual(len(batch), 1)
                self.assertEqual(batch[0][1]["route"], "soc-primary")
            finally:
                engine.close()

    def test_failures_and_resets_are_scoped(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = engine_in(folder)
            try:
                engine.process(s3(), NOW)
                good = Path(folder) / "good.log"
                missing_parent = Path(folder) / "missing" / "bad.log"
                engine.add_destination(NOW, "good", "wazuh", path=str(good))
                engine.add_destination(
                    NOW, "bad", "wazuh", path=str(missing_parent)
                )
                engine.outbox_enqueue("good", NOW)
                from unittest.mock import patch

                with patch("fools_gold.transport.BACKOFF_SECONDS", (0.0, 0.0)), patch(
                    "fools_gold.transport.SEND_INTERVAL_SECONDS", 0
                ):
                    failed = deliver(engine, "bad", NOW)
                self.assertFalse(failed["complete"])
                report = engine.outbox_report()["outbox"]
                self.assertEqual(report["bad"].get("failed"), 1)
                self.assertEqual(report["good"].get("pending"), 1)
                self.assertEqual(engine.outbox_reset_failed("bad", NOW), 1)
                report = engine.outbox_report()["outbox"]
                self.assertEqual(report["bad"], {"pending": 1})
                self.assertEqual(report["good"], {"pending": 1})
            finally:
                engine.close()


class OutboxMigrationTests(unittest.TestCase):
    def test_legacy_outbox_rows_survive_with_legacy_destination_names(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "legacy.sqlite"
            connection = sqlite3.connect(str(path))
            connection.executescript(
                """
                CREATE TABLE decisions (event_key TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, result TEXT NOT NULL, created_at TEXT);
                CREATE TABLE alerts (id TEXT PRIMARY KEY, decoy TEXT NOT NULL, actor TEXT NOT NULL, opened_at TEXT NOT NULL, received_at TEXT NOT NULL, evidence TEXT NOT NULL, acknowledged_at TEXT, acknowledged_by TEXT, evidence_mac TEXT, prev_mac TEXT, route TEXT);
                CREATE TABLE outbox (alert_id TEXT NOT NULL, payload_format TEXT NOT NULL, state TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, last_error TEXT, updated_at TEXT NOT NULL, PRIMARY KEY (alert_id, payload_format));
                CREATE TABLE trail_files (digest TEXT PRIMARY KEY, processed_at TEXT NOT NULL);
                CREATE TABLE assurance_runs (id INTEGER PRIMARY KEY AUTOINCREMENT, ran_at TEXT NOT NULL, mode TEXT NOT NULL, ok INTEGER NOT NULL, failed_scenarios INTEGER NOT NULL, details TEXT NOT NULL, run_id TEXT);
                CREATE TABLE checkpoints (id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL, pruned_before TEXT NOT NULL, deleted_alerts INTEGER NOT NULL, boundary_prev_mac TEXT NOT NULL, first_retained_id TEXT, mac TEXT NOT NULL);
                CREATE TABLE acceptances (id INTEGER PRIMARY KEY AUTOINCREMENT, stage TEXT NOT NULL, note TEXT NOT NULL, actor TEXT NOT NULL, recorded_at TEXT NOT NULL);
                INSERT INTO outbox(alert_id,payload_format,state,attempts,last_error,updated_at)
                    VALUES('fg-legacy','wazuh','sent',1,NULL,'2026-01-01T00:00:00Z');
                INSERT INTO outbox(alert_id,payload_format,state,attempts,last_error,updated_at)
                    VALUES('fg-legacy-2','splunk','failed',3,'down','2026-01-02T00:00:00Z');
                """
            )
            connection.commit()
            connection.close()
            engine = Engine(Registry(registry()), path)
            try:
                columns = {
                    row[1] for row in engine.db.execute("PRAGMA table_info(outbox)")
                }
                self.assertIn("destination", columns)
                report = engine.outbox_report()["outbox"]
                self.assertEqual(report["wazuh"], {"sent": 1})
                self.assertEqual(report["splunk"], {"failed": 1})
                rows = engine.db.execute(
                    "SELECT alert_id,destination,payload_format FROM outbox "
                    "ORDER BY alert_id"
                ).fetchall()
                self.assertEqual(
                    rows,
                    [
                        ("fg-legacy", "wazuh", "wazuh"),
                        ("fg-legacy-2", "splunk", "splunk"),
                    ],
                )
            finally:
                engine.close()


class DestinationCliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.folder = Path(self.temp.name)
        self.registry = self.folder / "registry.json"
        self.registry.write_text(json.dumps(registry()), encoding="utf-8")
        self.database = self.folder / "db.sqlite"
        self.base = [
            "--registry",
            str(self.registry),
            "--database",
            str(self.database),
        ]

    def tearDown(self):
        self.temp.cleanup()

    def invoke(self, *args):
        import contextlib
        import io

        from fools_gold.cli import main

        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(self.base + list(args))
        return code, out.getvalue(), err.getvalue()

    def test_destination_and_route_commands(self):
        sink = self.folder / "feed.log"
        code, output, error = self.invoke(
            "destination",
            "add",
            "--name",
            "soc-a",
            "--format",
            "wazuh",
            "--path",
            str(sink),
        )
        self.assertEqual(code, 0, error)
        code, output, _ = self.invoke("destination", "list")
        self.assertEqual(json.loads(output)["destinations"][0]["name"], "soc-a")
        code, output, _ = self.invoke(
            "route", "map", "--route", "soc-primary", "--destination", "soc-a"
        )
        self.assertEqual(code, 0)
        code, output, _ = self.invoke("route", "list")
        self.assertEqual(json.loads(output)["routes"][0]["destination"], "soc-a")

    def test_deliver_requires_exactly_one_selector(self):
        code, _, error = self.invoke("deliver")
        self.assertEqual(code, 2)
        self.assertIn("exactly one", error)
        code, _, error = self.invoke(
            "deliver",
            "--destination",
            "soc-a",
            "--format",
            "wazuh",
            "--wazuh-output",
            str(self.folder / "x.log"),
        )
        self.assertEqual(code, 2)
        self.assertIn("exactly one", error)


if __name__ == "__main__":
    unittest.main()
