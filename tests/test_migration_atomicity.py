"""Outbox migration must be atomic, durable and recover interrupted artifacts."""

import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fools_gold.core import Engine, Registry
from tests.test_pilot import registry

LEGACY_SCHEMA = """
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


def make_legacy(folder: Path) -> Path:
    path = folder / "legacy.sqlite"
    connection = sqlite3.connect(str(path))
    connection.executescript(LEGACY_SCHEMA)
    connection.commit()
    connection.close()
    return path


class MigrationAtomicityTests(unittest.TestCase):
    def test_report_then_close_then_reopen_works(self):
        with tempfile.TemporaryDirectory() as folder:
            path = make_legacy(Path(folder))
            engine = Engine(Registry(registry()), path)
            try:
                self.assertFalse(engine.db.in_transaction)
                self.assertEqual(engine.report()["decisions"]["alert"], 0)
                self.assertEqual(
                    engine.outbox_report()["outbox"],
                    {"splunk": {"failed": 1}, "wazuh": {"sent": 1}},
                )
            finally:
                engine.close()
            reopened = Engine(Registry(registry()), path)
            try:
                columns = {
                    row[1]
                    for row in reopened.db.execute("PRAGMA table_info(outbox)")
                }
                self.assertIn("destination", columns)
                self.assertIsNone(
                    reopened.db.execute(
                        "SELECT name FROM sqlite_master WHERE name='outbox_v2'"
                    ).fetchone()
                )
                self.assertEqual(reopened.outbox_report()["outbox"]["wazuh"], {"sent": 1})
            finally:
                reopened.close()

    def test_stray_migration_artifact_is_rebuilt_from_legacy_rows(self):
        with tempfile.TemporaryDirectory() as folder:
            path = make_legacy(Path(folder))
            connection = sqlite3.connect(str(path))
            connection.execute(
                "CREATE TABLE outbox_v2 (alert_id TEXT, destination TEXT, "
                "payload_format TEXT, state TEXT, attempts INTEGER, "
                "last_error TEXT, updated_at TEXT, PRIMARY KEY(alert_id,destination))"
            )
            connection.execute(
                "INSERT INTO outbox_v2 VALUES('fg-partial','wazuh','wazuh','pending',0,NULL,'2026-01-03T00:00:00Z')"
            )
            connection.commit()
            connection.close()
            engine = Engine(Registry(registry()), path)
            try:
                rows = engine.db.execute(
                    "SELECT alert_id,destination,payload_format FROM outbox ORDER BY alert_id"
                ).fetchall()
                self.assertEqual(
                    rows,
                    [
                        ("fg-legacy", "wazuh", "wazuh"),
                        ("fg-legacy-2", "splunk", "splunk"),
                    ],
                )
                self.assertIsNone(
                    engine.db.execute(
                        "SELECT name FROM sqlite_master WHERE name='outbox_v2'"
                    ).fetchone()
                )
            finally:
                engine.close()
            second = Engine(Registry(registry()), path)
            try:
                self.assertEqual(second.outbox_report()["outbox"]["splunk"], {"failed": 1})
            finally:
                second.close()

    def test_interrupted_migration_rolls_back_and_recovers(self):
        with tempfile.TemporaryDirectory() as folder:
            path = make_legacy(Path(folder))

            def interrupted(engine):
                engine.db.execute(
                    "CREATE TABLE outbox_v2 (alert_id TEXT, destination TEXT, "
                    "payload_format TEXT, state TEXT, attempts INTEGER, "
                    "last_error TEXT, updated_at TEXT, PRIMARY KEY(alert_id,destination))"
                )
                raise RuntimeError("simulated interruption")

            with patch.object(Engine, "_migrate_outbox", interrupted):
                with self.assertRaises(RuntimeError):
                    Engine(Registry(registry()), path)
            # Legacy evidence must survive an interrupted initialization.
            check = sqlite3.connect(str(path))
            try:
                rows = check.execute(
                    "SELECT alert_id FROM outbox ORDER BY alert_id"
                ).fetchall()
            finally:
                check.close()
            self.assertEqual(rows, [("fg-legacy",), ("fg-legacy-2",)])
            engine = Engine(Registry(registry()), path)
            try:
                self.assertFalse(engine.db.in_transaction)
                self.assertEqual(
                    engine.outbox_report()["outbox"],
                    {"splunk": {"failed": 1}, "wazuh": {"sent": 1}},
                )
            finally:
                engine.close()

    def test_fresh_database_initializes_without_an_open_transaction(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "fresh.sqlite"
            engine = Engine(Registry(registry()), path)
            engine.close()
            reopened = Engine(Registry(registry()), path)
            try:
                self.assertFalse(reopened.db.in_transaction)
            finally:
                reopened.close()


if __name__ == "__main__":
    unittest.main()
