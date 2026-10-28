"""Maintenance, retention, backup/restore and route-filtered delivery tests."""

import sqlite3
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

from fools_gold.core import (
    ContractError,
    Engine,
    Registry,
    restore_database,
)
from tests.test_contracts_v2 import linux
from tests.test_pilot import NOW, registry, s3


def open_engine(path=None, mac_key=None):
    return Engine(Registry(registry()), path or ":memory:", mac_key=mac_key)


class DurabilityTests(unittest.TestCase):
    def test_file_databases_run_in_wal_mode(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = open_engine(Path(folder) / "db.sqlite")
            try:
                mode = engine.db.execute("PRAGMA journal_mode").fetchone()[0]
                self.assertEqual(mode.lower(), "wal")
            finally:
                engine.close()

    def test_decisions_carry_created_at(self):
        engine = open_engine()
        try:
            engine.process(s3(), NOW)
            row = engine.db.execute(
                "SELECT created_at FROM decisions"
            ).fetchone()
            self.assertEqual(row[0], "2026-10-02T12:00:00Z")
        finally:
            engine.close()

    def test_legacy_decisions_table_is_migrated(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "legacy.sqlite"
            connection = sqlite3.connect(str(path))
            connection.executescript(
                """
                CREATE TABLE decisions (
                    event_key TEXT PRIMARY KEY, fingerprint TEXT NOT NULL,
                    result TEXT NOT NULL
                );
                CREATE TABLE alerts (
                    id TEXT PRIMARY KEY, decoy TEXT NOT NULL, actor TEXT NOT NULL,
                    opened_at TEXT NOT NULL, received_at TEXT NOT NULL,
                    evidence TEXT NOT NULL, acknowledged_at TEXT, acknowledged_by TEXT
                );
                """
            )
            connection.commit()
            connection.close()
            engine = open_engine(path)
            try:
                columns = {
                    row[1]
                    for row in engine.db.execute("PRAGMA table_info(decisions)")
                }
                self.assertIn("created_at", columns)
                self.assertEqual(engine.process(s3(), NOW)["decision"], "alert")
            finally:
                engine.close()


class AssuranceRecordTests(unittest.TestCase):
    def test_record_and_read_history(self):
        engine = open_engine()
        try:
            self.assertIsNone(engine.last_assurance())
            engine.record_assurance(NOW, "canary", True, 0, {"scenarios": 4})
            engine.record_assurance(
                NOW + timedelta(hours=1), "canary", False, 1, {"error": "late"}
            )
            history = engine.assurance_history(10)
            self.assertEqual(len(history), 2)
            self.assertEqual(history[0]["mode"], "canary")
            self.assertFalse(history[0]["ok"])
            self.assertEqual(history[1]["details"], {"scenarios": 4})
            latest = engine.last_assurance()
            self.assertEqual(latest["failed_scenarios"], 1)
        finally:
            engine.close()

    def test_input_validation(self):
        engine = open_engine()
        try:
            with self.assertRaises(ContractError):
                engine.record_assurance(NOW, "", True, 0, {})
            with self.assertRaises(ContractError):
                engine.record_assurance(NOW, "canary", True, -1, {})
            with self.assertRaises(ContractError):
                engine.record_assurance(NOW, "canary", True, 0, [])
            with self.assertRaises(ContractError):
                engine.assurance_history(0)
        finally:
            engine.close()


class RetentionTests(unittest.TestCase):
    def test_prune_removes_only_old_rows(self):
        engine = open_engine()
        try:
            engine.process(s3(), NOW)
            engine.outbox_enqueue("wazuh", NOW)
            engine.record_assurance(NOW, "canary", True, 0, {})
            counts = engine.prune(NOW + timedelta(days=100), 30)
            self.assertEqual(counts["alerts"], 1)
            self.assertEqual(counts["outbox"], 1)
            self.assertEqual(counts["assurance_runs"], 1)
            self.assertEqual(counts["decisions"], 1)
            self.assertEqual(engine.report()["decisions"]["alert"], 0)
        finally:
            engine.close()

    def test_prune_keeps_recent_rows(self):
        engine = open_engine()
        try:
            engine.process(s3(), NOW)
            counts = engine.prune(NOW + timedelta(days=1), 30)
            self.assertEqual(counts["alerts"], 0)
            self.assertEqual(engine.report()["decisions"]["alert"], 1)
        finally:
            engine.close()

    def test_prune_bounds(self):
        engine = open_engine()
        try:
            for days in (0, -1, 3651):
                with self.assertRaises(ContractError):
                    engine.prune(NOW, days)
        finally:
            engine.close()


class BackupRestoreTests(unittest.TestCase):
    def test_backup_and_restore_round_trip(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / "live.sqlite"
            engine = open_engine(source)
            try:
                engine.process(s3(), NOW)
                target = Path(folder) / "backup.sqlite"
                engine.backup(target)
            finally:
                engine.close()
            restored = Path(folder) / "restored.sqlite"
            restore_database(target, restored)
            verification = open_engine(restored)
            try:
                self.assertEqual(verification.report()["decisions"]["alert"], 1)
            finally:
                verification.close()

    def test_backup_rejects_existing_target_and_missing_directory(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = open_engine(Path(folder) / "live.sqlite")
            try:
                target = Path(folder) / "backup.sqlite"
                engine.db.execute("SELECT 1")
                target.write_bytes(b"occupied")
                with self.assertRaises(ContractError):
                    engine.backup(target)
                with self.assertRaises(ContractError):
                    engine.backup(Path(folder) / "missing" / "backup.sqlite")
            finally:
                engine.close()

    def test_restore_rejects_invalid_sources(self):
        with tempfile.TemporaryDirectory() as folder:
            bogus = Path(folder) / "bogus.sqlite"
            bogus.write_bytes(b"not a database")
            destination = Path(folder) / "dest.sqlite"
            with self.assertRaises(ContractError):
                restore_database(bogus, destination)
            with self.assertRaises(ContractError):
                restore_database(Path(folder) / "absent.sqlite", destination)


class RouteDeliveryTests(unittest.TestCase):
    def test_enqueue_filters_by_route(self):
        engine = open_engine()
        try:
            engine.process(s3(), NOW)
            engine.process(linux(), NOW)
            self.assertEqual(engine.outbox_enqueue("wazuh", NOW, route="soc-primary"), 1)
            batch = engine.outbox_batch("wazuh", 10)
            self.assertEqual(len(batch), 1)
            self.assertEqual(batch[0][1]["route"], "soc-primary")
            self.assertEqual(engine.outbox_enqueue("wazuh", NOW), 1)
            self.assertEqual(len(engine.outbox_batch("wazuh", 10)), 2)
        finally:
            engine.close()

    def test_empty_route_is_rejected(self):
        engine = open_engine()
        try:
            with self.assertRaises(ContractError):
                engine.outbox_enqueue("wazuh", NOW, route="")
        finally:
            engine.close()


if __name__ == "__main__":
    unittest.main()
