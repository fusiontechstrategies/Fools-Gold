"""Retention must not break signed evidence integrity."""

import json
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

from fools_gold.core import ContractError, Engine, Registry
from fools_gold.reporting import build_bundle, verify_bundle
from tests.test_pilot import NOW, registry, s3

KEY = b"k" * 32


def keyed(folder):
    return Engine(Registry(registry()), Path(folder) / "db.sqlite", mac_key=KEY)


def two_alerts(engine):
    first = s3("synthetic-retention-1")
    first["eventTime"] = "2000-01-01T00:00:00Z"
    engine.process(first, NOW)
    second = s3("synthetic-retention-2")
    second["eventTime"] = "2000-01-02T00:00:00Z"
    engine.process(second, NOW + timedelta(days=10))
    return first, second


class RetentionCheckpointTests(unittest.TestCase):
    def test_pruning_a_signed_predecessor_keeps_the_chain_verifiable(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = keyed(folder)
            try:
                two_alerts(engine)
                before = engine.verify_integrity()
                self.assertTrue(before["ok"])
                counts = engine.prune(NOW + timedelta(days=11), 5)
                self.assertEqual(counts["alerts"], 1)
                outcome = engine.verify_integrity()
                self.assertTrue(outcome["ok"], outcome)
                self.assertEqual(outcome["alerts"], 1)
                self.assertEqual(outcome["retention"]["applied"], 1)
                checkpoints = engine.db.execute(
                    "SELECT boundary_prev_mac, first_retained_id FROM checkpoints"
                ).fetchall()
                self.assertEqual(len(checkpoints), 1)
                self.assertEqual(checkpoints[0][1], engine.export_alerts().__next__()["alert_id"])
            finally:
                engine.close()

    def test_unauthorized_deletion_is_still_detected(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = keyed(folder)
            try:
                two_alerts(engine)
                engine.db.execute("DELETE FROM alerts WHERE rowid=1")
                engine.db.commit()
                outcome = engine.verify_integrity()
                self.assertFalse(outcome["ok"])
                self.assertIn(
                    "no retention checkpoint",
                    outcome["failures"][0]["reason"],
                )
            finally:
                engine.close()

    def test_tampered_checkpoint_is_detected(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = keyed(folder)
            try:
                two_alerts(engine)
                engine.prune(NOW + timedelta(days=11), 5)
                engine.db.execute(
                    "UPDATE checkpoints SET boundary_prev_mac='forged'"
                )
                engine.db.commit()
                outcome = engine.verify_integrity()
                self.assertFalse(outcome["ok"])
                reasons = {failure["reason"] for failure in outcome["failures"]}
                self.assertTrue(
                    any("retention checkpoint" in reason for reason in reasons)
                )
            finally:
                engine.close()

    def test_pruning_everything_leaves_a_verifiable_empty_chain(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = keyed(folder)
            try:
                two_alerts(engine)
                engine.prune(NOW + timedelta(days=30), 5)
                outcome = engine.verify_integrity()
                self.assertTrue(outcome["ok"])
                self.assertEqual(outcome["alerts"], 0)
            finally:
                engine.close()

    def test_unkeyed_databases_do_not_gain_checkpoints(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = Engine(Registry(registry()), Path(folder) / "db.sqlite")
            try:
                first = s3("synthetic-unsigned-1")
                first["eventTime"] = "2000-01-01T00:00:00Z"
                engine.process(first, NOW)
                engine.prune(NOW + timedelta(days=30), 5)
                count = engine.db.execute(
                    "SELECT COUNT(*) FROM checkpoints"
                ).fetchone()[0]
                self.assertEqual(count, 0)
                with self.assertRaises(ContractError):
                    engine.verify_integrity()
            finally:
                engine.close()

    def test_backup_and_restore_preserve_the_retention_boundary(self):
        from fools_gold.core import restore_database

        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            engine = keyed(root)
            try:
                two_alerts(engine)
                engine.prune(NOW + timedelta(days=11), 5)
                backup = root / "backup.sqlite"
                engine.backup(backup)
            finally:
                engine.close()
            restored_path = root / "restored.sqlite"
            restore_database(backup, restored_path)
            restored = Engine(Registry(registry()), restored_path, mac_key=KEY)
            try:
                outcome = restored.verify_integrity()
                self.assertTrue(outcome["ok"], outcome)
                self.assertEqual(outcome["retention"]["applied"], 1)
            finally:
                restored.close()

    def test_bundle_carries_retention_boundary_and_detects_tampering(self):
        import zipfile

        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            engine = keyed(root)
            try:
                two_alerts(engine)
                engine.prune(NOW + timedelta(days=11), 5)
                target = root / "case.zip"
                build_bundle(engine, target, now=NOW)
            finally:
                engine.close()
            outcome = verify_bundle(target, KEY)
            self.assertTrue(outcome["ok"], outcome)
            self.assertEqual(outcome["signature"], "verified")
            with zipfile.ZipFile(target) as archive:
                entries = {name: archive.read(name) for name in archive.namelist()}
            self.assertIn("checkpoints.jsonl", entries)
            self.assertTrue(entries["checkpoints.jsonl"].strip())
            lines = entries["checkpoints.jsonl"].splitlines()
            self.assertEqual(json.loads(lines[0])["deleted_alerts"], 1)
            tampered = root / "tampered.zip"
            entries["checkpoints.jsonl"] = b'{"id": 99}\n'
            with zipfile.ZipFile(tampered, "x") as destination:
                for name, data in entries.items():
                    destination.writestr(name, data)
            tampered_outcome = verify_bundle(tampered, KEY)
            self.assertFalse(tampered_outcome["ok"])
            self.assertIn("checkpoints.jsonl", tampered_outcome["failures"])


class RestoreSchemaCheckpointTests(unittest.TestCase):
    def test_restore_requires_the_checkpoint_table(self):
        import sqlite3

        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = root / "old.sqlite"
            connection = sqlite3.connect(str(source))
            connection.executescript(
                """
                CREATE TABLE decisions (event_key TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, result TEXT NOT NULL, created_at TEXT);
                CREATE TABLE alerts (id TEXT PRIMARY KEY, decoy TEXT NOT NULL, actor TEXT NOT NULL, opened_at TEXT NOT NULL, received_at TEXT NOT NULL, evidence TEXT NOT NULL, acknowledged_at TEXT, acknowledged_by TEXT, evidence_mac TEXT, prev_mac TEXT, route TEXT);
                CREATE TABLE outbox (alert_id TEXT NOT NULL, payload_format TEXT NOT NULL, state TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, last_error TEXT, updated_at TEXT NOT NULL, PRIMARY KEY (alert_id, payload_format));
                CREATE TABLE trail_files (digest TEXT PRIMARY KEY, processed_at TEXT NOT NULL);
                CREATE TABLE assurance_runs (id INTEGER PRIMARY KEY AUTOINCREMENT, ran_at TEXT NOT NULL, mode TEXT NOT NULL, ok INTEGER NOT NULL, failed_scenarios INTEGER NOT NULL, details TEXT NOT NULL);
                """
            )
            connection.commit()
            connection.close()
            destination = root / "live.sqlite"
            with self.assertRaises(ContractError):
                from fools_gold.core import restore_database

                restore_database(source, destination)


if __name__ == "__main__":
    unittest.main()
