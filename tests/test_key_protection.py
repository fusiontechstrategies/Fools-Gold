"""Signed chains must not be damaged by keyless or wrongly keyed writes."""

import contextlib
import io
import json
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

from fools_gold.cli import main
from fools_gold.core import ContractError, Engine, Registry
from tests.test_pilot import NOW, registry, s3

KEY = b"k" * 32
WRONG = b"w" * 32


def signed_engine(folder):
    engine = Engine(Registry(registry()), Path(folder) / "db.sqlite", mac_key=KEY)
    first = s3("synthetic-signed-1")
    first["eventTime"] = "2000-01-01T00:00:00Z"
    engine.process(first, NOW)
    second = s3("synthetic-signed-2")
    second["eventTime"] = "2000-01-02T00:00:00Z"
    engine.process(second, NOW + timedelta(days=10))
    return engine


class KeyProtectionTests(unittest.TestCase):
    def test_keyless_prune_is_refused_and_leaves_evidence_intact(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = signed_engine(folder)
            try:
                self.assertTrue(engine.verify_integrity()["ok"])
            finally:
                engine.close()
            keyless = Engine(Registry(registry()), Path(folder) / "db.sqlite")
            try:
                self.assertEqual(keyless.report()["decisions"]["alert"], 2)
                self.assertEqual(len(list(keyless.export_alerts())), 2)
                with self.assertRaises(ContractError):
                    keyless.prune(NOW + timedelta(days=30), 5)
                self.assertEqual(keyless.report()["decisions"]["alert"], 2)
            finally:
                keyless.close()
            keyed = Engine(Registry(registry()), Path(folder) / "db.sqlite", mac_key=KEY)
            try:
                outcome = keyed.verify_integrity()
                self.assertTrue(outcome["ok"], outcome)
                self.assertEqual(outcome["alerts"], 2)
            finally:
                keyed.close()

    def test_wrong_key_prune_is_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = signed_engine(folder)
            engine.close()
            wrong = Engine(
                Registry(registry()), Path(folder) / "db.sqlite", mac_key=WRONG
            )
            try:
                with self.assertRaises(ContractError):
                    wrong.prune(NOW + timedelta(days=30), 5)
                self.assertEqual(wrong.report()["decisions"]["alert"], 2)
            finally:
                wrong.close()

    def test_correct_key_prune_succeeds_and_verifies(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = signed_engine(folder)
            try:
                counts = engine.prune(NOW + timedelta(days=11), 5)
                self.assertEqual(counts["alerts"], 1)
                outcome = engine.verify_integrity()
                self.assertTrue(outcome["ok"], outcome)
                self.assertEqual(outcome["retention"]["applied"], 1)
            finally:
                engine.close()

    def test_keyless_ingest_into_a_signed_chain_is_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = signed_engine(folder)
            engine.close()
            keyless = Engine(Registry(registry()), Path(folder) / "db.sqlite")
            try:
                with self.assertRaises(ContractError):
                    keyless.process(s3("synthetic-signed-3"), NOW)
                self.assertEqual(keyless.report()["decisions"]["alert"], 2)
            finally:
                keyless.close()

    def test_wrong_key_ingest_is_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = signed_engine(folder)
            engine.close()
            wrong = Engine(
                Registry(registry()), Path(folder) / "db.sqlite", mac_key=WRONG
            )
            try:
                with self.assertRaises(ContractError):
                    wrong.process(s3("synthetic-signed-3"), NOW)
                self.assertEqual(wrong.report()["decisions"]["alert"], 2)
            finally:
                wrong.close()

    def test_correct_key_continues_the_signed_chain(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = signed_engine(folder)
            try:
                result = engine.process(s3("synthetic-signed-3"), NOW)
                self.assertEqual(result["decision"], "alert")
                outcome = engine.verify_integrity()
                self.assertTrue(outcome["ok"], outcome)
                self.assertEqual(outcome["alerts"], 3)
            finally:
                engine.close()

    def test_acknowledgment_remains_allowed_without_the_key(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = signed_engine(folder)
            alert_id = next(engine.export_alerts())["alert_id"]
            engine.close()
            keyless = Engine(Registry(registry()), Path(folder) / "db.sqlite")
            try:
                keyless.acknowledge(alert_id, "keyless-analyst", NOW + timedelta(days=11))
                self.assertEqual(keyless.report()["alerts_acknowledged"], 1)
            finally:
                keyless.close()
            keyed = Engine(Registry(registry()), Path(folder) / "db.sqlite", mac_key=KEY)
            try:
                self.assertTrue(keyed.verify_integrity()["ok"])
            finally:
                keyed.close()

    def test_unsigned_database_allows_keyless_prune(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = Engine(Registry(registry()), Path(folder) / "db.sqlite")
            try:
                first = s3("synthetic-unsigned-1")
                first["eventTime"] = "2000-01-01T00:00:00Z"
                engine.process(first, NOW)
                counts = engine.prune(NOW + timedelta(days=30), 5)
                self.assertEqual(counts["alerts"], 1)
                checkpoints = engine.db.execute(
                    "SELECT COUNT(*) FROM checkpoints"
                ).fetchone()[0]
                self.assertEqual(checkpoints, 0)
            finally:
                engine.close()


class KeyProtectionCliTests(unittest.TestCase):
    def test_ingest_without_the_key_exits_two_and_preserves_evidence(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            registry_path = root / "registry.json"
            registry_path.write_text(json.dumps(registry()), encoding="utf-8")
            database = root / "db.sqlite"
            engine = Engine(Registry(registry()), database, mac_key=KEY)
            try:
                engine.process(s3(), NOW)
            finally:
                engine.close()
            events = root / "events.jsonl"
            event = s3("synthetic-cli-unsigned")
            event["eventTime"] = "2026-10-02T11:59:00Z"
            events.write_text(json.dumps(event) + "\n", encoding="utf-8")
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = main(
                    [
                        "--registry",
                        str(registry_path),
                        "--database",
                        str(database),
                        "ingest",
                        str(events),
                    ]
                )
            self.assertEqual(code, 2)
            self.assertIn("supply the evidence key", out.getvalue())
            check = Engine(Registry(registry()), database, mac_key=KEY)
            try:
                self.assertEqual(check.report()["decisions"]["alert"], 1)
                self.assertTrue(check.verify_integrity()["ok"])
            finally:
                check.close()


if __name__ == "__main__":
    unittest.main()
