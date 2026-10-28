"""Recovery safety: destination sidecars, active writers, schema validation."""

import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fools_gold.core import ContractError, Engine, Registry, restore_database
from tests.test_pilot import NOW, registry, s3

CRASH_SCRIPT = """
import os, sqlite3, sys
conn = sqlite3.connect(sys.argv[1])
conn.execute("PRAGMA journal_mode=WAL")
conn.execute(
    "INSERT OR REPLACE INTO decisions(event_key,fingerprint,result,created_at) "
    "VALUES('STALE-DESTINATION','x','alert','2026-01-01T00:00:00Z')"
)
conn.execute(
    "INSERT OR REPLACE INTO alerts(id,decoy,actor,opened_at,received_at,evidence,evidence_mac,prev_mac,route) "
    "VALUES('fg-stale','stale-decoy','stale-actor','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z','{}',NULL,NULL,NULL)"
)
conn.commit()
os._exit(0)
"""


def make_source(folder: Path) -> Path:
    database = folder / "source.sqlite"
    engine = Engine(Registry(registry()), database)
    try:
        engine.process(s3(), NOW)
    finally:
        engine.close()
    backup = folder / "backup.sqlite"
    engine = Engine(Registry(registry()), database)
    try:
        engine.backup(backup)
    finally:
        engine.close()
    return backup


def crash_destination(destination: Path):
    completed = subprocess.run(
        [sys.executable, "-c", CRASH_SCRIPT, str(destination)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    if completed.returncode != 0:
        raise AssertionError(completed.stderr)


class RestoreSidecarTests(unittest.TestCase):
    def test_restore_supersedes_a_crashed_destination_wal(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            backup = make_source(root)
            destination = root / "live.sqlite"
            shutil.copy(backup, destination)
            crash_destination(destination)
            self.assertTrue(
                Path(str(destination) + "-wal").exists(),
                "subprocess crash should leave a destination WAL",
            )
            restore_database(backup, destination)
            check = sqlite3.connect(str(destination))
            try:
                stale = check.execute(
                    "SELECT COUNT(*) FROM decisions WHERE event_key='STALE-DESTINATION'"
                ).fetchone()[0]
            finally:
                check.close()
            self.assertEqual(stale, 0)
            self.assertFalse(Path(str(destination) + ".restore-tmp").exists())

    def test_restore_refuses_an_active_destination(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            backup = make_source(root)
            destination = root / "live.sqlite"
            shutil.copy(backup, destination)
            active = Engine(Registry(registry()), destination)
            try:
                with self.assertRaises(ContractError):
                    restore_database(backup, destination)
            finally:
                active.close()
            check = sqlite3.connect(str(destination))
            try:
                self.assertEqual(
                    check.execute("SELECT COUNT(*) FROM alerts").fetchone()[0], 1
                )
            finally:
                check.close()

    def test_restore_rejects_incomplete_application_schema(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = root / "schema.sqlite"
            connection = sqlite3.connect(str(source))
            connection.executescript(
                """
                CREATE TABLE alerts (x TEXT);
                CREATE TABLE decisions (y TEXT);
                """
            )
            connection.commit()
            connection.close()
            destination = root / "live.sqlite"
            destination.write_bytes(b"preserve-me")
            with self.assertRaises(ContractError):
                restore_database(source, destination)
            self.assertEqual(destination.read_bytes(), b"preserve-me")

    def test_restore_rejects_corrupted_source(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = root / "broken.sqlite"
            source.write_bytes(os.urandom(4096))
            destination = root / "live.sqlite"
            destination.write_bytes(b"preserve-me")
            with self.assertRaises(ContractError):
                restore_database(source, destination)
            self.assertEqual(destination.read_bytes(), b"preserve-me")

    def test_interrupted_replace_preserves_destination_and_cleans_temp(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            backup = make_source(root)
            destination = root / "live.sqlite"
            shutil.copy(backup, destination)
            original = destination.read_bytes()
            with patch(
                "fools_gold.core.os.replace",
                side_effect=OSError("simulated interruption"),
            ):
                with self.assertRaises(ContractError):
                    restore_database(backup, destination)
            self.assertEqual(destination.read_bytes(), original)
            self.assertFalse(Path(str(destination) + ".restore-tmp").exists())

    def test_successful_recovery_preserves_backup_evidence(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            backup = make_source(root)
            destination = root / "live.sqlite"
            restore_database(backup, destination)
            engine = Engine(Registry(registry()), destination)
            try:
                self.assertEqual(engine.report()["decisions"]["alert"], 1)
                self.assertTrue(Path(str(destination) + ".lock").exists())
            finally:
                engine.close()

    def test_two_writers_on_one_database_are_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "db.sqlite"
            first = Engine(Registry(registry()), path)
            try:
                with self.assertRaises(ContractError):
                    Engine(Registry(registry()), path)
            finally:
                first.close()
            second = Engine(Registry(registry()), path)
            second.close()


if __name__ == "__main__":
    unittest.main()
