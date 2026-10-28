import secrets
import tempfile
import unittest
from pathlib import Path

from fools_gold.cli import load_evidence_key, main
from fools_gold.core import ContractError, Engine, Registry
from tests.test_pilot import NOW, registry, s3

KEY_HEX = secrets.token_hex(32)


class IntegrityTests(unittest.TestCase):
    def setUp(self):
        self.engine = Engine(
            Registry(registry()), ":memory:", mac_key=bytes.fromhex(KEY_HEX)
        )
        self.engine.process(s3(), NOW)
        self.engine.process(s3("synthetic-s3-002"), NOW)

    def tearDown(self):
        self.engine.close()

    def test_every_alert_carries_a_linked_mac(self):
        rows = self.engine.db.execute(
            "SELECT id,evidence,prev_mac,evidence_mac FROM alerts ORDER BY rowid"
        ).fetchall()
        self.assertEqual(len(rows), 2)
        self.assertIsNone(rows[0][2])
        self.assertIsNotNone(rows[0][3])
        self.assertEqual(rows[1][2], rows[0][3])
        self.assertTrue(self.engine.verify_integrity()["ok"])

    def test_mac_length_and_format_are_checked(self):
        with self.assertRaises(ContractError):
            Engine(Registry(registry()), ":memory:", mac_key=b"short")
        with self.assertRaises(ContractError):
            Engine(Registry(registry()), ":memory:", mac_key="not-bytes")

    def test_tampered_evidence_is_detected(self):
        self.engine.db.execute(
            "UPDATE alerts SET evidence=replace(evidence,'synthetic-soc','tampered') "
            "WHERE rowid=1"
        )
        outcome = self.engine.verify_integrity()
        self.assertFalse(outcome["ok"])
        self.assertTrue(outcome["failures"])

    def test_cleared_mac_breaks_the_chain_visibly(self):
        self.engine.db.execute(
            "UPDATE alerts SET evidence_mac=NULL WHERE rowid=2"
        )
        outcome = self.engine.verify_integrity()
        self.assertFalse(outcome["ok"])
        reasons = {failure["reason"] for failure in outcome["failures"]}
        self.assertIn("mac mismatch", reasons)

    def test_verification_requires_a_key(self):
        engine = Engine(Registry(registry()), ":memory:")
        try:
            with self.assertRaises(ContractError):
                engine.verify_integrity()
        finally:
            engine.close()

    def test_legacy_database_schema_is_migrated(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "legacy.sqlite"
            import sqlite3

            connection = sqlite3.connect(str(path))
            connection.executescript(
                """
                CREATE TABLE decisions (event_key TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, result TEXT NOT NULL);
                CREATE TABLE alerts (
                    id TEXT PRIMARY KEY, decoy TEXT NOT NULL, actor TEXT NOT NULL,
                    opened_at TEXT NOT NULL, received_at TEXT NOT NULL, evidence TEXT NOT NULL,
                    acknowledged_at TEXT, acknowledged_by TEXT
                );
                """
            )
            connection.commit()
            connection.close()
            engine = Engine(
                Registry(registry()), path, mac_key=bytes.fromhex(KEY_HEX)
            )
            try:
                engine.process(s3(), NOW)
                self.assertTrue(engine.verify_integrity()["ok"])
            finally:
                engine.close()


class EvidenceKeyLoadingTests(unittest.TestCase):
    def test_accepts_hex_with_trailing_newline(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "key.hex"
            path.write_text(KEY_HEX + "\n", encoding="ascii")
            self.assertEqual(load_evidence_key(str(path)), bytes.fromhex(KEY_HEX))

    def test_rejects_bad_keys(self):
        with tempfile.TemporaryDirectory() as folder:
            folder_path = Path(folder)
            for content in ("nothex", KEY_HEX[:-1], "x" * 65, b"\xff" * 10):
                path = folder_path / "key.hex"
                if isinstance(content, bytes):
                    path.write_bytes(content)
                else:
                    path.write_text(content, encoding="ascii")
                with self.assertRaises(ContractError):
                    load_evidence_key(str(path))
            path = folder_path / "big.hex"
            path.write_bytes(b"a" * 1025)
            with self.assertRaises(ContractError):
                load_evidence_key(str(path))


class VerifyIntegrityCliTests(unittest.TestCase):
    def setUp(self):
        import contextlib
        import io
        import json as jsonlib

        self.contextlib = contextlib
        self.io = io
        self.json = jsonlib
        self.temp = tempfile.TemporaryDirectory()
        self.folder = Path(self.temp.name)
        self.registry = self.folder / "registry.json"
        self.registry.write_text(jsonlib.dumps(registry()), encoding="utf-8")
        self.database = self.folder / "evidence.sqlite"
        self.key_file = self.folder / "key.hex"
        self.key_file.write_text(KEY_HEX, encoding="ascii")
        self.events = self.folder / "events.jsonl"
        import json as jsonlib2

        event = s3()
        event["eventTime"] = "2000-01-01T00:00:00Z"
        self.events.write_text(jsonlib2.dumps(event) + "\n", encoding="utf-8")

    def tearDown(self):
        self.temp.cleanup()

    def invoke(self, *args):
        out, err = self.io.StringIO(), self.io.StringIO()
        with self.contextlib.redirect_stdout(out), self.contextlib.redirect_stderr(err):
            result = main(
                [
                    "--registry",
                    str(self.registry),
                    "--database",
                    str(self.database),
                    "--evidence-key-file",
                    str(self.key_file),
                    *args,
                ]
            )
        return result, out.getvalue(), err.getvalue()

    def test_ingest_and_verify_round_trip(self):
        code, _, _ = self.invoke("ingest", str(self.events))
        self.assertEqual(code, 0)
        code, output, _ = self.invoke("verify-integrity")
        self.assertEqual(code, 0)
        self.assertTrue(self.json.loads(output)["ok"])

    def test_tampered_database_fails_verification(self):
        self.invoke("ingest", str(self.events))
        import sqlite3

        connection = sqlite3.connect(str(self.database))
        connection.execute(
            "UPDATE alerts SET evidence=replace(evidence,'fools-gold','forged')"
        )
        connection.commit()
        connection.close()
        code, output, _ = self.invoke("verify-integrity")
        self.assertEqual(code, 2)
        self.assertFalse(self.json.loads(output)["ok"])

    def test_verify_without_key_file_fails(self):
        self.invoke("ingest", str(self.events))
        out, err = self.io.StringIO(), self.io.StringIO()
        with self.contextlib.redirect_stdout(out), self.contextlib.redirect_stderr(err):
            code = main(
                [
                    "--registry",
                    str(self.registry),
                    "--database",
                    str(self.database),
                    "verify-integrity",
                ]
            )
        self.assertEqual(code, 2)
        self.assertIn("requires --evidence-key-file", err.getvalue())


if __name__ == "__main__":
    unittest.main()
