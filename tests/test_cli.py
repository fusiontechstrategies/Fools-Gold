import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from test_pilot import registry, s3

from fools_gold.cli import main


class CliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.folder = Path(self.temp.name)
        self.registry = self.folder / "registry.json"
        self.registry.write_text(json.dumps(registry()), encoding="utf-8")
        self.events = self.folder / "events.jsonl"
        self.database = self.folder / "pilot.sqlite"
        self.base = ["--registry", str(self.registry), "--database", str(self.database)]

    def tearDown(self):
        self.temp.cleanup()

    def invoke(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            result = main(self.base + list(args))
        return result, out.getvalue(), err.getvalue()

    def event(self):
        event = s3()
        event["eventTime"] = "2000-01-01T00:00:00Z"
        return event

    def test_ingest_restart_and_report(self):
        self.events.write_text(json.dumps(self.event()) + "\n", encoding="utf-8")
        code, output, _ = self.invoke("ingest", str(self.events))
        self.assertEqual(code, 0)
        alert_id = json.loads(output)["alert"]["alert_id"]
        code, output, _ = self.invoke("ingest", str(self.events))
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output)["decision"], "duplicate")
        self.assertEqual(
            self.invoke("acknowledge", alert_id, "--analyst", "synthetic-analyst")[0], 0
        )
        code, output, _ = self.invoke("report")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output)["alerts_acknowledged"], 1)

    def test_invalid_line_returns_failure_but_preserves_prior_decision(self):
        self.events.write_text(
            json.dumps(self.event()) + '\n{"eventSource":"fake"}\n', encoding="utf-8"
        )
        code, output, _ = self.invoke("ingest", str(self.events))
        self.assertEqual(code, 2)
        self.assertEqual(
            [json.loads(line)["decision"] for line in output.splitlines()],
            ["alert", "rejected"],
        )
        self.assertEqual(json.loads(self.invoke("report")[1])["decisions"]["alert"], 1)

    def test_oversized_event_stops_with_failure(self):
        self.events.write_bytes(b"x" * 65537)
        code, _, error = self.invoke("ingest", str(self.events))
        self.assertEqual(code, 2)
        self.assertIn("exceeds 64 KiB", error)

    def test_oversized_registry_rejected(self):
        self.registry.write_bytes(b"x" * (1024 * 1024 + 1))
        code, _, error = self.invoke("report")
        self.assertEqual(code, 2)
        self.assertIn("exceeds 1 MiB", error)

    def test_unknown_acknowledgment_rejected(self):
        code, _, error = self.invoke(
            "acknowledge", "fg-does-not-exist", "--analyst", "synthetic-analyst"
        )
        self.assertEqual(code, 2)
        self.assertIn("unknown alert", error)

    def test_corrupt_database_returns_failure(self):
        self.database.write_bytes(b"not a sqlite database")
        code, _, error = self.invoke("report")
        self.assertEqual(code, 2)
        self.assertIn("database", error)
