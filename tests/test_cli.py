import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from fools_gold.cli import main
from tests.test_pilot import registry, s3


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

    def test_deliver_wazuh_writes_records_once(self):
        import json as jsonlib


        self.events.write_text(
            jsonlib.dumps(self.event()) + "\n", encoding="utf-8"
        )
        self.invoke("ingest", str(self.events))
        sink = self.folder / "wazuh.log"
        code, output, _ = self.invoke(
            "deliver", "--format", "wazuh", "--wazuh-output", str(sink)
        )
        self.assertEqual(code, 0)
        self.assertEqual(len(sink.read_text(encoding="utf-8").splitlines()), 1)
        code, _, _ = self.invoke(
            "deliver", "--format", "wazuh", "--wazuh-output", str(sink)
        )
        self.assertEqual(code, 0)
        self.assertEqual(len(sink.read_text(encoding="utf-8").splitlines()), 1)

    def test_deliver_splunk_requires_host_and_port(self):
        code, _, error = self.invoke("deliver", "--format", "splunk")
        self.assertEqual(code, 2)
        self.assertIn("--splunk-host", error)

    def test_deliver_splunk_without_token_fails_closed(self):
        import os
        from unittest.mock import patch

        self.events.write_text(
            json.dumps(self.event()) + "\n", encoding="utf-8"
        )
        self.invoke("ingest", str(self.events))
        with patch.dict(os.environ, {}, clear=True):
            code, _, error = self.invoke(
                "deliver",
                "--format",
                "splunk",
                "--splunk-host",
                "hec.internal.example",
                "--splunk-port",
                "8088",
            )
        self.assertEqual(code, 2)
        self.assertIn("FG_SPLUNK_HEC_TOKEN", error)

    def test_trail_inbox_processes_and_skips_processed_files(self):
        import gzip as gziplib
        import json as jsonlib

        from fools_gold.core import Engine, Registry

        self.events.write_text(
            jsonlib.dumps(self.event()) + "\n", encoding="utf-8"
        )
        self.invoke("ingest", str(self.events))
        inbox = self.folder / "inbox"
        inbox.mkdir()
        (inbox / "trail.json.gz").write_bytes(
            gziplib.compress(jsonlib.dumps({"Records": [self.event()]}).encode())
        )
        engine = Engine(
            Registry(jsonlib.loads(self.registry.read_text(encoding="utf-8"))),
            self.database,
        )
        from fools_gold.cli import run_trail_inbox

        try:
            self.assertEqual(run_trail_inbox(engine, str(inbox)), 0)
            before = engine.report()["decisions"]["alert"]
            self.assertEqual(before, 1)
            second = run_trail_inbox(engine, str(inbox))
            self.assertEqual(second, 0)
            self.assertEqual(engine.report()["decisions"]["alert"], before)
        finally:
            engine.close()

    def test_trail_inbox_rejects_malformed_file_and_reports(self):
        import json as jsonlib

        from fools_gold.core import Engine, Registry

        inbox = self.folder / "inbox"
        inbox.mkdir()
        (inbox / "broken.json").write_text("{not json", encoding="utf-8")
        engine = Engine(
            Registry(jsonlib.loads(self.registry.read_text(encoding="utf-8"))),
            self.database,
        )
        from fools_gold.cli import run_trail_inbox

        try:
            self.assertEqual(run_trail_inbox(engine, str(inbox)), 2)
        finally:
            engine.close()
