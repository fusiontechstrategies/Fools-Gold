"""Assurance runs, SLO reporting and maintenance command tests."""

import contextlib
import io
import json
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

from fools_gold.assurance import assurance_report, run_assurance
from fools_gold.cli import main
from fools_gold.core import ContractError, Engine, Registry
from tests.test_pilot import NOW, registry, s3


def engine_at(folder):
    return Engine(Registry(registry()), Path(folder) / "db.sqlite")


class RunAssuranceTests(unittest.TestCase):
    def test_canary_run_is_recorded(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = engine_at(folder)
            try:
                result = run_assurance(engine, now=NOW)
                self.assertTrue(result["ok"])
                self.assertEqual(result["mode"], "canary")
                history = engine.assurance_history(5)
                self.assertEqual(len(history), 1)
                self.assertEqual(history[0]["mode"], "canary")
                self.assertTrue(history[0]["ok"])
                self.assertEqual(history[0]["details"]["scenarios"][0]["passed"], True)
            finally:
                engine.close()

    def test_live_probe_pass_requires_matching_alert(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = engine_at(folder)
            try:
                engine.process(s3(), NOW)

                def probe():
                    return {"decoy_ids": ["synthetic-s3-backup"], "probed": 1}

                result = run_assurance(
                    engine,
                    now=NOW,
                    probe=probe,
                    wait_seconds=1,
                    sleep=lambda _seconds: None,
                    clock=lambda: NOW,
                )
                self.assertTrue(result["ok"])
                self.assertEqual(result["mode"], "live")
                self.assertTrue(result["live"]["passed"])
            finally:
                engine.close()

    def test_live_probe_fails_without_alert(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = engine_at(folder)
            try:
                ticks = iter([NOW, NOW, NOW + timedelta(seconds=5)])

                def clock():
                    return next(ticks, NOW + timedelta(seconds=10))

                result = run_assurance(
                    engine,
                    now=NOW,
                    probe=lambda: {"decoy_ids": ["synthetic-linux-config"]},
                    wait_seconds=1,
                    sleep=lambda _seconds: None,
                    clock=clock,
                )
                self.assertFalse(result["ok"])
                self.assertFalse(result["live"]["passed"])
                self.assertEqual(result["failed_scenarios"], 1)
            finally:
                engine.close()

    def test_live_probe_with_no_matching_decoy_fails_closed(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = engine_at(folder)
            try:
                result = run_assurance(
                    engine,
                    now=NOW,
                    probe=lambda: {"decoy_ids": []},
                    sleep=lambda _seconds: None,
                    clock=lambda: NOW,
                )
                self.assertFalse(result["ok"])
                self.assertIn("no registered decoy", result["live"]["reason"])
            finally:
                engine.close()

    def test_invalid_wait_seconds_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = engine_at(folder)
            try:
                for value in (0, 301, "10"):
                    with self.assertRaises(ContractError):
                        run_assurance(engine, now=NOW, wait_seconds=value)
            finally:
                engine.close()


class AssuranceReportTests(unittest.TestCase):
    def test_metrics_and_percentiles(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = engine_at(folder)
            try:
                for index, event_id in enumerate(("a", "b", "c")):
                    event = s3(f"synthetic-metric-{event_id}")
                    engine.process(event, NOW)
                engine.acknowledge(
                    engine.export_alerts().__next__()["alert_id"],
                    "analyst",
                    NOW + timedelta(seconds=10),
                )
                engine.record_assurance(NOW, "canary", True, 0, {})
                outcome = assurance_report(engine, max_age_hours=24, now=NOW)
                self.assertEqual(outcome["runs"], 1)
                self.assertEqual(outcome["passed"], 1)
                self.assertEqual(outcome["mttd_seconds"]["samples"], 3)
                self.assertEqual(outcome["mttd_seconds"]["p50"], 5.0)
                self.assertEqual(outcome["mtta_seconds"]["samples"], 1)
                self.assertFalse(outcome["stale"])
                self.assertEqual(outcome["last_ok_age_hours"], 0.0)
            finally:
                engine.close()

    def test_staleness_gate(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = engine_at(folder)
            try:
                engine.record_assurance(NOW, "canary", True, 0, {})
                fresh = assurance_report(
                    engine, max_age_hours=24, now=NOW + timedelta(hours=1)
                )
                self.assertFalse(fresh["stale"])
                stale = assurance_report(
                    engine, max_age_hours=24, now=NOW + timedelta(hours=48)
                )
                self.assertTrue(stale["stale"])
                other = Path(folder) / "other"
                other.mkdir()
                empty = engine_at(str(other))
                try:
                    self.assertTrue(
                        assurance_report(empty, max_age_hours=24, now=NOW)["stale"]
                    )
                finally:
                    empty.close()
            finally:
                engine.close()

    def test_report_without_max_age_has_no_stale_verdict(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = engine_at(folder)
            try:
                self.assertIsNone(assurance_report(engine)["stale"])
            finally:
                engine.close()


class AssuranceCliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.folder = Path(self.temp.name)
        self.registry = self.folder / "registry.json"
        self.registry.write_text(json.dumps(registry()), encoding="utf-8")
        self.database = self.folder / "db.sqlite"
        self.base = ["--registry", str(self.registry), "--database", str(self.database)]

    def tearDown(self):
        self.temp.cleanup()

    def invoke(self, *args):
        return self.invoke_argv(self.base + list(args))

    def invoke_argv(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def test_assure_then_report(self):
        code, output, _ = self.invoke("assure")
        self.assertEqual(code, 0)
        self.assertTrue(json.loads(output)["ok"])
        code, output, _ = self.invoke("assure-report", "--max-age-hours", "24")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output)["runs"], 1)

    def test_report_on_empty_database_is_stale(self):
        code, output, _ = self.invoke("assure-report", "--max-age-hours", "24")
        self.assertEqual(code, 2)
        self.assertTrue(json.loads(output)["stale"])

    def test_assure_rejects_two_transport_targets(self):
        with tempfile.TemporaryDirectory() as sink_folder:
            code, _, error = self.invoke(
                "assure",
                "--splunk-host",
                "hec.example",
                "--splunk-port",
                "8088",
                "--wazuh-output",
                str(Path(sink_folder) / "w.log"),
            )
        self.assertEqual(code, 2)
        self.assertIn("at most one transport target", error)

    def test_prune_backup_restore_cycle(self):
        event = s3()
        event["eventTime"] = "2000-01-01T00:00:00Z"
        events = self.folder / "events.jsonl"
        events.write_text(json.dumps(event) + "\n", encoding="utf-8")
        self.invoke("ingest", str(events))
        backup_path = self.folder / "backup.sqlite"
        code, output, _ = self.invoke("backup", "--out", str(backup_path))
        self.assertEqual(code, 0)
        self.assertTrue(json.loads(output)["backup"].endswith("backup.sqlite"))
        restored = self.folder / "restored.sqlite"
        code, output, _ = self.invoke_argv(
            ["--database", str(restored), "restore", "--source", str(backup_path)]
        )
        self.assertEqual(code, 0)
        self.assertTrue(json.loads(output)["restored"])
        code, output, _ = self.invoke_argv(
            ["--registry", str(self.registry), "--database", str(restored), "report"]
        )
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output)["decisions"]["alert"], 1)
        import sqlite3

        connection = sqlite3.connect(str(self.database))
        connection.execute(
            "UPDATE alerts SET received_at='2000-01-01T00:00:00Z'"
        )
        connection.execute(
            "UPDATE decisions SET created_at='2000-01-01T00:00:00Z'"
        )
        connection.commit()
        connection.close()
        code, output, _ = self.invoke("prune", "--older-than-days", "1")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output)["pruned"]["alerts"], 1)


if __name__ == "__main__":
    unittest.main()
