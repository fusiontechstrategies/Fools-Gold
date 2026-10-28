"""Assurance stages, unique run identities and operator acceptance."""

import contextlib
import io
import json
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

from fools_gold.assurance import assurance_report, run_assurance
from fools_gold.cli import main
from fools_gold.core import ContractError, Engine, Registry
from tests.test_pilot import NOW, registry


def engine_in(folder):
    return Engine(Registry(registry()), Path(folder) / "db.sqlite")


class StageTests(unittest.TestCase):
    def test_canary_run_reports_stage_statuses(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = engine_in(folder)
            try:
                result = run_assurance(engine, now=NOW)
                self.assertTrue(result["ok"])
                self.assertRegex(result["run_id"], r"^[0-9a-f]{32}$")
                stages = result["stages"]
                self.assertEqual(stages["synthetic"]["status"], "pass")
                self.assertEqual(stages["live"]["status"], "not_run")
                self.assertEqual(stages["transport"]["status"], "not_run")
                self.assertEqual(stages["ingestion"]["status"], "unverified")
                self.assertEqual(
                    stages["analyst_acknowledgment"]["status"], "unverified"
                )
                report = assurance_report(engine, now=NOW)
                self.assertEqual(report["latest_run_id"], result["run_id"])
                self.assertEqual(report["stages"]["live"]["status"], "not_run")
            finally:
                engine.close()

    def test_live_failure_is_a_separate_stage(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = engine_in(folder)
            try:
                step = {"now": NOW - timedelta(seconds=1)}

                def clock():
                    step["now"] += timedelta(seconds=1)
                    return step["now"]

                result = run_assurance(
                    engine,
                    now=NOW,
                    probe=lambda: {"decoy_ids": ["synthetic-linux-config"]},
                    wait_seconds=1,
                    sleep=lambda _seconds: None,
                    clock=clock,
                )
                self.assertFalse(result["ok"])
                self.assertEqual(result["stages"]["live"]["status"], "fail")
                self.assertEqual(result["stages"]["synthetic"]["status"], "pass")
                report = assurance_report(engine, now=NOW)
                self.assertFalse(report["stages"]["live"]["status"] == "pass")
            finally:
                engine.close()

    def test_transport_setup_failure_is_recorded_not_raised(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = engine_in(folder)
            try:
                with patch.dict("os.environ", {}, clear=True):
                    result = run_assurance(
                        engine,
                        now=NOW,
                        transport_config={
                            "format": "splunk",
                            "splunk_host": "hec.example",
                            "splunk_port": 8088,
                        },
                    )
                self.assertFalse(result["ok"])
                self.assertIn("FG_SPLUNK_HEC_TOKEN", result["notice"])
                self.assertEqual(result["stages"]["transport"]["status"], "fail")
                history = engine.assurance_history(5)
                self.assertEqual(len(history), 1)
                self.assertFalse(history[0]["ok"])
            finally:
                engine.close()

    def test_run_ids_are_unique_and_persisted(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = engine_in(folder)
            try:
                first = run_assurance(engine, now=NOW)
                second = run_assurance(engine, now=NOW + timedelta(hours=1))
                self.assertNotEqual(first["run_id"], second["run_id"])
                ids = {run["run_id"] for run in engine.assurance_history(10)}
                self.assertEqual(len(ids), 2)
            finally:
                engine.close()

    def test_latency_and_mode_summary(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = engine_in(folder)
            try:
                run_assurance(engine, now=NOW)
                report = assurance_report(
                    engine, max_age_hours=24, require_mode="canary", now=NOW
                )
                self.assertFalse(report["stale"])
                self.assertIsNotNone(report["last_ok_by_mode"]["canary"])
                self.assertIsNone(report["last_ok_by_mode"]["live"])
                live = assurance_report(
                    engine, max_age_hours=24, require_mode="live", now=NOW
                )
                self.assertTrue(live["stale"])
                self.assertIsNone(live["last_ok_run_id"])
            finally:
                engine.close()


class AcceptanceTests(unittest.TestCase):
    def test_acceptance_marks_external_stages_operator_verified(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = engine_in(folder)
            try:
                run_assurance(engine, now=NOW)
                before = assurance_report(engine, now=NOW)
                self.assertEqual(
                    before["stages"]["ingestion"]["status"], "unverified"
                )
                engine.record_acceptance(
                    NOW, "ingestion", "alert visible in Splunk index", "analyst-a"
                )
                after = assurance_report(engine, now=NOW)
                self.assertEqual(
                    after["stages"]["ingestion"]["status"], "operator_verified"
                )
                self.assertEqual(after["stages"]["ingestion"]["actor"], "analyst-a")
                self.assertEqual(
                    after["stages"]["analyst_acknowledgment"]["status"],
                    "unverified",
                )
            finally:
                engine.close()

    def test_stage_and_field_validation(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = engine_in(folder)
            try:
                for kwargs in (
                    {"stage": "synthetic", "note": "x", "actor": "a"},
                    {"stage": "ingestion", "note": "", "actor": "a"},
                    {"stage": "ingestion", "note": "x", "actor": ""},
                ):
                    with self.subTest(kwargs=kwargs), self.assertRaises(ContractError):
                        engine.record_acceptance(NOW, **kwargs)
            finally:
                engine.close()


class AcceptanceCliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.folder = Path(self.temp.name)
        self.registry = self.folder / "registry.json"
        self.registry.write_text(json.dumps(registry()), encoding="utf-8")
        self.database = self.folder / "db.sqlite"

    def tearDown(self):
        self.temp.cleanup()

    def invoke(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(
                [
                    "--registry",
                    str(self.registry),
                    "--database",
                    str(self.database),
                    *args,
                ]
            )
        return code, out.getvalue(), err.getvalue()

    def test_accept_and_require_mode_gate(self):
        code, output, _ = self.invoke("assure")
        self.assertEqual(code, 0)
        code, output, _ = self.invoke(
            "accept",
            "--stage",
            "ingestion",
            "--note",
            "confirmed in index",
            "--actor",
            "analyst-b",
        )
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output)["stage"], "ingestion")
        code, output, _ = self.invoke(
            "assure-report", "--max-age-hours", "24", "--require-mode", "canary"
        )
        self.assertEqual(code, 0)
        payload = json.loads(output)
        self.assertEqual(payload["stages"]["ingestion"]["status"], "operator_verified")
        code, output, _ = self.invoke(
            "assure-report", "--max-age-hours", "24", "--require-mode", "live"
        )
        self.assertEqual(code, 2)
        self.assertTrue(json.loads(output)["stale"])


if __name__ == "__main__":
    unittest.main()
