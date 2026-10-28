"""Live assurance wiring: callable probes, correlation, coverage and durability."""

import contextlib
import io
import json
import os
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

from fools_gold.assurance import run_assurance
from fools_gold.cli import main
from fools_gold.core import Engine, Registry, stamp
from fools_gold.onboarding import write_registry
from tests.test_contracts_v2 import linux
from tests.test_pilot import NOW, registry, s3


def engine_in(folder):
    return Engine(Registry(registry()), Path(folder) / "db.sqlite")


def stepped_clock(start, step=timedelta(seconds=1)):
    """Advances on every call so bounded loops always terminate."""
    state = {"now": start - step}

    def clock():
        state["now"] += step
        return state["now"]

    return clock


class ProbeCorrelationTests(unittest.TestCase):
    def test_preexisting_alert_does_not_satisfy_the_probe(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = engine_in(folder)
            try:
                engine.process(linux(), NOW)
                result = run_assurance(
                    engine,
                    now=NOW,
                    probe=lambda: {"decoy_ids": ["synthetic-linux-config"]},
                    wait_seconds=1,
                    sleep=lambda _seconds: None,
                    clock=stepped_clock(NOW),
                )
                self.assertFalse(result["ok"])
                self.assertEqual(
                    result["live"]["missed"], ["synthetic-linux-config"]
                )
            finally:
                engine.close()

    def test_actor_mismatch_does_not_satisfy_the_probe(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = engine_in(folder)
            try:

                def probe():
                    engine.process(linux("777"), NOW + timedelta(seconds=1))
                    return {
                        "decoy_ids": ["synthetic-linux-config"],
                        "actors": ["uid:9999"],
                    }

                result = run_assurance(
                    engine,
                    now=NOW,
                    probe=probe,
                    wait_seconds=1,
                    sleep=lambda _seconds: None,
                    clock=stepped_clock(NOW),
                )
                self.assertFalse(result["ok"])
                self.assertEqual(
                    result["live"]["missed"], ["synthetic-linux-config"]
                )
            finally:
                engine.close()

    def test_matching_new_alert_satisfies_the_probe(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = engine_in(folder)
            try:

                def probe():
                    engine.process(linux("888"), NOW + timedelta(seconds=1))
                    return {
                        "decoy_ids": ["synthetic-linux-config"],
                        "actors": ["uid:1001"],
                    }

                result = run_assurance(
                    engine,
                    now=NOW,
                    probe=probe,
                    wait_seconds=1,
                    sleep=lambda _seconds: None,
                    clock=stepped_clock(NOW),
                )
                self.assertTrue(result["ok"])
                self.assertEqual(
                    result["live"]["detected"], ["synthetic-linux-config"]
                )
            finally:
                engine.close()

    def test_delayed_old_event_does_not_satisfy_the_probe(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = engine_in(folder)
            try:
                stale = linux("901")
                stale["time"] = stamp(NOW - timedelta(days=1))

                def probe():
                    engine.process(stale, NOW + timedelta(seconds=1))
                    return {
                        "decoy_ids": ["synthetic-linux-config"],
                        "actors": ["uid:1001"],
                    }

                result = run_assurance(
                    engine,
                    now=NOW,
                    probe=probe,
                    wait_seconds=1,
                    sleep=lambda _seconds: None,
                    clock=stepped_clock(NOW),
                )
                self.assertFalse(result["ok"])
                self.assertEqual(
                    result["live"]["missed"], ["synthetic-linux-config"]
                )
                self.assertEqual(result["live"]["evidence"], {})
            finally:
                engine.close()

    def test_action_mismatch_does_not_satisfy_the_probe(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = engine_in(folder)
            try:
                write_event = linux("902", action="write", time=stamp(NOW))

                def probe():
                    engine.process(write_event, NOW + timedelta(seconds=1))
                    return {
                        "decoy_ids": ["synthetic-linux-config"],
                        "actors": ["uid:1001"],
                        "actions": ["read"],
                    }

                result = run_assurance(
                    engine,
                    now=NOW,
                    probe=probe,
                    wait_seconds=1,
                    sleep=lambda _seconds: None,
                    clock=stepped_clock(NOW),
                )
                self.assertFalse(result["ok"])
                self.assertEqual(
                    result["live"]["missed"], ["synthetic-linux-config"]
                )
            finally:
                engine.close()

    def test_matching_alert_records_per_decoy_evidence(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = engine_in(folder)
            try:
                current = linux("903", time=stamp(NOW))

                def probe():
                    engine.process(current, NOW + timedelta(seconds=1))
                    return {
                        "decoy_ids": ["synthetic-linux-config"],
                        "actors": ["uid:1001"],
                    }

                result = run_assurance(
                    engine,
                    now=NOW,
                    probe=probe,
                    wait_seconds=1,
                    sleep=lambda _seconds: None,
                    clock=stepped_clock(NOW),
                )
                self.assertTrue(result["ok"])
                alert_id = result["live"]["evidence"]["synthetic-linux-config"]
                self.assertTrue(alert_id.startswith("fg-"))
            finally:
                engine.close()

    def test_every_probed_decoy_must_be_detected(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = engine_in(folder)
            try:

                def probe():
                    engine.process(linux("889"), NOW + timedelta(seconds=1))
                    return {"decoy_ids": ["synthetic-linux-config", "synthetic-windows-config"]}

                result = run_assurance(
                    engine,
                    now=NOW,
                    probe=probe,
                    wait_seconds=1,
                    sleep=lambda _seconds: None,
                    clock=stepped_clock(NOW),
                )
                self.assertFalse(result["ok"])
                self.assertEqual(
                    result["live"]["detected"], ["synthetic-linux-config"]
                )
                self.assertEqual(
                    result["live"]["missed"], ["synthetic-windows-config"]
                )
            finally:
                engine.close()

    def test_probe_exception_is_structured_and_recorded(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = engine_in(folder)
            try:

                def probe():
                    raise RuntimeError("sensor unavailable")

                result = run_assurance(
                    engine,
                    now=NOW,
                    probe=probe,
                    sleep=lambda _seconds: None,
                    clock=stepped_clock(NOW),
                )
                self.assertFalse(result["ok"])
                self.assertIn("probe failed", result["live"]["reason"])
                history = engine.assurance_history(1)
                self.assertEqual(len(history), 1)
                self.assertEqual(history[0]["mode"], "live")
                self.assertFalse(history[0]["ok"])
            finally:
                engine.close()


class LiveCliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.folder = Path(self.temp.name)
        self.host = "synthetic-live-host"
        self.decoy = self.folder / "decoy.txt"
        self.decoy.write_text("SYNTHETIC DECOY\n", encoding="utf-8")
        spec = {"host": self.host, "path": str(self.decoy)}
        if os.name == "nt":
            self.decoy_id = "decoy-windows-1"
            selector = {"windows": spec}
        else:
            self.decoy_id = "decoy-linux-1"
            selector = {"linux": spec}
        self.registry_path = Path(
            write_registry(self.folder, owner="synthetic-soc", now=NOW, **selector)
        )
        self.database = self.folder / "evidence.sqlite"

    def tearDown(self):
        self.temp.cleanup()

    def invoke(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with patch(
            "fools_gold.assurance.platform.node", return_value=self.host
        ), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(
                [
                    "--registry",
                    str(self.registry_path),
                    "--database",
                    str(self.database),
                    *args,
                ]
            )
        return code, out.getvalue(), err.getvalue()

    def test_cli_live_assurance_reports_structured_failure_not_traceback(self):
        code, output, error = self.invoke(
            "assure", "--live", "--wait-seconds", "1"
        )
        self.assertEqual(code, 2)
        result = json.loads(output)
        self.assertFalse(result["ok"])
        self.assertEqual(result["mode"], "live")
        self.assertEqual(result["live"]["attempted"], [self.decoy_id])
        self.assertEqual(result["live"]["missed"], [self.decoy_id])
        self.assertNotIn("Traceback", error)

    def test_cli_records_the_failed_live_run_durably(self):
        self.invoke("assure", "--live", "--wait-seconds", "1")
        engine = Engine(Registry(json.loads(self.registry_path.read_text())), self.database)
        try:
            history = engine.assurance_history(5)
            self.assertEqual(len(history), 1)
            self.assertEqual(history[0]["mode"], "live")
            self.assertFalse(history[0]["ok"])
            self.assertEqual(
                history[0]["details"]["scenarios"][-1]["name"],
                "Live decoy probe",
            )
        finally:
            engine.close()


class NonLiveTests(unittest.TestCase):
    def test_unrelated_registry_fixture_still_passes_canary_mode(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = engine_in(folder)
            try:
                result = run_assurance(engine, now=NOW)
                self.assertTrue(result["ok"])
                self.assertEqual(result["mode"], "canary")
                self.assertNotIn("live", result)
            finally:
                engine.close()

    def test_s3_fixture_unchanged(self):
        self.assertEqual(s3("synthetic-live-001")["eventID"], "synthetic-live-001")


if __name__ == "__main__":
    unittest.main()
