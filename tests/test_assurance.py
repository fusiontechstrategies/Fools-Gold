import json
import tempfile
import unittest
from pathlib import Path

from fools_gold.assurance import run_check
from tests.test_pilot import NOW, registry, s3
from tests.test_transport import FakeConnection


class AssuranceTests(unittest.TestCase):
    def test_offline_check_passes_all_scenarios(self):
        result = run_check(now=NOW)
        self.assertTrue(result["ok"])
        self.assertEqual(len(result["scenarios"]), 4)
        self.assertTrue(all(s["passed"] for s in result["scenarios"]))
        self.assertEqual(result["decisions"]["alert"], 2)
        self.assertEqual(result["decisions"]["expected_access"], 1)
        self.assertEqual(result["acknowledgment_seconds"], [30, 30])
        self.assertIsNone(result["delivery"])

    def test_canary_events_are_distinct_from_pilot_fixtures(self):
        result = run_check(now=NOW)
        decoys = {s.get("decoy_id") for s in result["scenarios"] if "decoy_id" in s}
        self.assertTrue(all(d.startswith("fg-canary") for d in decoys))
        registry_ids = {d["id"] for d in registry()["decoys"]}
        self.assertFalse(decoys & registry_ids)

    def test_wazuh_transport_stage_runs_when_configured(self):
        with tempfile.TemporaryDirectory() as folder:
            sink = Path(folder) / "canary-wazuh.log"
            result = run_check(
                now=NOW, transport_config={"format": "wazuh", "wazuh_output": str(sink)}
            )
            self.assertTrue(result["ok"])
            self.assertEqual(result["delivery"]["sent"], 2)
            self.assertEqual(len(sink.read_text(encoding="utf-8").splitlines()), 2)

    def test_splunk_transport_stage_runs_when_configured(self):
        old = FakeConnection.responses
        FakeConnection.responses = [(200, b'{"code":0}')]
        try:
            result = run_check(
                now=NOW,
                transport_config={
                    "format": "splunk",
                    "splunk_host": "hec.internal.example",
                    "splunk_port": 8088,
                    "token": "synthetic-check-token",
                    "connection_factory": lambda host, port: FakeConnection(host, port),
                },
            )
            self.assertTrue(result["ok"])
            self.assertEqual(result["delivery"]["sent"], 2)
        finally:
            FakeConnection.responses = old

    def test_failed_transport_fails_the_check(self):
        old = FakeConnection.responses
        FakeConnection.responses = [(500, b"down")]
        try:
            result = run_check(
                now=NOW,
                transport_config={
                    "format": "splunk",
                    "splunk_host": "hec.internal.example",
                    "splunk_port": 8088,
                    "token": "synthetic-check-token",
                    "connection_factory": lambda host, port: FakeConnection(host, port),
                },
            )
            self.assertFalse(result["ok"])
        finally:
            FakeConnection.responses = old


class AssuranceCliTests(unittest.TestCase):
    def invoke_check(self, *args):
        import contextlib
        import io

        from fools_gold.cli import main

        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(["check", *args])
        return code, out.getvalue(), err.getvalue()

    def test_check_command_reports_success(self):
        code, output, _ = self.invoke_check()
        self.assertEqual(code, 0)
        self.assertTrue(json.loads(output)["ok"])

    def test_check_rejects_two_transport_targets(self):
        with tempfile.TemporaryDirectory() as folder:
            code, _, error = self.invoke_check(
                "--splunk-host",
                "hec.example",
                "--splunk-port",
                "8088",
                "--wazuh-output",
                str(Path(folder) / "w.log"),
            )
            self.assertEqual(code, 2)
            self.assertIn("at most one transport target", error)

    def test_check_splunk_requires_port(self):
        code, _, error = self.invoke_check("--splunk-host", "hec.example")
        self.assertEqual(code, 2)
        self.assertIn("--splunk-port", error)

    def test_check_requires_no_registry_or_database(self):
        import contextlib
        import io

        from fools_gold.cli import main

        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(["check"])
        self.assertEqual(code, 0)

    def test_ingest_still_requires_registry_and_database(self):
        import contextlib
        import io

        from fools_gold.cli import main

        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(["report"])
        self.assertEqual(code, 2)
        self.assertIn("requires --registry and --database", err.getvalue())

    def test_s3_fixture_still_matches_the_shared_registry(self):
        self.assertEqual(len(registry()["decoys"]), 2)
        self.assertTrue(s3("synthetic-s3-001")["eventID"].startswith("synthetic"))


if __name__ == "__main__":
    unittest.main()
