"""The scheduled Windows workflow: spool, ingest, retry and restart recovery."""

import json
import tempfile
import unittest
from pathlib import Path

from fools_gold.cli import main, run_windows_collector
from fools_gold.core import Engine, Registry
from fools_gold.winlog import load_state
from tests.test_pilot import registry
from tests.test_windows_collector import make_fetch, win_event

ROOT = Path(__file__).resolve().parents[1]


class ScheduledWorkflowArtifactTests(unittest.TestCase):
    def test_script_spools_ingests_and_never_creates_the_state_file(self):
        script = (
            ROOT / "deployment/windows/register-collector.ps1"
        ).read_text(encoding="utf-8")
        for marker in (
            "collect-windows",
            "ingest",
            "$LASTEXITCODE",
            "pending",
            "processed",
            ".tmp",
            "state-file",
        ):
            self.assertIn(marker, script)
        # The collector must create its own validated state file.
        self.assertNotIn("New-Item -ItemType File -Path $StateFile", script)
        self.assertIn("Do NOT run blindly", script)


class ScheduledWorkflowSimulationTests(unittest.TestCase):
    """Exercise the same sequence the script performs, with real commands."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.folder = Path(self.temp.name)
        self.registry = self.folder / "registry.json"
        self.registry.write_text(json.dumps(registry()), encoding="utf-8")
        self.database = self.folder / "evidence.sqlite"
        self.state = self.folder / "collector-state.json"
        self.spool_dir = self.folder / "spool"
        self.spool_dir.mkdir()
        (self.spool_dir / "processed").mkdir()
        self.counter = 0

    def tearDown(self):
        self.temp.cleanup()

    def collect_to_spool(self, records):
        import contextlib
        import io

        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = run_windows_collector(
                Registry(registry()),
                log_epoch="synthetic-installation-1",
                follow=False,
                interval_seconds=1,
                max_events=128,
                state_file=self.state,
                pages_per_cycle=10,
                fetch=make_fetch(records),
            )
        if code != 0:
            return None
        if not out.getvalue().strip():
            return None
        self.counter += 1
        spool = self.spool_dir / f"events-{self.counter}.jsonl"
        spool.write_text(out.getvalue(), encoding="utf-8")
        return spool

    def ingest(self, spool):
        import contextlib
        import io

        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(
                [
                    "--registry",
                    str(self.registry),
                    "--database",
                    str(self.database),
                    "ingest",
                    str(spool),
                ]
            )
        return code

    def alert_count(self):
        engine = Engine(Registry(registry()), self.database)
        try:
            return engine.report()["decisions"]["alert"]
        finally:
            engine.close()

    def test_first_run_collects_and_ingests_exactly_once(self):
        spool = self.collect_to_spool([(1, win_event(1)), (2, win_event(2))])
        self.assertIsNotNone(spool)
        self.assertEqual(self.ingest(spool), 0)
        (self.spool_dir / "processed" / spool.name).write_bytes(spool.read_bytes())
        spool.unlink()
        self.assertEqual(self.alert_count(), 2)
        # Idle rerun: no new events, no new spool, no replay.
        self.assertIsNone(self.collect_to_spool([(1, win_event(1)), (2, win_event(2))]))
        self.assertEqual(self.alert_count(), 2)

    def test_ingestion_failure_keeps_the_spool_for_retry(self):
        spool = self.collect_to_spool([(1, win_event(1))])
        self.assertIsNotNone(spool)
        spool.write_text(spool.read_text(encoding="utf-8") + "{not json}\n")
        self.assertEqual(self.ingest(spool), 2)
        self.assertTrue(spool.exists())
        self.assertEqual(self.alert_count(), 1)
        # Restart recovery: drop the bad line, retry the pending spool.
        spool.write_text(
            "\n".join(
                line
                for line in spool.read_text(encoding="utf-8").splitlines()
                if line.strip() and not line.startswith("{not")
            )
            + "\n",
            encoding="utf-8",
        )
        self.assertEqual(self.ingest(spool), 0)
        (self.spool_dir / "processed" / spool.name).write_bytes(spool.read_bytes())
        spool.unlink()
        self.assertEqual(self.alert_count(), 1)

    def test_collection_failure_does_not_advance_the_cursor(self):

        from fools_gold.core import ContractError

        def broken_fetch(**_kwargs):
            raise ContractError("simulated wevtutil failure")

        with self.assertRaises(ContractError):
            run_windows_collector(
                Registry(registry()),
                log_epoch="synthetic-installation-1",
                follow=False,
                interval_seconds=1,
                max_events=128,
                state_file=self.state,
                fetch=broken_fetch,
            )
        self.assertFalse(self.state.exists())
        self.assertEqual(list(self.spool_dir.glob("*.jsonl")), [])

    def test_restart_resumes_from_the_persisted_cursor(self):
        self.assertIsNotNone(self.collect_to_spool([(1, win_event(1))]))
        state = load_state(self.state)
        self.assertEqual(state["last_record_id"], 1)
        spool = self.collect_to_spool(
            [(1, win_event(1)), (2, win_event(2)), (3, win_event(3))]
        )
        self.assertIsNotNone(spool)
        lines = spool.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 2)
        self.assertEqual(load_state(self.state)["last_record_id"], 3)


if __name__ == "__main__":
    unittest.main()
