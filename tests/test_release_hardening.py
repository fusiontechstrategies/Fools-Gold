"""Cross-feature regressions found during release acceptance."""

import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

from fools_gold.cli import main, run_windows_collector
from fools_gold.core import ContractError, Engine, Registry
from fools_gold.reporting import build_bundle, verify_bundle
from fools_gold.winlog import load_state
from tests.test_pilot import NOW, registry, s3
from tests.test_windows_collector import make_fetch, win_event

KEY = b"k" * 32


class EmptySignedRetentionTests(unittest.TestCase):
    def test_complete_retention_preserves_the_key_requirement(self):
        with tempfile.TemporaryDirectory() as folder:
            database = Path(folder) / "evidence.sqlite"
            engine = Engine(Registry(registry()), database, mac_key=KEY)
            engine.process(s3("before-retention"), NOW)
            engine.prune(NOW + timedelta(days=30), 5)
            engine.close()
            for key in (None, b"w" * 32):
                reader = Engine(Registry(registry()), database, mac_key=key)
                try:
                    self.assertEqual(len(list(reader.export_alerts())), 0)
                    with self.assertRaises(ContractError):
                        reader.process(s3("missing-or-wrong-key"), NOW)
                    self.assertEqual(
                        reader.db.execute(
                            "SELECT COUNT(*) FROM checkpoints"
                        ).fetchone()[0],
                        1,
                    )
                finally:
                    reader.close()
            writer = Engine(Registry(registry()), database, mac_key=KEY)
            try:
                self.assertEqual(
                    writer.process(s3("after-retention"), NOW)["decision"], "alert"
                )
                self.assertTrue(writer.verify_integrity()["ok"])
            finally:
                writer.close()

    def test_unused_checkpoint_tampering_is_detected_with_no_alerts(self):
        with tempfile.TemporaryDirectory() as folder:
            database = Path(folder) / "evidence.sqlite"
            engine = Engine(Registry(registry()), database, mac_key=KEY)
            engine.process(s3(), NOW)
            engine.prune(NOW + timedelta(days=30), 5)
            engine.db.execute("UPDATE checkpoints SET mac=?", ("0" * 64,))
            engine.db.commit()
            engine.close()
            reader = Engine(Registry(registry()), database, mac_key=KEY)
            try:
                self.assertFalse(reader.verify_integrity()["ok"])
                with self.assertRaises(ContractError):
                    reader.process(s3("after-tamper"), NOW)
            finally:
                reader.close()


class BundleSnapshotTests(unittest.TestCase):
    def capture_during(self, action):
        with tempfile.TemporaryDirectory() as folder:
            database = Path(folder) / "evidence.sqlite"
            reader = Engine(Registry(registry()), database, mac_key=KEY)
            writer = Engine(Registry(registry()), database, mac_key=KEY)
            try:
                reader.process(s3("snapshot-old"), NOW)
                reader.process(s3("snapshot-new"), NOW + timedelta(days=10))
                original = reader.export_alerts

                def interleaved():
                    yield from original()
                    action(writer)

                target = Path(folder) / "snapshot.zip"
                with patch.object(reader, "export_alerts", interleaved):
                    build_bundle(reader, target, now=NOW + timedelta(days=11))
                self.assertTrue(verify_bundle(target, KEY)["ok"])
                with zipfile.ZipFile(target) as archive:
                    manifest = json.loads(archive.read("manifest.json"))
                    report = json.loads(archive.read("report.json"))
                    count = len(archive.read("alerts.jsonl").splitlines())
                self.assertEqual(count, 2)
                self.assertEqual(manifest["alerts"], count)
                self.assertEqual(report["report"]["decisions"]["alert"], count)
                self.assertEqual(report["integrity"]["alerts"], count)
                self.assertFalse(reader.db.in_transaction)
                reader.process(s3("write-after-snapshot"), NOW + timedelta(days=11))
                self.assertTrue(reader.verify_integrity()["ok"])
            finally:
                writer.close()
                reader.close()

    def test_bundle_is_coherent_during_ingestion(self):
        self.capture_during(
            lambda writer: writer.process(s3("concurrent"), NOW + timedelta(days=11))
        )

    def test_bundle_is_coherent_during_retention(self):
        self.capture_during(lambda writer: writer.prune(NOW + timedelta(days=11), 5))

    def test_read_snapshot_does_not_end_the_callers_transaction(self):
        engine = Engine(Registry(registry()), ":memory:")
        try:
            engine.db.execute("BEGIN")
            with engine.read_snapshot():
                engine.report()
            self.assertTrue(engine.db.in_transaction)
            engine.db.rollback()
        finally:
            engine.close()


class DurableCollectorPageTests(unittest.TestCase):
    def test_failed_later_page_keeps_completed_page_and_recovers(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            spool = root / "spool"
            spool.mkdir()
            state = root / "cursor.json"
            calls = []

            def fetch(**kwargs):
                calls.append(kwargs)
                if len(calls) > 1:
                    raise ContractError("second-page query failed")
                return b"".join(win_event(i) for i in range(1, 129))

            options = dict(
                log_epoch="release-test",
                follow=False,
                interval_seconds=1,
                max_events=128,
                state_file=state,
                spool_directory=spool,
            )
            with self.assertRaises(ContractError):
                run_windows_collector(Registry(registry()), fetch=fetch, **options)
            pages = list(spool.glob("*.jsonl"))
            self.assertEqual(len(pages), 1)
            self.assertEqual(len(pages[0].read_text().splitlines()), 128)
            self.assertEqual(load_state(state)["last_record_id"], 128)
            run_windows_collector(
                Registry(registry()),
                fetch=make_fetch([(i, win_event(i)) for i in range(1, 130)]),
                **options,
            )
            registry_path = root / "registry.json"
            registry_path.write_text(json.dumps(registry()), encoding="utf-8")
            database = root / "evidence.sqlite"
            for page in spool.glob("*.jsonl"):
                with contextlib.redirect_stdout(io.StringIO()):
                    result = main(
                        [
                            "--registry",
                            str(registry_path),
                            "--database",
                            str(database),
                            "ingest",
                            str(page),
                        ]
                    )
                self.assertEqual(result, 0)
            engine = Engine(Registry(registry()), database)
            try:
                self.assertEqual(engine.report()["decisions"]["alert"], 129)
            finally:
                engine.close()

    def test_spool_failure_leaves_cursor_unchanged(self):
        with tempfile.TemporaryDirectory() as folder:
            state = Path(folder) / "cursor.json"
            with patch(
                "fools_gold.winlog.os.replace", side_effect=OSError("disk full")
            ):
                with self.assertRaises(ContractError):
                    run_windows_collector(
                        Registry(registry()),
                        log_epoch="release-test",
                        follow=False,
                        interval_seconds=1,
                        max_events=128,
                        state_file=state,
                        spool_directory=folder,
                        fetch=make_fetch([(1, win_event(1))]),
                    )
            self.assertFalse(state.exists())
            self.assertEqual(list(Path(folder).glob("*.jsonl")), [])

    def test_replay_after_cursor_save_failure_is_safe(self):
        with tempfile.TemporaryDirectory() as folder:
            state = Path(folder) / "cursor.json"
            options = dict(
                log_epoch="release-test",
                follow=False,
                interval_seconds=1,
                max_events=128,
                state_file=state,
                spool_directory=folder,
                fetch=make_fetch([(1, win_event(1))]),
            )
            with patch(
                "fools_gold.winlog.save_state",
                side_effect=OSError("cursor write failed"),
            ):
                with self.assertRaises(OSError):
                    run_windows_collector(Registry(registry()), **options)
            self.assertEqual(len(list(Path(folder).glob("*.jsonl"))), 1)
            run_windows_collector(Registry(registry()), **options)
            pages = list(Path(folder).glob("*.jsonl"))
            self.assertEqual(len(pages), 2)
            self.assertEqual(pages[0].read_bytes(), pages[1].read_bytes())


@unittest.skipUnless(os.name == "nt", "Windows PowerShell 5.1 regression")
class WindowsWorkerNativeTests(unittest.TestCase):
    def test_stderr_diagnostics_do_not_bypass_native_exit_handling(self):
        powershell = shutil.which("powershell.exe")
        if powershell is None:
            self.skipTest("Windows PowerShell is unavailable")
        source = (
            Path(__file__).resolve().parents[1]
            / "deployment/windows/register-collector.ps1"
        ).read_text(encoding="utf-8")
        helper = source.split("function Invoke-FoolsGold", 1)[1].split(
            "function Invoke-Ingest", 1
        )[0]

        def literal(value):
            return "'" + str(value).replace("'", "''") + "'"

        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            program = root / "native.py"
            program.write_text(
                "import sys; print('synthetic diagnostic', file=sys.stderr); "
                "sys.exit(int(sys.argv[1]))",
                encoding="utf-8",
            )
            for code in (0, 2):
                script = root / f"verify-{code}.ps1"
                script.write_text(
                    "$ErrorActionPreference = 'Stop'\n"
                    f"$FoolsGold = {literal(sys.executable)}\n"
                    f"$LogFile = {literal(root / 'diagnostics.log')}\n"
                    "function Invoke-FoolsGold"
                    + helper
                    + f"\n$result = Invoke-FoolsGold -Arguments @({literal(program)}, '{code}')\n"
                    + "Write-Output ('NATIVE_EXIT=' + $result)\n"
                    + "Write-Output ('PREFERENCE=' + $ErrorActionPreference)\n",
                    encoding="utf-8",
                )
                completed = subprocess.run(
                    [powershell, "-NoProfile", "-NonInteractive", "-File", str(script)],
                    capture_output=True,
                    text=True,
                    timeout=20,
                )
                with self.subTest(native_exit=code):
                    self.assertEqual(completed.returncode, 0, completed.stderr)
                    self.assertIn(f"NATIVE_EXIT={code}", completed.stdout)
                    self.assertIn("PREFERENCE=Stop", completed.stdout)
            self.assertIn(
                "synthetic diagnostic",
                (root / "diagnostics.log").read_text(encoding="utf-16"),
            )


if __name__ == "__main__":
    unittest.main()
