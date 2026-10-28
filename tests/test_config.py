"""Profile loading, precedence, doctor mode gates and readiness details."""

import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path

from fools_gold.cli import main
from fools_gold.config import load_profile
from fools_gold.core import ContractError, Engine, Registry
from fools_gold.doctor import run_doctor
from tests.test_pilot import NOW, registry, s3


class ProfileTests(unittest.TestCase):
    def write(self, folder, document, name="profile.json"):
        path = Path(folder) / name
        path.write_text(json.dumps(document), encoding="utf-8")
        return path

    def test_relative_paths_resolve_against_the_profile(self):
        with tempfile.TemporaryDirectory() as folder:
            path = self.write(
                folder,
                {
                    "registry": "registry.json",
                    "database": "evidence.sqlite",
                    "splunk_host": "hec.example",
                    "splunk_port": 8088,
                    "inbox": "inbox",
                    "state_file": "collector-state.json",
                },
            )
            profile = load_profile(path)
            base = Path(folder)
            self.assertEqual(profile["registry"], str(base / "registry.json"))
            self.assertEqual(profile["database"], str(base / "evidence.sqlite"))
            self.assertEqual(profile["inbox"], str(base / "inbox"))
            self.assertEqual(profile["splunk_port"], 8088)

    def test_unknown_and_secret_like_keys_are_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            for document in (
                {"splunk_token": "x"},
                {"unknown": "x"},
                {"splunk_port": "8088"},
                {"splunk_port": 0},
                {"registry": 5},
                {"registry": ""},
            ):
                with self.subTest(document=document), self.assertRaises(ContractError):
                    load_profile(self.write(folder, document))

    def test_oversized_profile_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "big.json"
            path.write_bytes(b'{"registry": "' + b"x" * (64 * 1024) + b'"}')
            with self.assertRaises(ContractError):
                load_profile(path)


class ProfileCliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.folder = Path(self.temp.name)
        self.registry = self.folder / "registry.json"
        self.registry.write_text(json.dumps(registry()), encoding="utf-8")
        self.database = self.folder / "evidence.sqlite"
        self.profile = self.folder / "profile.json"
        self.profile.write_text(
            json.dumps(
                {"registry": str(self.registry), "database": str(self.database)}
            ),
            encoding="utf-8",
        )

    def tearDown(self):
        self.temp.cleanup()

    def invoke(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_report_runs_from_a_profile(self):
        code, output, error = self.invoke(["--profile", str(self.profile), "report"])
        self.assertEqual(code, 0, error)
        self.assertEqual(json.loads(output)["decisions"]["alert"], 0)

    def test_cli_arguments_override_the_profile(self):
        other = self.folder / "other.sqlite"
        code, _, error = self.invoke(
            [
                "--profile",
                str(self.profile),
                "--database",
                str(other),
                "report",
            ]
        )
        self.assertEqual(code, 0, error)
        self.assertTrue(other.exists())
        self.assertFalse(self.database.exists())

    def test_profile_with_missing_registry_fails_closed(self):
        self.registry.unlink()
        code, _, error = self.invoke(["--profile", str(self.profile), "report"])
        self.assertEqual(code, 2)


class DoctorReadinessTests(unittest.TestCase):
    def engine(self, folder):
        return Engine(Registry(registry()), Path(folder) / "db.sqlite")

    def statuses(self, outcome):
        return {check["name"]: check["status"] for check in outcome["checks"]}

    def test_assurance_mode_gate_requires_the_right_mode(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = self.engine(folder)
            try:
                engine.record_assurance(NOW, "canary", True, 0, {})
                canary = run_doctor(
                    engine,
                    max_assurance_hours=24,
                    assurance_mode="canary",
                    now=NOW,
                )
                self.assertEqual(self.statuses(canary)["assurance"], "pass")
                live = run_doctor(
                    engine,
                    max_assurance_hours=24,
                    assurance_mode="live",
                    now=NOW,
                )
                self.assertEqual(self.statuses(live)["assurance"], "fail")
                self.assertFalse(live["ok"])
            finally:
                engine.close()

    def test_pending_backlog_age_warns(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = self.engine(folder)
            try:
                engine.process(s3(), NOW)
                engine.outbox_enqueue("wazuh", NOW)
                engine.db.execute(
                    "UPDATE outbox SET updated_at='2000-01-01T00:00:00Z'"
                )
                engine.db.commit()
                outcome = run_doctor(engine, now=NOW)
                self.assertEqual(
                    self.statuses(outcome)["delivery_backlog_age"], "warn"
                )
            finally:
                engine.close()

    def test_collection_freshness_warns_for_stale_or_empty_inboxes(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = self.engine(folder)
            inbox = Path(folder) / "inbox"
            inbox.mkdir()
            try:
                outcome = run_doctor(
                    engine,
                    inbox=str(inbox),
                    max_collection_hours=24,
                    now=NOW,
                )
                self.assertEqual(
                    self.statuses(outcome)["collection_freshness"], "warn"
                )
                staged = inbox / "trail.json"
                staged.write_text("{}", encoding="utf-8")
                old = NOW.timestamp() - 48 * 3600
                os.utime(staged, (old, old))
                outcome = run_doctor(
                    engine,
                    inbox=str(inbox),
                    max_collection_hours=24,
                    now=NOW,
                )
                self.assertEqual(
                    self.statuses(outcome)["collection_freshness"], "warn"
                )
            finally:
                engine.close()

    def test_unverified_checks_are_visible_but_do_not_fail_readiness(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = self.engine(folder)
            try:
                outcome = run_doctor(engine, now=NOW)
                statuses = self.statuses(outcome)
                self.assertEqual(statuses["audit_policy"], "unverified")
                self.assertTrue(outcome["ok"])
            finally:
                engine.close()

    def test_bad_bounds_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = self.engine(folder)
            try:
                for kwargs in (
                    {"max_assurance_hours": -1},
                    {"assurance_mode": "synthetic"},
                    {"max_collection_hours": -1},
                ):
                    with self.subTest(kwargs=kwargs), self.assertRaises(ContractError):
                        run_doctor(engine, now=NOW, **kwargs)
            finally:
                engine.close()


class DoctorCliTests(unittest.TestCase):
    def test_doctor_accepts_mode_and_freshness_arguments(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            registry_path = root / "registry.json"
            registry_path.write_text(json.dumps(registry()), encoding="utf-8")
            database = root / "db.sqlite"
            engine = Engine(Registry(registry()), database)
            try:
                engine.record_assurance(NOW, "canary", True, 0, {})
            finally:
                engine.close()
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = main(
                    [
                        "--registry",
                        str(registry_path),
                        "--database",
                        str(database),
                        "doctor",
                        "--max-assurance-hours",
                        "24",
                        "--assurance-mode",
                        "live",
                    ]
                )
            self.assertEqual(code, 2)
            self.assertEqual(
                {
                    check["name"]: check["status"]
                    for check in json.loads(out.getvalue())["checks"]
                }["assurance"],
                "fail",
            )


if __name__ == "__main__":
    unittest.main()
