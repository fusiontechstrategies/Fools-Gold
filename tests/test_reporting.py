"""Incident clustering and evidence bundle tests."""

import contextlib
import io
import json
import tempfile
import unittest
import zipfile
from datetime import timedelta
from pathlib import Path

from fools_gold.cli import main
from fools_gold.core import Engine, Registry
from fools_gold.reporting import build_bundle, incidents, verify_bundle
from tests.test_contracts_v2 import linux
from tests.test_pilot import NOW, registry, s3


def engine_in(folder, mac_key=None):
    return Engine(Registry(registry()), Path(folder) / "db.sqlite", mac_key=mac_key)


class IncidentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.engine = engine_in(self.temp.name)

    def tearDown(self):
        self.engine.close()
        self.temp.cleanup()

    def test_alerts_from_one_actor_within_gap_form_one_incident(self):
        self.engine.process(s3("synthetic-i-1"), NOW)
        self.engine.process(s3("synthetic-i-2"), NOW + timedelta(seconds=3))
        self.engine.process(linux("501"), NOW + timedelta(seconds=4))
        outcome = incidents(self.engine, 300)
        self.assertEqual(len(outcome["incidents"]), 2)
        incident = outcome["incidents"][0]
        self.assertEqual(incident["alert_count"], 2)
        self.assertEqual(incident["decoys"], ["synthetic-s3-backup"])
        self.assertEqual(incident["actions"], ["read"])
        self.assertEqual(incident["mitre_techniques"], ["T1530"])
        self.assertEqual(len(incident["alert_ids"]), 2)
        self.assertEqual(outcome["incidents"][1]["actor"], "uid:1001")

    def test_gap_splits_incidents_and_actors_stay_separate(self):
        self.engine.process(s3("synthetic-g-1"), NOW)
        self.engine.process(s3("synthetic-g-2"), NOW + timedelta(seconds=600))
        self.engine.process(linux("501"), NOW + timedelta(seconds=1))
        outcome = incidents(self.engine, 300)
        self.assertEqual(len(outcome["incidents"]), 3)

    def test_acknowledgment_is_counted(self):
        alert = self.engine.process(s3(), NOW)["alert"]
        self.engine.acknowledge(alert["alert_id"], "analyst", NOW + timedelta(seconds=5))
        incident = incidents(self.engine, 300)["incidents"][0]
        self.assertEqual(incident["acknowledged"], 1)

    def test_gap_bounds(self):
        for value in (0, 86401, "300"):
            with self.assertRaises(Exception):
                incidents(self.engine, value)


class BundleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.folder = Path(self.temp.name)
        self.key = b"k" * 32
        self.engine = engine_in(self.temp.name, mac_key=self.key)

    def tearDown(self):
        self.engine.close()
        self.temp.cleanup()

    def test_bundle_round_trip_with_signature(self):
        self.engine.process(s3(), NOW)
        target = self.folder / "case.zip"
        build_bundle(self.engine, target, now=NOW)
        outcome = verify_bundle(target, self.key)
        self.assertTrue(outcome["ok"])
        self.assertEqual(outcome["signature"], "verified")
        self.assertEqual(outcome["alerts"], 1)
        self.assertTrue(outcome["integrity_ok"])
        self.assertEqual(outcome["failures"], [])

    def test_bundle_without_key_has_no_signature(self):
        with tempfile.TemporaryDirectory() as other:
            engine = engine_in(other)
            try:
                engine.process(s3(), NOW)
                target = Path(other) / "plain.zip"
                build_bundle(engine, target, now=NOW)
                outcome = verify_bundle(target)
                self.assertTrue(outcome["ok"])
                self.assertIsNone(outcome["signature"])
                self.assertIsNone(outcome["integrity_ok"])
            finally:
                engine.close()

    def test_unverified_signature_when_key_missing(self):
        self.engine.process(s3(), NOW)
        target = self.folder / "case.zip"
        build_bundle(self.engine, target, now=NOW)
        outcome = verify_bundle(target)
        self.assertEqual(outcome["signature"], "unverified")
        self.assertTrue(outcome["ok"])

    def test_tampered_entry_is_detected(self):
        self.engine.process(s3(), NOW)
        target = self.folder / "case.zip"
        build_bundle(self.engine, target, now=NOW)
        tampered = self.folder / "tampered.zip"
        with zipfile.ZipFile(target) as source, zipfile.ZipFile(
            tampered, "x"
        ) as destination:
            for name in source.namelist():
                data = source.read(name)
                if name == "alerts.jsonl":
                    data = data.replace(b"synthetic-soc", b"tampered-owner")
                destination.writestr(name, data)
        outcome = verify_bundle(tampered, self.key)
        self.assertFalse(outcome["ok"])
        self.assertEqual(outcome["failures"], ["alerts.jsonl"])
        # The manifest and its signature are untouched, so the signature still
        # verifies; the entry hash is what catches the tampering.
        self.assertEqual(outcome["signature"], "verified")

    def test_rewritten_manifest_invalidates_the_signature(self):
        self.engine.process(s3(), NOW)
        target = self.folder / "case.zip"
        build_bundle(self.engine, target, now=NOW)
        forged = self.folder / "forged.zip"
        with zipfile.ZipFile(target) as source:
            entries = {name: source.read(name) for name in source.namelist()}
        manifest = json.loads(entries["manifest.json"])
        tampered_alerts = entries["alerts.jsonl"].replace(b"synthetic-soc", b"evil")
        manifest["file_sha256"]["alerts.jsonl"] = __import__("hashlib").sha256(
            tampered_alerts
        ).hexdigest()
        entries["alerts.jsonl"] = tampered_alerts
        entries["manifest.json"] = json.dumps(
            manifest, sort_keys=True, separators=(",", ":")
        ).encode()
        with zipfile.ZipFile(forged, "x") as destination:
            for name, data in entries.items():
                destination.writestr(name, data)
        outcome = verify_bundle(forged, self.key)
        self.assertFalse(outcome["ok"])
        self.assertTrue(outcome["files_ok"])
        self.assertEqual(outcome["signature"], "invalid")

    def test_signed_bundle_without_signature_fails_when_key_supplied(self):
        import hashlib

        self.engine.process(s3(), NOW)
        target = self.folder / "case.zip"
        build_bundle(self.engine, target, now=NOW)
        with zipfile.ZipFile(target) as source:
            entries = {
                name: source.read(name)
                for name in source.namelist()
                if name != "manifest.sig"
            }
        manifest = json.loads(entries["manifest.json"])
        tampered = entries["alerts.jsonl"].replace(b"synthetic-soc", b"tampered")
        manifest["file_sha256"]["alerts.jsonl"] = hashlib.sha256(
            tampered
        ).hexdigest()
        entries["alerts.jsonl"] = tampered
        entries["manifest.json"] = json.dumps(
            manifest, sort_keys=True, separators=(",", ":")
        ).encode()
        downgraded = self.folder / "downgraded.zip"
        with zipfile.ZipFile(downgraded, "x") as destination:
            for name, data in entries.items():
                destination.writestr(name, data)
        outcome = verify_bundle(downgraded, self.key)
        self.assertFalse(outcome["ok"])
        self.assertEqual(outcome["signature"], "missing")
        self.assertFalse(outcome["authenticated"])

    def test_manifest_only_archive_is_not_a_complete_bundle(self):
        target = self.folder / "manifest-only.zip"
        with zipfile.ZipFile(target, "x") as archive:
            archive.writestr("manifest.json", b"{}")
        with self.assertRaises(Exception):
            verify_bundle(target, self.key)

    def test_alert_count_must_match_the_payload(self):
        self.engine.process(s3(), NOW)
        target = self.folder / "case.zip"
        build_bundle(self.engine, target, now=NOW)
        with zipfile.ZipFile(target) as source:
            entries = {name: source.read(name) for name in source.namelist()}
        manifest = json.loads(entries["manifest.json"])
        manifest["alerts"] = manifest["alerts"] + 1
        entries["manifest.json"] = json.dumps(
            manifest, sort_keys=True, separators=(",", ":")
        ).encode()
        forged = self.folder / "count.zip"
        with zipfile.ZipFile(forged, "x") as destination:
            for name, data in entries.items():
                destination.writestr(name, data)
        with self.assertRaises(Exception):
            verify_bundle(forged)

    def test_recorded_source_integrity_failure_is_not_hidden(self):
        self.engine.process(s3(), NOW)
        target = self.folder / "case.zip"
        build_bundle(self.engine, target, now=NOW)
        with zipfile.ZipFile(target) as source:
            entries = {name: source.read(name) for name in source.namelist()}
        manifest = json.loads(entries["manifest.json"])
        manifest["integrity_ok"] = False
        entries["manifest.json"] = json.dumps(
            manifest, sort_keys=True, separators=(",", ":")
        ).encode()
        forged = self.folder / "integrity.zip"
        with zipfile.ZipFile(forged, "x") as destination:
            for name, data in entries.items():
                destination.writestr(name, data)
        outcome = verify_bundle(forged)
        self.assertFalse(outcome["ok"])
        self.assertFalse(outcome["source_integrity_ok"])

    def test_unexpected_entries_and_existing_target_rejected(self):
        self.engine.process(s3(), NOW)
        target = self.folder / "case.zip"
        with zipfile.ZipFile(target, "x") as archive:
            archive.writestr("evil.sh", b"#!/bin/sh")
        with self.assertRaises(Exception):
            verify_bundle(target)
        target2 = self.folder / "case2.zip"
        build_bundle(self.engine, target2, now=NOW)
        with self.assertRaises(Exception):
            build_bundle(self.engine, target2, now=NOW)

    def test_bad_zip_and_missing_file_rejected(self):
        bogus = self.folder / "bogus.zip"
        bogus.write_bytes(b"not a zip")
        with self.assertRaises(Exception):
            verify_bundle(bogus)
        with self.assertRaises(Exception):
            verify_bundle(self.folder / "absent.zip")


class ReportingCliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.folder = Path(self.temp.name)
        self.registry = self.folder / "registry.json"
        self.registry.write_text(json.dumps(registry()), encoding="utf-8")
        self.database = self.folder / "db.sqlite"
        self.key = self.folder / "key.hex"
        self.key.write_text("ab" * 32, encoding="ascii")
        self.registry_arg = ["--registry", str(self.registry)]
        self.db_arg = ["--database", str(self.database)]

    def tearDown(self):
        self.temp.cleanup()

    def invoke(self, *args, keyed=False):
        argv = self.registry_arg + self.db_arg
        if keyed:
            argv += ["--evidence-key-file", str(self.key)]
        argv += list(args)
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(argv)
        return code, out.getvalue(), err.getvalue()

    def ingest_one(self):
        event = s3()
        event["eventTime"] = "2000-01-01T00:00:00Z"
        events = self.folder / "events.jsonl"
        events.write_text(json.dumps(event) + "\n", encoding="utf-8")
        code, _, _ = self.invoke("ingest", str(events), keyed=True)
        self.assertEqual(code, 0)

    def test_incidents_and_bundle_cli(self):
        self.ingest_one()
        code, output, _ = self.invoke("incidents")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output)["incidents"][0]["alert_count"], 1)
        bundle = self.folder / "case.zip"
        code, output, _ = self.invoke(
            "bundle", "--out", str(bundle), keyed=True
        )
        self.assertEqual(code, 0)
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(
                [
                    "--evidence-key-file",
                    str(self.key),
                    "verify-bundle",
                    "--file",
                    str(bundle),
                ]
            )
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out.getvalue())["signature"], "verified")

    def test_verify_bundle_tamper_exits_two(self):
        self.ingest_one()
        bundle = self.folder / "case.zip"
        self.invoke("bundle", "--out", str(bundle))
        tampered = self.folder / "tampered.zip"
        with zipfile.ZipFile(bundle) as source, zipfile.ZipFile(
            tampered, "x"
        ) as destination:
            for name in source.namelist():
                data = source.read(name)
                if name == "alerts.jsonl":
                    # Parseable tamper: the manifest hash must catch it.
                    data = data.replace(b"synthetic-soc", b"tampered-soc")
                destination.writestr(name, data)
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(["verify-bundle", "--file", str(tampered)])
        self.assertEqual(code, 2)
        self.assertFalse(json.loads(out.getvalue())["ok"])


if __name__ == "__main__":
    unittest.main()
