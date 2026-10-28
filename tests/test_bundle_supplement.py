"""Evidence exports include annotations, delivery, assurance and acceptance."""

import json
import tempfile
import unittest
import zipfile
from datetime import timedelta
from pathlib import Path

from fools_gold.core import Engine, Registry
from fools_gold.reporting import build_bundle, verify_bundle
from tests.test_pilot import NOW, registry, s3

KEY = b"k" * 32


class BundleSupplementTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.folder = Path(self.temp.name)
        self.engine = Engine(
            Registry(registry()), self.folder / "db.sqlite", mac_key=KEY
        )

    def tearDown(self):
        self.engine.close()
        self.temp.cleanup()

    def test_bundle_carries_acknowledgment_and_operational_history(self):
        alert = self.engine.process(s3(), NOW)["alert"]
        self.engine.acknowledge(
            alert["alert_id"], "analyst-a", NOW + timedelta(seconds=30)
        )
        self.engine.outbox_enqueue("wazuh", NOW)
        self.engine.record_assurance(NOW, "canary", True, 0, {"scenarios": []})
        self.engine.record_acceptance(
            NOW, "ingestion", "visible in index", "analyst-b"
        )
        target = self.folder / "case.zip"
        build_bundle(self.engine, target, now=NOW)
        with zipfile.ZipFile(target) as archive:
            entries = {name: archive.read(name) for name in archive.namelist()}
        self.assertEqual(
            set(entries),
            {
                "alerts.jsonl",
                "checkpoints.jsonl",
                "annotations.jsonl",
                "delivery.jsonl",
                "assurance.jsonl",
                "acceptances.jsonl",
                "report.json",
                "manifest.json",
                "manifest.sig",
            },
        )
        annotation = json.loads(entries["annotations.jsonl"])
        self.assertEqual(annotation["acknowledged_by"], "analyst-a")
        self.assertEqual(
            annotation["acknowledged_at"], "2026-10-02T12:00:30Z"
        )
        delivery = json.loads(entries["delivery.jsonl"])
        self.assertEqual(delivery["destination"], "wazuh")
        assurance = json.loads(entries["assurance.jsonl"])
        self.assertEqual(assurance["mode"], "canary")
        self.assertTrue(assurance["ok"])
        acceptance = json.loads(entries["acceptances.jsonl"])
        self.assertEqual(acceptance["stage"], "ingestion")
        report = json.loads(entries["report.json"])
        self.assertEqual(report["supplemental"]["annotations"], 1)
        self.assertEqual(report["supplemental"]["delivery"], 1)
        self.assertEqual(report["supplemental"]["assurance_runs"], 1)
        self.assertEqual(report["supplemental"]["acceptances"], 1)
        outcome = verify_bundle(target, KEY)
        self.assertTrue(outcome["ok"], outcome)
        self.assertEqual(outcome["signature"], "verified")

    def test_tampered_annotation_is_detected(self):
        alert = self.engine.process(s3(), NOW)["alert"]
        self.engine.acknowledge(alert["alert_id"], "analyst-a", NOW)
        target = self.folder / "case.zip"
        build_bundle(self.engine, target, now=NOW)
        tampered = self.folder / "tampered.zip"
        with zipfile.ZipFile(target) as source:
            entries = {name: source.read(name) for name in source.namelist()}
        entries["annotations.jsonl"] = entries["annotations.jsonl"].replace(
            b"analyst-a", b"someone-else"
        )
        with zipfile.ZipFile(tampered, "x") as destination:
            for name, data in entries.items():
                destination.writestr(name, data)
        outcome = verify_bundle(tampered, KEY)
        self.assertFalse(outcome["ok"])
        self.assertIn("annotations.jsonl", outcome["failures"])

    def test_supplemental_counts_must_match(self):
        self.engine.process(s3(), NOW)
        target = self.folder / "case.zip"
        build_bundle(self.engine, target, now=NOW)
        forged = self.folder / "forged.zip"
        with zipfile.ZipFile(target) as source:
            entries = {name: source.read(name) for name in source.namelist()}
        report = json.loads(entries["report.json"])
        report["supplemental"]["delivery"] = 5
        entries["report.json"] = json.dumps(
            report, sort_keys=True, separators=(",", ":")
        ).encode()
        with zipfile.ZipFile(forged, "x") as destination:
            for name, data in entries.items():
                destination.writestr(name, data)
        with self.assertRaises(Exception):
            verify_bundle(forged, KEY)


if __name__ == "__main__":
    unittest.main()
