import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from defusedxml import ElementTree as ET

from fools_gold.adapters import main
from fools_gold.cli import main as engine_main
from fools_gold.core import Engine, Registry
from tests.test_adapters import WINDOWS_XML
from tests.test_pilot import NOW, registry, s3


class AdapterCliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.folder = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def invoke(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(list(args))
        return code, out.getvalue(), err.getvalue()

    def test_windows_and_cloudtrail_conversion(self):
        windows = self.folder / "event.xml"
        windows.write_bytes(WINDOWS_XML)
        code, output, _ = self.invoke(
            "windows-export", str(windows), "--log-epoch", "test-generation"
        )
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output)["log_epoch"], "test-generation")
        cloud = self.folder / "cloud.json"
        cloud.write_text(json.dumps({"Records": [s3()]}), encoding="utf-8")
        code, output, _ = self.invoke("cloudtrail-export", str(cloud))
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output), s3())

    def test_retained_alert_export_and_both_renderers(self):
        registry_path = self.folder / "registry.json"
        registry_path.write_text(json.dumps(registry()), encoding="utf-8")
        database = self.folder / "evidence.sqlite"
        engine = Engine(Registry(registry()), database)
        expected = engine.process(s3(), NOW)["alert"]
        engine.close()
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = engine_main(
                [
                    "--registry",
                    str(registry_path),
                    "--database",
                    str(database),
                    "export-alerts",
                ]
            )
        self.assertEqual(code, 0)
        decisions = self.folder / "decisions.jsonl"
        decisions.write_text(out.getvalue(), encoding="utf-8")
        for target, field in (("wazuh", "fg_alert_id"), ("splunk", "event")):
            code, output, _ = self.invoke(
                "render-alerts", str(decisions), "--format", target
            )
            self.assertEqual(code, 0)
            value = json.loads(output)
            actual = value[field] if target == "wazuh" else value[field]["alert_id"]
            self.assertEqual(actual, expected["alert_id"])

    def test_rejection_stream_cannot_be_mistaken_for_complete_packets(self):
        decisions = self.folder / "decisions.jsonl"
        decisions.write_text('{"decision":"rejected"}\n', encoding="utf-8")
        code, output, error = self.invoke(
            "render-alerts", str(decisions), "--format", "wazuh"
        )
        self.assertEqual(code, 2)
        self.assertEqual(output, "")
        self.assertIn("rejection", error)

    def test_synthetic_deployment_artifacts_remain_disabled_and_scoped(self):
        root = Path(__file__).resolve().parents[1]
        plan = json.loads((root / "deployment/pilot-plan.template.json").read_text())
        self.assertFalse(plan["deployment_enabled"])
        self.assertFalse(plan["production_delivery_enabled"])
        self.assertIsNone(plan["splunk_hec"]["endpoint"])
        selectors = json.loads(
            (root / "deployment/cloudtrail-data-selector.synthetic.json").read_text()
        )
        fields = {f["Field"]: f["Equals"] for f in selectors[0]["FieldSelectors"]}
        self.assertEqual(fields["eventCategory"], ["Data"])
        self.assertEqual(fields["resources.type"], ["AWS::S3::Object"])
        self.assertEqual(
            fields["resources.ARN"], [registry()["decoys"][0]["locator"]["arn"]]
        )
        rule = ET.parse(root / "deployment/wazuh-rules.example.xml").getroot()
        self.assertEqual(rule.find("rule/decoded_as").text, "json")
        self.assertEqual(rule.find("rule/field").attrib["name"], "fg_product")
        local = ET.parse(root / "deployment/wazuh-localfile.example.xml").getroot()
        self.assertEqual(local.find("log_format").text, "json")

    def test_shipped_deployment_artifacts_are_present_and_scoped(self):
        root = Path(__file__).resolve().parents[1]
        expected = {
            "Dockerfile": "ENTRYPOINT",
            "docker-compose.yml": "fools-gold",
            "deployment/systemd/fools-gold-inbox.service": "trail-inbox",
            "deployment/systemd/fools-gold-inbox.timer": "OnUnitActiveSec",
            "deployment/terraform/main.tf": "aws_cloudtrail",
            "deployment/splunk/fools_gold.savedsearches.conf": "fools_gold:alert:json",
            "deployment/elastic/fools_gold.eql": "fools_gold.alert",
            "deployment/sentinel/fools_gold.kql": "fools-gold",
        }
        for relative, marker in expected.items():
            with self.subTest(artifact=relative):
                content = (root / relative).read_text(encoding="utf-8")
                self.assertIn(marker, content)
        terraform = (root / "deployment/terraform/main.tf").read_text(encoding="utf-8")
        self.assertIn("NOT APPLIED", terraform.upper())
        self.assertNotIn("access_key", terraform)
        # Listings are captured as bucket-level data events, not management
        # selectors with unsupported eventName/ARN filtering.
        self.assertIn("AWS::S3::Bucket", terraform)
        self.assertNotIn('equals = ["Management"]', terraform)
