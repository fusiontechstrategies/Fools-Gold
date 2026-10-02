import copy
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

from fools_gold.cli import parse_json
from fools_gold.core import ContractError, Engine, Registry, normalize

NOW = datetime(2026, 10, 2, 12, 0, tzinfo=UTC)


def registry():
    return {
        "schema_version": 1,
        "decoys": [
            {
                "id": "synthetic-s3-backup",
                "owner": "synthetic-soc",
                "source": "aws.cloudtrail.s3",
                "locator": {
                    "account": "000000000000",
                    "region": "us-gov-west-1",
                    "arn": "arn:aws-us-gov:s3:::synthetic-decoy-bucket/backups/inventory.txt",
                },
                "created_at": "2026-10-01T00:00:00Z",
                "expires_at": "2026-11-01T00:00:00Z",
                "expected_actions": ["read", "write", "append", "delete"],
                "response_procedure": "Synthetic triage: verify actor and contact owner",
                "exceptions": [
                    {
                        "id": "synthetic-backup-test",
                        "actor": "arn:aws-us-gov:sts::000000000000:assumed-role/synthetic-backup/synthetic-session",
                        "owner": "synthetic-backup-owner",
                        "reason": "Authorized synthetic read test",
                        "actions": ["read"],
                        "starts_at": "2026-10-02T00:00:00Z",
                        "expires_at": "2026-10-03T00:00:00Z",
                    }
                ],
            },
            {
                "id": "synthetic-windows-config",
                "owner": "synthetic-soc",
                "source": "windows.security",
                "locator": {
                    "host": "synthetic-fs01",
                    "path": "C:\\SyntheticDecoys\\config-export.txt",
                },
                "created_at": "2026-10-01T00:00:00Z",
                "expires_at": "2026-11-01T00:00:00Z",
                "expected_actions": ["read", "write", "append", "delete"],
                "response_procedure": "Synthetic triage: inspect process and confirm authorized testing",
            },
        ],
    }


def s3(identifier="synthetic-s3-001"):
    return {
        "eventSource": "s3.amazonaws.com",
        "eventCategory": "Data",
        "eventName": "GetObject",
        "eventID": identifier,
        "eventTime": "2026-10-02T11:59:55Z",
        "awsRegion": "us-gov-west-1",
        "recipientAccountId": "000000000000",
        "requestParameters": {
            "bucketName": "synthetic-decoy-bucket",
            "key": "backups/inventory.txt",
        },
        "resources": [
            {
                "type": "AWS::S3::Object",
                "ARN": "arn:aws-us-gov:s3:::synthetic-decoy-bucket/backups/inventory.txt",
            }
        ],
        "userIdentity": {
            "type": "AssumedRole",
            "arn": "arn:aws-us-gov:sts::000000000000:assumed-role/synthetic-intrusion-test/synthetic-session",
        },
        "sourceIPAddress": "192.0.2.10",
    }


def windows(record="101"):
    return {
        "source": "windows.security",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "event_id": 4663,
        "audit_outcome": "success",
        "object_type": "File",
        "computer": "synthetic-fs01",
        "log_epoch": "synthetic-installation-1",
        "record_id": record,
        "time": "2026-10-02T11:59:58Z",
        "object_name": "C:\\SyntheticDecoys\\config-export.txt",
        "access_mask": "0x1",
        "subject_sid": "S-1-5-21-111-222-333-1001",
        "process_name": "C:\\Windows\\System32\\notepad.exe",
    }


class PilotTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "evidence.sqlite"
        self.engine = Engine(Registry(registry()), self.path)

    def tearDown(self):
        self.engine.close()
        self.temp.cleanup()

    def test_s3_read_yields_evidence_and_delay(self):
        result = self.engine.process(s3(), NOW)
        self.assertEqual(result["decision"], "alert")
        self.assertEqual(result["alert"]["telemetry_delay_seconds"], 5)
        self.assertEqual(result["alert"]["owner"], "synthetic-soc")
        self.assertEqual(len(result["alert"]["raw_event_sha256"]), 64)

    def test_windows_read_match_case_insensitive_without_prefix_match(self):
        raw = windows()
        raw["object_name"] = raw["object_name"].upper()
        self.assertEqual(self.engine.process(raw, NOW)["decision"], "alert")
        raw = windows("102")
        raw["object_name"] += ".real"
        self.assertEqual(self.engine.process(raw, NOW)["decision"], "unmatched")

    def test_all_documented_windows_content_actions(self):
        for bit, action in (
            (1, "read"),
            (2, "write"),
            (4, "append"),
            (0x10000, "delete"),
        ):
            raw = windows(str(bit))
            raw["access_mask"] = hex(bit)
            self.assertEqual(normalize(raw)["actions"], [action])

    def test_scoped_exception_preserves_expected_access_evidence(self):
        raw = s3()
        raw["userIdentity"]["arn"] = registry()["decoys"][0]["exceptions"][0]["actor"]
        result = self.engine.process(raw, NOW)
        self.assertEqual(result["decision"], "expected_access")
        self.assertEqual(result["exception_owner"], "synthetic-backup-owner")
        raw["eventID"] = "synthetic-delete"
        raw["eventName"] = "DeleteObject"
        self.assertEqual(self.engine.process(raw, NOW)["decision"], "alert")

    def test_expired_exception_does_not_hide_delayed_event(self):
        raw = s3()
        raw["userIdentity"]["arn"] = registry()["decoys"][0]["exceptions"][0]["actor"]
        self.assertEqual(
            self.engine.process(raw, NOW + timedelta(days=2))["decision"], "alert"
        )

    def test_expired_decoy_still_alerts_and_flags_maintenance(self):
        result = self.engine.process(s3(), NOW + timedelta(days=40))
        self.assertEqual(result["decision"], "alert")
        self.assertTrue(result["alert"]["registry_expired"])

    def test_duplicate_survives_restart_and_collision_is_rejected(self):
        self.engine.process(s3(), NOW)
        self.engine.close()
        self.engine = Engine(Registry(registry()), self.path)
        self.assertEqual(self.engine.process(s3(), NOW)["decision"], "duplicate")
        raw = s3()
        raw["eventName"] = "DeleteObject"
        with self.assertRaises(ContractError):
            self.engine.process(raw, NOW)
        self.assertEqual(self.engine.report()["decisions"]["alert"], 1)

    def test_correlation_retains_both_individual_evidence_records(self):
        first = self.engine.process(s3(), NOW)["alert"]
        second = self.engine.process(
            s3("synthetic-s3-002"), NOW + timedelta(seconds=3)
        )["alert"]
        self.assertEqual(second["related_alert_id"], first["alert_id"])
        self.assertEqual(self.engine.report()["decisions"]["alert"], 2)

    def test_acknowledgment_records_latency_and_prevents_rewrite(self):
        alert = self.engine.process(s3(), NOW)["alert"]
        self.engine.acknowledge(
            alert["alert_id"], "synthetic-analyst", NOW + timedelta(seconds=30)
        )
        self.assertEqual(self.engine.report()["acknowledgment_seconds"], [30])
        with self.assertRaises(ContractError):
            self.engine.acknowledge(
                alert["alert_id"], "other", NOW + timedelta(seconds=40)
            )

    def test_future_event_and_early_ack_rejected(self):
        raw = s3()
        raw["eventTime"] = "2026-10-02T12:01:00Z"
        with self.assertRaises(ContractError):
            self.engine.process(raw, NOW)
        alert = self.engine.process(s3(), NOW)["alert"]
        with self.assertRaises(ContractError):
            self.engine.acknowledge(
                alert["alert_id"], "synthetic-analyst", NOW - timedelta(seconds=1)
            )

    def test_wrong_aws_partition_account_region_and_arn_never_match(self):
        for field, value in (
            ("awsRegion", "us-east-1"),
            ("eventCategory", "Management"),
            ("recipientAccountId", "bad"),
        ):
            raw = s3()
            raw[field] = value
            with self.assertRaises(ContractError):
                normalize(raw)
        raw = s3()
        raw["resources"][0]["ARN"] = (
            "arn:aws:s3:::synthetic-decoy-bucket/backups/inventory.txt"
        )
        with self.assertRaises(ContractError):
            normalize(raw)
        raw = s3()
        raw["recipientAccountId"] = "111111111111"
        self.assertEqual(self.engine.process(raw, NOW)["decision"], "unmatched")

    def test_wrong_windows_provider_host_and_metadata_only(self):
        for field, value in (
            ("provider", "fake"),
            ("event_id", 4656),
            ("access_mask", "0x80"),
            ("audit_outcome", "failure"),
            ("object_name", "C:relative"),
        ):
            raw = windows()
            raw[field] = value
            with self.assertRaises(ContractError):
                normalize(raw)
        raw = windows()
        raw["computer"] = "other-host"
        self.assertEqual(self.engine.process(raw, NOW)["decision"], "unmatched")

    def test_malformed_and_duplicate_registry_fail_closed(self):
        for field in ("owner", "response_procedure", "expires_at"):
            doc = registry()
            del doc["decoys"][0][field]
            with self.assertRaises(ContractError):
                Registry(doc)
        doc = registry()
        doc["decoys"].append(copy.deepcopy(doc["decoys"][0]))
        with self.assertRaises(ContractError):
            Registry(doc)

    def test_denied_s3_attempt_is_evidence_not_success(self):
        raw = s3()
        raw["errorCode"] = "AccessDenied"
        self.assertEqual(
            self.engine.process(raw, NOW)["alert"]["event"]["outcome"], "denied"
        )

    def test_json_duplicate_keys_and_nonfinite_rejected(self):
        for payload in ('{"x":1,"x":2}', '{"x":NaN}', '{"x":Infinity}'):
            with self.assertRaises(ContractError):
                parse_json(payload)

    def test_denied_expected_principal_is_never_suppressed(self):
        raw = s3()
        raw["userIdentity"]["arn"] = registry()["decoys"][0]["exceptions"][0]["actor"]
        raw["errorCode"] = "AccessDenied"
        self.assertEqual(self.engine.process(raw, NOW)["decision"], "alert")

    def test_malformed_json_field_types_raise_contract_error(self):
        for factory, fields in (
            (
                s3,
                (
                    "eventName",
                    "eventTime",
                    "resources",
                    "userIdentity",
                    "requestParameters",
                    "awsRegion",
                ),
            ),
            (windows, ("event_id", "access_mask", "object_name", "time", "record_id")),
        ):
            for field in fields:
                for value in (None, [], {}, True, 17):
                    raw = factory()
                    raw[field] = value
                    with (
                        self.subTest(field=field, value=value),
                        self.assertRaises(ContractError),
                    ):
                        normalize(raw)
        document = registry()
        document["decoys"][0]["source"] = []
        with self.assertRaises(ContractError):
            Registry(document)

    def test_windows_parent_traversal_rejected_for_both_separators(self):
        for value in (
            "C:\\Other\\..\\SyntheticDecoys\\config-export.txt",
            "C:\\Other/../SyntheticDecoys/config-export.txt",
        ):
            raw = windows()
            raw["object_name"] = value
            with self.assertRaises(ContractError):
                normalize(raw)


if __name__ == "__main__":
    unittest.main()
