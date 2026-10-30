"""Contract coverage for the 0.3.0 expansion: recon, versions, copy, 4656, Linux."""

import copy
import unittest

from fools_gold.collection import windows_event_xml
from fools_gold.core import ContractError, Engine, Registry, mitre_techniques, normalize
from tests.test_adapters import WINDOWS_XML
from tests.test_pilot import NOW, registry, s3, windows


def s3_variant(**changes):
    raw = s3("synthetic-variant-001")
    raw.update(changes)
    return raw


def list_event(prefix="backups/", category="Management"):
    return {
        "eventSource": "s3.amazonaws.com",
        "eventCategory": category,
        "eventName": "ListObjects",
        "eventID": "synthetic-list-001",
        "eventTime": "2026-10-02T11:59:55Z",
        "awsRegion": "us-gov-west-1",
        "recipientAccountId": "000000000000",
        "requestParameters": {
            "bucketName": "synthetic-decoy-bucket",
            "prefix": prefix,
        },
        "userIdentity": {
            "type": "AssumedRole",
            "arn": "arn:aws-us-gov:sts::000000000000:assumed-role/recon/session",
        },
        "sourceIPAddress": "192.0.2.11",
    }


def linux(record="501", **changes):
    raw = {
        "source": "linux.audit",
        "host": "synthetic-linux01",
        "sensor_epoch": "synthetic-boot-1",
        "record_id": record,
        "time": "2026-10-02T11:59:57Z",
        "uid": "1001",
        "path": "/opt/decoys/config-export.txt",
        "action": "read",
        "audit_outcome": "success",
        "process_name": "/usr/bin/cat",
    }
    raw.update(changes)
    return raw


class S3OperationTests(unittest.TestCase):
    def setUp(self):
        self.engine = Engine(Registry(registry()), ":memory:")

    def tearDown(self):
        self.engine.close()

    def test_head_object_is_recon(self):
        raw = s3_variant(eventName="HeadObject", eventID="synthetic-head-001")
        result = self.engine.process(raw, NOW)
        self.assertEqual(result["decision"], "alert")
        self.assertEqual(result["alert"]["event"]["actions"], ["recon"])
        self.assertIn("T1526", result["alert"]["mitre_techniques"])

    def test_get_object_version_is_a_read(self):
        raw = s3_variant(
            eventName="GetObjectVersion", eventID="synthetic-version-001"
        )
        self.assertEqual(
            self.engine.process(raw, NOW)["alert"]["event"]["actions"], ["read"]
        )

    def test_copy_object_alerts_on_destination_write(self):
        raw = s3_variant(eventName="CopyObject", eventID="synthetic-copy-001")
        self.assertEqual(
            self.engine.process(raw, NOW)["alert"]["event"]["actions"], ["write"]
        )

    def test_bucket_listing_matches_registered_prefix(self):
        raw = list_event(prefix="backups/")
        result = self.engine.process(raw, NOW)
        self.assertEqual(result["decision"], "alert")
        self.assertEqual(result["decoy_id"], "synthetic-s3-backup")
        self.assertEqual(result["alert"]["event"]["actions"], ["recon"])

    def test_listing_exception_cannot_suppress_another_covered_decoy(self):
        document = registry()
        second = copy.deepcopy(document["decoys"][0])
        second["id"] = "synthetic-s3-uncovered"
        second["locator"]["arn"] = (
            "arn:aws-us-gov:s3:::synthetic-decoy-bucket/backups/uncovered.txt"
        )
        second["exceptions"] = []
        document["decoys"][0]["expected_actions"].append("recon")
        document["decoys"][0]["exceptions"][0]["actions"].append("recon")
        document["decoys"].append(second)
        engine = Engine(Registry(document), ":memory:")
        try:
            raw = list_event(prefix="backups/")
            raw["userIdentity"]["arn"] = document["decoys"][0]["exceptions"][0][
                "actor"
            ]
            result = engine.process(raw, NOW)
            self.assertEqual(result["decision"], "alert")
            self.assertEqual(result["decoy_id"], "synthetic-s3-uncovered")
        finally:
            engine.close()

    def test_bucket_listing_is_accepted_as_data_or_management(self):
        for category in ("Data", "Management"):
            with self.subTest(category=category):
                event = normalize(list_event(category=category))
                self.assertEqual(event["actions"], ["recon"])
                self.assertTrue(event["prefix_match"])

    def test_bucket_listing_with_unrelated_prefix_is_unmatched(self):
        raw = list_event(prefix="other/")
        self.assertEqual(self.engine.process(raw, NOW)["decision"], "unmatched")

    def test_bucket_listing_rejects_unknown_category(self):
        with self.assertRaises(ContractError):
            normalize(list_event(category="Insight"))

    def test_versioned_read_carries_the_version_id(self):
        raw = s3_variant(
            eventName="GetObject",
            eventID="synthetic-versioned-001",
            requestParameters={
                "bucketName": "synthetic-decoy-bucket",
                "key": "backups/inventory.txt",
                "versionId": "synthetic-version-1",
            },
        )
        event = normalize(raw)
        self.assertEqual(event["actions"], ["read"])
        self.assertEqual(event["context"]["version_id"], "synthetic-version-1")
        self.assertNotIn("version_id", normalize(s3())["context"])

    def test_batch_delete_remains_unsupported(self):
        with self.assertRaises(ContractError):
            normalize(s3_variant(eventName="DeleteObjects"))


class WindowsDeniedTests(unittest.TestCase):
    def test_4656_failure_is_a_denied_alert(self):
        raw = windows()
        raw["event_id"] = 4656
        raw["audit_outcome"] = "failure"
        engine = Engine(Registry(registry()), ":memory:")
        try:
            result = engine.process(raw, NOW)
            self.assertEqual(result["decision"], "alert")
            self.assertEqual(result["alert"]["event"]["outcome"], "denied")
        finally:
            engine.close()

    def test_4656_with_success_outcome_is_rejected(self):
        raw = windows()
        raw["event_id"] = 4656
        with self.assertRaises(ContractError):
            normalize(raw)

    def test_4663_with_failure_outcome_is_rejected(self):
        raw = windows()
        raw["audit_outcome"] = "failure"
        with self.assertRaises(ContractError):
            normalize(raw)

    def test_xml_adapter_maps_denied_4656(self):
        denied = (
            WINDOWS_XML.replace(b"<EventID>4663</EventID>", b"<EventID>4656</EventID>")
            .replace(b"0x8020000000000000", b"0x8010000000000000")
            .replace(b"<EventRecordID>101</EventRecordID>", b"<EventRecordID>202</EventRecordID>")
        )
        mapped = windows_event_xml(denied, log_epoch="synthetic-installation-1")
        self.assertEqual(mapped["event_id"], 4656)
        self.assertEqual(mapped["audit_outcome"], "failure")
        self.assertEqual(normalize(mapped)["outcome"], "denied")

    def test_xml_adapter_rejects_4656_with_success_keywords(self):
        wrong = WINDOWS_XML.replace(
            b"<EventID>4663</EventID>", b"<EventID>4656</EventID>"
        )
        with self.assertRaises(ContractError):
            windows_event_xml(wrong, log_epoch="synthetic-installation-1")


class LinuxAuditTests(unittest.TestCase):
    def setUp(self):
        self.engine = Engine(Registry(registry()), ":memory:")

    def tearDown(self):
        self.engine.close()

    def test_read_alerts_with_route_and_mitre(self):
        result = self.engine.process(linux(), NOW)
        self.assertEqual(result["decision"], "alert")
        self.assertEqual(result["decoy_id"], "synthetic-linux-config")
        self.assertEqual(result["alert"]["route"], "soc-primary")
        self.assertEqual(result["alert"]["mitre_techniques"], ["T1005"])
        self.assertEqual(result["alert"]["event"]["actor"], "uid:1001")

    def test_paths_stay_case_sensitive(self):
        raw = linux()
        raw["path"] = "/opt/Decoys/config-export.txt"
        self.assertEqual(self.engine.process(raw, NOW)["decision"], "unmatched")

    def test_denied_outcome_is_evidence(self):
        raw = linux(audit_outcome="denied")
        self.assertEqual(
            self.engine.process(raw, NOW)["alert"]["event"]["outcome"], "denied"
        )

    def test_invalid_paths_and_actions_rejected(self):
        for change in (
            {"path": "relative/path"},
            {"path": "/opt/../etc/shadow"},
            {"action": "execute"},
            {"audit_outcome": "maybe"},
            {"record_id": "abc"},
            {"sensor_epoch": ""},
        ):
            raw = linux(**change)
            with self.subTest(change=change), self.assertRaises(ContractError):
                normalize(raw)

    def test_replay_identity_is_stable_and_scoped(self):
        first = self.engine.process(linux(), NOW)
        self.assertEqual(first["decision"], "alert")
        self.assertEqual(self.engine.process(linux(), NOW)["decision"], "duplicate")
        other_host = linux("502", host="synthetic-linux02")
        self.assertEqual(
            self.engine.process(other_host, NOW)["decision"], "unmatched"
        )


class RegistryV2Tests(unittest.TestCase):
    def test_linux_decoy_source_and_route_are_accepted(self):
        snapshot = Registry(registry())
        linux_decoy = next(
            d for d in snapshot.decoys if d["source"] == "linux.audit"
        )
        self.assertEqual(linux_decoy["route"], "soc-primary")
        self.assertIn("recon", linux_decoy["expected_actions"])

    def test_linux_locator_requires_absolute_path(self):
        document = registry()
        document["decoys"][2]["locator"]["path"] = "relative"
        with self.assertRaises(ContractError):
            Registry(document)

    def test_recon_action_set_is_documented(self):
        document = registry()
        document["decoys"][1]["expected_actions"] = ["recon"]
        Registry(document)

    def test_undocumented_action_set_rejected(self):
        document = registry()
        document["decoys"][0]["expected_actions"] = ["execute"]
        with self.assertRaises(ContractError):
            Registry(document)

    def test_duplicate_route_is_allowed_but_invalid_route_rejected(self):
        document = registry()
        document["decoys"][0]["route"] = ""
        with self.assertRaises(ContractError):
            Registry(document)
        document = registry()
        document["decoys"][0]["route"] = "x" * 65
        with self.assertRaises(ContractError):
            Registry(document)


class MitreMappingTests(unittest.TestCase):
    def test_source_and_recon_mapping(self):
        read = normalize(s3())
        self.assertEqual(mitre_techniques(read), ["T1530"])
        head = normalize(s3_variant(eventName="HeadObject", eventID="h-1"))
        self.assertEqual(mitre_techniques(head), ["T1526", "T1530"])
        self.assertEqual(mitre_techniques(normalize(windows())), ["T1005"])

    def test_normalized_event_shapes_are_unchanged_for_existing_sources(self):
        read = normalize(s3())
        self.assertNotIn("prefix_match", read)
        self.assertEqual(read["actions"], ["read"])
        denied = copy.deepcopy(s3())
        denied["errorCode"] = "AccessDenied"
        self.assertEqual(normalize(denied)["outcome"], "denied")


if __name__ == "__main__":
    unittest.main()
