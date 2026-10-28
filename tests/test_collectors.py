import gzip
import json
import tempfile
import unittest
from pathlib import Path

from fools_gold.collection import windows_events_xml_envelope
from fools_gold.core import ContractError, Engine, Registry
from fools_gold.trail_inbox import cloudtrail_records_file
from fools_gold.winlog import collect
from tests.test_adapters import WINDOWS_XML
from tests.test_pilot import NOW, registry, s3, windows

ENVELOPE_OPEN = b'<Events xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'


def envelope(*events: bytes) -> bytes:
    return ENVELOPE_OPEN + b"".join(events) + b"</Events>"


UNMATCHED_XML = WINDOWS_XML.replace(
    b"C:\\SyntheticDecoys\\config-export.txt", b"C:\\Other\\plain.txt"
).replace(b"<EventRecordID>101</EventRecordID>", b"<EventRecordID>102</EventRecordID>")


class WindowsEnvelopeTests(unittest.TestCase):
    def test_envelope_maps_each_event_to_the_existing_contract(self):
        mapped = windows_events_xml_envelope(
            envelope(WINDOWS_XML, UNMATCHED_XML), log_epoch="collector-epoch"
        )
        self.assertEqual(len(mapped), 2)
        self.assertTrue(all(item["log_epoch"] == "collector-epoch" for item in mapped))
        self.assertEqual(mapped[0]["object_name"], "C:\\SyntheticDecoys\\config-export.txt")

    def test_envelope_rejects_bounds_structure_and_encoding(self):
        many = envelope(*([WINDOWS_XML] * 129))
        for payload in (
            many,
            envelope().replace(b"</Events>", b"<Stray/></Events>"),
            envelope(WINDOWS_XML).replace(b"Events>", b"WrongEvents>"),
            b"<!DOCTYPE Events [<!ENTITY x 'y'>]>" + envelope(WINDOWS_XML),
            envelope(WINDOWS_XML).decode().encode("utf-16"),
            b"x" * (1024 * 1024 + 1),
        ):
            with self.subTest(payload=payload[:32]), self.assertRaises(ContractError):
                windows_events_xml_envelope(payload, log_epoch="collector-epoch")

    def test_collect_emits_only_registered_decoy_locations(self):
        events, report = collect(
            Registry(registry()),
            log_epoch="collector-epoch",
            fetch=lambda **_kwargs: envelope(WINDOWS_XML, UNMATCHED_XML),
        )
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["object_name"], "C:\\SyntheticDecoys\\config-export.txt")
        self.assertEqual(report["skipped"], 0)

    def test_collect_skips_contract_failures_with_a_visible_count(self):
        broken = WINDOWS_XML.replace(
            b'<Data Name="AccessMask">0x1</Data>', b'<Data Name="AccessMask">0x80</Data>'
        )
        events, report = collect(
            Registry(registry()),
            log_epoch="collector-epoch",
            fetch=lambda **_kwargs: envelope(broken),
        )
        self.assertEqual(events, [])
        self.assertEqual(report["skipped"], 1)

    def test_query_requires_windows(self):
        import fools_gold.winlog as winlog

        if winlog.os.name == "nt":
            self.skipTest("subprocess query assertion is POSIX-only")
        with self.assertRaises(ContractError):
            winlog.query_security_log()


class TrailInboxTests(unittest.TestCase):
    def test_gzip_and_plain_envelopes_yield_validated_records(self):
        plain = json.dumps({"Records": [s3()]}).encode()
        zipped = gzip.compress(plain)
        for payload in (plain, zipped):
            self.assertEqual(cloudtrail_records_file(payload), [s3()])

    def test_invalid_batches_fail_without_partial_acceptance(self):
        for payload in (
            json.dumps({"Records": []}).encode(),
            json.dumps({"Records": [s3(), {}]}).encode(),
            json.dumps({"Records": [windows()]}).encode(),
            json.dumps({"Records": [s3()], "extra": True}).encode(),
            b"[]",
            gzip.compress(b"[]"),
        ):
            with self.subTest(payload=payload[:24]), self.assertRaises(ContractError):
                cloudtrail_records_file(payload)

    def test_decompression_is_bounded_against_gzip_bombs(self):
        bomb = gzip.compress(b'{"Records":[' + b"0," * (24 * 1024 * 1024) + b"0]}")
        self.assertLess(len(bomb), 1024 * 1024)
        with self.assertRaises(ContractError):
            cloudtrail_records_file(bomb)

    def test_oversized_single_record_is_rejected(self):
        huge = s3("synthetic-huge")
        huge["resources"] = [
            {"type": "AWS::S3::Object", "ARN": "arn:aws-us-gov:s3:::b/" + "k" * 70000}
        ]
        with self.assertRaises(ContractError):
            cloudtrail_records_file(json.dumps({"Records": [huge]}).encode())


class TrailFileStateTests(unittest.TestCase):
    def test_marks_are_idempotent_and_digest_bound(self):
        engine = Engine(Registry(registry()), ":memory:")
        try:
            digest = "a" * 64
            engine.mark_trail_file(digest, NOW)
            engine.mark_trail_file(digest, NOW)
            self.assertTrue(engine.trail_file_processed(digest))
            self.assertFalse(engine.trail_file_processed("b" * 64))
            with self.assertRaises(ContractError):
                engine.mark_trail_file("short", NOW)
        finally:
            engine.close()

    def test_directory_processing_is_idempotent(self):
        with tempfile.TemporaryDirectory() as folder:
            inbox = Path(folder)
            (inbox / "trail.json").write_text(
                json.dumps({"Records": [s3()]}), encoding="utf-8"
            )
            engine = Engine(Registry(registry()), inbox / "evidence.sqlite")
            try:
                from fools_gold.cli import run_trail_inbox

                first = run_trail_inbox(engine, str(inbox))
                self.assertEqual(first, 0)
                self.assertEqual(
                    engine.report()["decisions"]["alert"], 1
                )
                second = run_trail_inbox(engine, str(inbox))
                self.assertEqual(second, 0)
                self.assertEqual(engine.report()["decisions"]["alert"], 1)
            finally:
                engine.close()


if __name__ == "__main__":
    unittest.main()
