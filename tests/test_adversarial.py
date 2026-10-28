"""Adversarial edge cases for the 0.2.0 subsystems."""

import gzip
import json
import tempfile
import unittest
from pathlib import Path

from fools_gold.core import ContractError, Engine, Registry, parse_json
from fools_gold.trail_inbox import MAX_INBOX_RECORDS, cloudtrail_records_file
from fools_gold.transport import deliver
from tests.test_pilot import NOW, registry, s3


class ParseJsonBoundTests(unittest.TestCase):
    def test_node_limit_is_parameterized_and_bounded(self):
        for payload, limit in (("[]", 1), ("[0]", 2)):
            self.assertEqual(type(parse_json(payload, max_nodes=limit)), list)
        with self.assertRaises(ContractError):
            parse_json("[0,1]", max_nodes=1)
        with self.assertRaises(ContractError):
            parse_json("[]", max_nodes=0)
        with self.assertRaises(ContractError):
            parse_json("[]", max_nodes=10000001)

    def test_default_limit_still_applies(self):
        with self.assertRaises(ContractError):
            parse_json("[" + ",".join("0" for _ in range(100001)) + "]")

    def test_many_record_inbox_file_is_processable(self):
        records = []
        for index in range(3000):
            event = s3(f"synthetic-many-{index}")
            records.append(event)
        payload = json.dumps({"Records": records}).encode()
        result = cloudtrail_records_file(payload)
        self.assertEqual(len(result), 3000)


class TrailInboxDoSTests(unittest.TestCase):
    def test_gzip_bomb_larger_than_cap_is_rejected_not_decoded(self):
        # 200 MiB of zeros compresses below 16 MiB; the decompression cap must
        # reject it without materializing the full output.
        bomb = gzip.compress(b"\x00" * (200 * 1024 * 1024))
        self.assertLess(len(bomb), 1024 * 1024)
        with self.assertRaises(ContractError):
            cloudtrail_records_file(bomb)

    def test_record_count_bound_matches_documented_contract(self):
        records = [s3(f"synthetic-bound-{index}") for index in range(MAX_INBOX_RECORDS + 1)]
        payload = json.dumps({"Records": records}).encode()
        with self.assertRaises(ContractError):
            cloudtrail_records_file(payload)


class TransportEdgeTests(unittest.TestCase):
    def test_alert_removed_after_enqueue_does_not_break_delivery(self):
        engine = Engine(Registry(registry()), ":memory:")
        try:
            engine.process(s3(), NOW)
            engine.outbox_enqueue("wazuh", NOW)
            engine.db.execute("DELETE FROM alerts")
            engine.db.commit()
            with tempfile.TemporaryDirectory() as folder:
                summary = deliver(
                    engine, "wazuh", NOW, wazuh_output=str(Path(folder) / "out.log")
                )
            self.assertTrue(summary["complete"])
            self.assertEqual(summary["sent"], 0)
        finally:
            engine.close()

    def test_limit_of_one_delivers_all_alerts_across_batches(self):
        engine = Engine(Registry(registry()), ":memory:")
        try:
            for index in range(3):
                engine.process(s3(f"synthetic-batch-{index}"), NOW)
            with tempfile.TemporaryDirectory() as folder:
                sink = Path(folder) / "out.log"
                summary = deliver(
                    engine, "wazuh", NOW, wazuh_output=str(sink), limit=1
                )
                self.assertTrue(summary["complete"])
                self.assertEqual(summary["sent"], 3)
                self.assertEqual(
                    len(sink.read_text(encoding="utf-8").splitlines()), 3
                )
        finally:
            engine.close()

    def test_verify_survives_empty_database(self):
        engine = Engine(
            Registry(registry()), ":memory:", mac_key=b"k" * 32
        )
        try:
            outcome = engine.verify_integrity()
            self.assertEqual(outcome["alerts"], 0)
            self.assertTrue(outcome["ok"])
        finally:
            engine.close()


class RegistryFingerprintStabilityTests(unittest.TestCase):
    def test_legacy_row_without_mac_is_reported_not_crashed(self):
        engine = Engine(Registry(registry()), ":memory:", mac_key=b"k" * 32)
        try:
            engine.process(s3(), NOW)
            engine.db.execute("UPDATE alerts SET evidence_mac=NULL")
            engine.db.commit()
            outcome = engine.verify_integrity()
            self.assertFalse(outcome["ok"])
        finally:
            engine.close()


class ConcurrencySmokeTests(unittest.TestCase):
    def test_shared_database_across_engines_survives_reopen(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "shared.sqlite"
            first = Engine(Registry(registry()), path, mac_key=b"k" * 32)
            try:
                first.process(s3(), NOW)
            finally:
                first.close()
            second = Engine(Registry(registry()), path, mac_key=b"k" * 32)
            try:
                result = second.process(s3(), NOW)
                self.assertEqual(result["decision"], "duplicate")
                self.assertTrue(second.verify_integrity()["ok"])
            finally:
                second.close()


class OutboxForeignKeyTests(unittest.TestCase):
    def test_outbox_is_not_orphaned_by_deletion_mid_delivery(self):
        engine = Engine(Registry(registry()), ":memory:")
        try:
            engine.process(s3(), NOW)
            engine.outbox_enqueue("wazuh", NOW)
            batch = engine.outbox_batch("wazuh", 10)
            self.assertEqual(len(batch), 1)
            # Deleting the alert makes the batch skip the orphaned row.
            engine.db.execute("DELETE FROM alerts WHERE rowid=1")
            engine.db.commit()
            self.assertEqual(engine.outbox_batch("wazuh", 10), [])
        finally:
            engine.close()


class CliTrailInboxStreamTests(unittest.TestCase):
    def test_oversized_inbox_file_is_rejected_without_full_read(self):
        from fools_gold.cli import run_trail_inbox
        from fools_gold.trail_inbox import MAX_INBOX_BYTES

        engine = Engine(Registry(registry()), ":memory:")
        try:
            with tempfile.TemporaryDirectory() as folder:
                inbox = Path(folder)
                big = inbox / "big.json"
                big.write_bytes(b"[" + b"0," * (MAX_INBOX_BYTES // 2) + b"0]")
                self.assertGreater(big.stat().st_size, MAX_INBOX_BYTES)
                code = run_trail_inbox(engine, str(inbox))
                self.assertEqual(code, 2)
        finally:
            engine.close()


if __name__ == "__main__":
    unittest.main()
