"""Windows collection: output alignment, mixed records, cursors and rollover."""

import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fools_gold.cli import run_windows_collector
from fools_gold.collection import (
    windows_events_batch,
    windows_events_xml_envelope,
)
from fools_gold.core import ContractError, Registry
from fools_gold.winlog import (
    decode_query_output,
    load_state,
    query_security_log,
    save_state,
)
from tests.test_adapters import WINDOWS_XML
from tests.test_pilot import registry

PATH = "C:\\SyntheticDecoys\\config-export.txt"


def win_event(record_id, event_id=4663, keywords="0x8020000000000000", path=PATH):
    xml = WINDOWS_XML
    xml = xml.replace(b"<EventID>4663</EventID>", f"<EventID>{event_id}</EventID>".encode())
    xml = xml.replace(b"0x8020000000000000", keywords.encode())
    xml = xml.replace(
        b"<EventRecordID>101</EventRecordID>",
        f"<EventRecordID>{record_id}</EventRecordID>".encode(),
    )
    return xml.replace(PATH.encode(), path.encode())


def make_fetch(records):
    """Simulate wevtutil paging: concatenated Event roots, no wrapper."""

    def fetch(*, max_events, since_record_id, newest_first=False):
        if newest_first:
            batch = records[-max_events:]
        elif since_record_id is None:
            batch = records[:max_events]
        else:
            batch = [item for item in records if item[0] > since_record_id][
                :max_events
            ]
        return b"".join(xml for _identifier, xml in batch)

    return fetch


class OutputNormalizationTests(unittest.TestCase):
    def test_empty_output_maps_to_zero_events(self):
        mapped, skipped, observed, total = windows_events_batch(
            b"", log_epoch="collector-epoch"
        )
        self.assertEqual((mapped, skipped, observed, total), ([], 0, [], 0))

    def test_single_and_concatenated_roots_are_accepted(self):
        payload = win_event(11) + win_event(12)
        mapped, skipped, observed, total = windows_events_batch(
            payload, log_epoch="collector-epoch"
        )
        self.assertEqual((len(mapped), skipped, observed, total), (2, 0, [11, 12], 2))

    def test_bare_events_wrapper_without_namespace_is_accepted(self):
        payload = b"<Events>" + win_event(13) + b"</Events>"
        mapped, _, observed, _ = windows_events_batch(
            payload, log_epoch="collector-epoch"
        )
        self.assertEqual((len(mapped), observed), (1, [13]))

    def test_xml_declarations_between_roots_are_stripped(self):
        payload = (
            b'<?xml version="1.0" encoding="utf-8"?>' + win_event(21)
            + b'<?xml version="1.0" encoding="utf-8"?>' + win_event(22)
        )
        mapped, _, observed, _ = windows_events_batch(
            payload, log_epoch="collector-epoch"
        )
        self.assertEqual((len(mapped), observed), (2, [21, 22]))

    def test_query_output_decoding_handles_utf8_and_utf16(self):
        xml = win_event(31)
        self.assertEqual(decode_query_output(xml), xml)
        utf16 = xml.decode("utf-8").encode("utf-16")
        self.assertEqual(decode_query_output(utf16), xml)


class MixedRecordTests(unittest.TestCase):
    def test_unsupported_events_are_skipped_not_fatal(self):
        payload = b"".join(
            [
                win_event(1),
                win_event(2, event_id=4656, keywords="0x8020000000000000"),
                win_event(3, keywords="0x8010000000000000"),
                win_event(4, event_id=4656, keywords="0x8010000000000000"),
            ]
        )
        mapped, skipped, observed, total = windows_events_batch(
            payload, log_epoch="collector-epoch"
        )
        self.assertEqual((len(mapped), skipped, total), (2, 2, 4))
        self.assertEqual(observed, [1, 2, 3, 4])
        outcomes = sorted(item["audit_outcome"] for item in mapped)
        self.assertEqual(outcomes, ["failure", "success"])

    def test_strict_envelope_still_rejects_unsupported_events(self):
        payload = win_event(1) + win_event(
            2, event_id=4656, keywords="0x8020000000000000"
        )
        with self.assertRaises(ContractError):
            windows_events_xml_envelope(payload, log_epoch="collector-epoch")

    def test_malformed_envelopes_fail_closed(self):
        scenarios = (
            b"<Events><Stray/></Events>",
            b"<!DOCTYPE Events [<!ENTITY x 'y'>]><Events/>",
            b"<Events>" + b"".join(win_event(i) for i in range(1, 130)) + b"</Events>",
            b"not xml at all",
        )
        for payload in scenarios:
            with self.subTest(payload=payload[:32]), self.assertRaises(ContractError):
                windows_events_batch(payload, log_epoch="collector-epoch")


class CollectorCursorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.folder = Path(self.temp.name)
        self.registry = Registry(registry())
        self.state = self.folder / "collector-state.json"

    def tearDown(self):
        self.temp.cleanup()

    def run_collector(self, records, *, follow=False, pages=10):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = run_windows_collector(
                self.registry,
                log_epoch="synthetic-installation-1",
                follow=follow,
                interval_seconds=1,
                max_events=128,
                state_file=self.state,
                pages_per_cycle=pages,
                fetch=make_fetch(records),
            )
        return code, out.getvalue(), err.getvalue()

    def test_burst_larger_than_a_batch_is_paged_and_cursored(self):
        records = [(index, win_event(index)) for index in range(1, 301)]
        code, output, error = self.run_collector(records)
        self.assertEqual(code, 0)
        self.assertEqual(len(output.splitlines()), 300)
        self.assertEqual(load_state(self.state)["last_record_id"], 300)
        self.assertNotIn("coverage gap", error)

    def test_restart_resumes_from_the_durable_cursor(self):
        records = [(index, win_event(index)) for index in range(1, 6)]
        self.run_collector(records)
        records += [(index, win_event(index)) for index in range(6, 11)]
        code, output, _ = self.run_collector(records)
        self.assertEqual(code, 0)
        emitted = output.splitlines()
        self.assertEqual(len(emitted), 5)
        self.assertIn('"record_id":"10"', emitted[-1])
        self.assertEqual(load_state(self.state)["last_record_id"], 10)

    def test_idle_polls_do_not_report_rollover_or_replay(self):
        records = [(index, win_event(index)) for index in range(1, 4)]
        save_state(
            self.state,
            {
                "log_epoch": "synthetic-installation-1",
                "last_record_id": 3,
                "generation": 0,
            },
        )
        for _ in range(3):
            code, output, error = self.run_collector(records)
            self.assertEqual(code, 0)
            self.assertEqual(output, "")
            self.assertNotIn("coverage gap", error)
            state = load_state(self.state)
            self.assertEqual(state["last_record_id"], 3)
            self.assertEqual(state["generation"], 0)

    def test_clear_bumps_generation_and_prevents_evidence_collisions(self):
        from fools_gold.core import Engine
        from tests.test_pilot import NOW

        engine = Engine(
            Registry(registry()), self.folder / "evidence.sqlite"
        )
        try:
            before = [(index, win_event(index)) for index in range(1, 4)]
            _, output, _ = self.run_collector(before)
            for line in output.splitlines():
                engine.process(json.loads(line), NOW)
            self.assertEqual(engine.report()["decisions"]["alert"], 3)
            save_state(
                self.state,
                {
                    "log_epoch": "synthetic-installation-1",
                    "last_record_id": 300,
                    "generation": 0,
                },
            )
            after = [
                (
                    index,
                    win_event(index).replace(
                        b'<Data Name="AccessMask">0x1</Data>',
                        b'<Data Name="AccessMask">0x3</Data>',
                    ),
                )
                for index in range(1, 4)
            ]
            code, output, error = self.run_collector(after)
            self.assertEqual(code, 0)
            self.assertIn("coverage gap", error)
            self.assertEqual(len(output.splitlines()), 3)
            for line in output.splitlines():
                engine.process(json.loads(line), NOW)
            self.assertIn(
                '"log_epoch":"synthetic-installation-1#g1"',
                output.splitlines()[0],
            )
            self.assertEqual(engine.report()["decisions"]["alert"], 6)
            state = load_state(self.state)
            self.assertEqual(state["generation"], 1)
            self.assertEqual(state["last_record_id"], 3)
        finally:
            engine.close()

    def test_legacy_state_without_generation_still_loads(self):
        self.state.write_text(
            json.dumps(
                {
                    "log_epoch": "synthetic-installation-1",
                    "last_record_id": 7,
                    "updated_at": "2026-10-02T12:00:00Z",
                }
            ),
            encoding="utf-8",
        )
        state = load_state(self.state)
        self.assertEqual(state["generation"], 0)
        self.assertEqual(state["last_record_id"], 7)

    def test_rollover_reports_a_coverage_gap_and_recovers(self):
        records = [(index, win_event(index)) for index in range(1, 4)]
        self.run_collector(records)
        save_state(self.state, {"log_epoch": "synthetic-installation-1", "last_record_id": 300})
        cleared = [(index, win_event(index)) for index in range(1, 4)]
        code, output, error = self.run_collector(cleared)
        self.assertEqual(code, 0)
        self.assertIn("coverage gap", error)
        self.assertEqual(len(output.splitlines()), 3)
        self.assertEqual(load_state(self.state)["last_record_id"], 3)

    def test_log_epoch_change_restarts_the_cursor(self):
        self.run_collector([(1, win_event(1))])
        state = load_state(self.state)
        state["log_epoch"] = "previous-installation"
        save_state(self.state, state)
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            run_windows_collector(
                self.registry,
                log_epoch="synthetic-installation-1",
                follow=False,
                interval_seconds=1,
                max_events=128,
                state_file=self.state,
                fetch=make_fetch([(1, win_event(1))]),
            )
        self.assertIn("log epoch changed", err.getvalue())

    def test_empty_output_is_clean(self):
        code, output, error = self.run_collector([])
        self.assertEqual(code, 0)
        self.assertEqual(output, "")
        self.assertEqual(error, "")

    def test_corrupt_state_is_rejected(self):
        self.state.write_text("not json", encoding="utf-8")
        with self.assertRaises(ContractError):
            load_state(self.state)

    def test_state_round_trip_and_bounds(self):
        save_state(self.state, {"log_epoch": "ep", "last_record_id": 7})
        self.assertEqual(load_state(self.state)["last_record_id"], 7)
        self.state.write_bytes(b"x" * 5000)
        with self.assertRaises(ContractError):
            load_state(self.state)


class QueryConstructionTests(unittest.TestCase):
    @unittest.skipIf(os.name != "nt", "subprocess capture assertion is Windows-only")
    def test_query_uses_cursor_and_oldest_first_paging(self):
        completed = type(
            "Completed", (), {"returncode": 0, "stdout": win_event(9), "stderr": b""}
        )()
        with patch("fools_gold.winlog.subprocess.run", return_value=completed) as run:
            query_security_log(since_record_id=5, max_events=10)
        args = run.call_args.args[0]
        self.assertIn(
            "/q:*[System[(EventID=4663 or EventID=4656) and EventRecordID > 5]]",
            args,
        )
        self.assertIn("/rd:false", args)
        self.assertIn("/c:10", args)
        with patch("fools_gold.winlog.subprocess.run", return_value=completed) as run:
            query_security_log(max_events=10)
        args = run.call_args.args[0]
        self.assertIn("/rd:false", args)
        with patch("fools_gold.winlog.subprocess.run", return_value=completed) as run:
            query_security_log(max_events=10, newest_first=True)
        args = run.call_args.args[0]
        self.assertIn("/rd:true", args)

    def test_query_bounds(self):
        for kwargs in (
            {"max_events": 0},
            {"max_events": 129},
            {"timeout": 0},
            {"since_record_id": -1},
            {"since_record_id": "5"},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(ContractError):
                query_security_log(**kwargs)


if __name__ == "__main__":
    unittest.main()
