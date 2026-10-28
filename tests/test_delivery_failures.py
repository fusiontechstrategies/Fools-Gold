"""Wazuh delivery failures must be recorded durably, not raised past the outbox."""

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fools_gold.core import Engine, Registry
from fools_gold.transport import deliver
from tests.test_pilot import NOW, registry, s3


REAL_WRITE = os.write


def engine_in(folder):
    engine = Engine(Registry(registry()), Path(folder) / "db.sqlite")
    engine.process(s3(), NOW)
    return engine


def failed_state(engine):
    return engine.db.execute(
        "SELECT state, attempts FROM outbox WHERE payload_format='wazuh'"
    ).fetchall()


class WazuhFailureTests(unittest.TestCase):
    def test_disk_full_is_recorded_after_bounded_attempts(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = engine_in(folder)
            try:
                sink = Path(folder) / "wazuh.log"
                with patch("fools_gold.transport.os.write", side_effect=OSError(28, "No space left on device")), patch(
                    "fools_gold.transport.SEND_INTERVAL_SECONDS", 0
                ), patch("fools_gold.transport.BACKOFF_SECONDS", (0.0, 0.0)):
                    summary = deliver(engine, "wazuh", NOW, wazuh_output=str(sink))
                self.assertFalse(summary["complete"])
                self.assertIn("write failed", summary["error"])
                rows = failed_state(engine)
                self.assertEqual(rows, [("failed", 3)])
            finally:
                engine.close()

    def test_permission_denied_on_open_is_recorded(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = engine_in(folder)
            try:
                sink = Path(folder) / "wazuh.log"
                with patch(
                    "fools_gold.transport.os.open",
                    side_effect=PermissionError(13, "denied"),
                ), patch("fools_gold.transport.SEND_INTERVAL_SECONDS", 0), patch(
                    "fools_gold.transport.BACKOFF_SECONDS", (0.0, 0.0)
                ):
                    summary = deliver(engine, "wazuh", NOW, wazuh_output=str(sink))
                self.assertFalse(summary["complete"])
                self.assertIn("could not be opened", summary["error"])
                self.assertEqual(failed_state(engine), [("failed", 3)])
            finally:
                engine.close()

    def test_fsync_failure_is_recorded(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = engine_in(folder)
            try:
                sink = Path(folder) / "wazuh.log"
                with patch(
                    "fools_gold.transport.os.fsync",
                    side_effect=OSError(5, "I/O error"),
                ), patch("fools_gold.transport.SEND_INTERVAL_SECONDS", 0), patch(
                    "fools_gold.transport.BACKOFF_SECONDS", (0.0, 0.0)
                ):
                    summary = deliver(engine, "wazuh", NOW, wazuh_output=str(sink))
                self.assertFalse(summary["complete"])
                self.assertIn("fsync failed", summary["error"])
                self.assertEqual(failed_state(engine), [("failed", 3)])
            finally:
                engine.close()

    def test_short_writes_are_completed(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = engine_in(folder)
            try:
                sink = Path(folder) / "wazuh.log"

                def one_byte(fd, data):
                    return REAL_WRITE(fd, data[:1])

                with patch(
                    "fools_gold.transport.os.write", side_effect=one_byte
                ), patch("fools_gold.transport.SEND_INTERVAL_SECONDS", 0):
                    summary = deliver(engine, "wazuh", NOW, wazuh_output=str(sink))
                self.assertTrue(summary["complete"])
                content = sink.read_text(encoding="utf-8")
                self.assertEqual(len(content.splitlines()), 1)
                self.assertEqual(json.loads(content)["fg_alert_id"], engine.export_alerts().__next__()["alert_id"])
                self.assertEqual(failed_state(engine), [("sent", 1)])
            finally:
                engine.close()

    def test_zero_progress_write_fails_closed(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = engine_in(folder)
            try:
                sink = Path(folder) / "wazuh.log"
                with patch("fools_gold.transport.os.write", return_value=0), patch(
                    "fools_gold.transport.SEND_INTERVAL_SECONDS", 0
                ), patch("fools_gold.transport.BACKOFF_SECONDS", (0.0, 0.0)):
                    summary = deliver(engine, "wazuh", NOW, wazuh_output=str(sink))
                self.assertFalse(summary["complete"])
                self.assertIn("no write progress", summary["error"])
            finally:
                engine.close()

    def test_failed_packet_is_retried_only_on_request(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = engine_in(folder)
            try:
                sink = Path(folder) / "wazuh.log"
                with patch("fools_gold.transport.os.write", side_effect=OSError(28, "full")), patch(
                    "fools_gold.transport.SEND_INTERVAL_SECONDS", 0
                ), patch("fools_gold.transport.BACKOFF_SECONDS", (0.0, 0.0)):
                    deliver(engine, "wazuh", NOW, wazuh_output=str(sink))
                with patch("fools_gold.transport.SEND_INTERVAL_SECONDS", 0):
                    summary = deliver(engine, "wazuh", NOW, wazuh_output=str(sink))
                self.assertEqual(summary["sent"], 0)
                with patch("fools_gold.transport.SEND_INTERVAL_SECONDS", 0):
                    summary = deliver(
                        engine, "wazuh", NOW, wazuh_output=str(sink),
                        retry_failed=True,
                    )
                self.assertTrue(summary["complete"])
                self.assertEqual(summary["sent"], 1)
                self.assertEqual(len(sink.read_text(encoding="utf-8").splitlines()), 1)
            finally:
                engine.close()


if __name__ == "__main__":
    unittest.main()
