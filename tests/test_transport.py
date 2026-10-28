import http.client
import json
import os
import tempfile
import threading
import unittest
from datetime import timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest.mock import patch

from fools_gold.core import ContractError, Engine, Registry
from fools_gold.transport import TOKEN_VARIABLE, deliver, hec_token, post_hec
from tests.test_pilot import NOW, registry, s3


class FakeResponse:
    def __init__(self, status, body):
        self.status = status
        self._body = body

    def read(self, limit):
        return self._body[:limit]


class FakeConnection:
    responses = []
    requests = []

    def __init__(self, *_args, **_kwargs):
        FakeConnection.requests = []

    def request(self, method, path, body, headers):
        FakeConnection.requests.append((method, path, headers))

    def getresponse(self):
        status, body = self.responses[0]
        return FakeResponse(status, body)

    def close(self):
        pass


def _secs(seconds):
    return timedelta(seconds=seconds)


class OutboxTests(unittest.TestCase):
    def setUp(self):
        self.engine = Engine(Registry(registry()), ":memory:")
        self.engine.process(s3(), NOW)
        self.engine.process(s3("synthetic-s3-002"), NOW + _secs(3))

    def tearDown(self):
        self.engine.close()

    def test_enqueue_is_idempotent_and_batches_are_ordered(self):
        self.assertEqual(self.engine.outbox_enqueue("wazuh", NOW), 2)
        self.assertEqual(self.engine.outbox_enqueue("wazuh", NOW), 0)
        batch = self.engine.outbox_batch("wazuh", 10)
        self.assertEqual(len(batch), 2)
        self.assertTrue(all("alert_id" in alert for _, alert in batch))
        self.assertEqual(self.engine.outbox_batch("wazuh", 1)[0][1], batch[0][1])
        with self.assertRaises(ContractError):
            self.engine.outbox_batch("wazuh", 0)

    def test_mark_records_state_and_rejects_unknown_state(self):
        self.engine.outbox_enqueue("splunk", NOW)
        alert_id = self.engine.outbox_batch("splunk", 10)[0][0]
        self.engine.outbox_mark("splunk", alert_id, "sent", NOW)
        with self.assertRaises(ContractError):
            self.engine.outbox_mark("splunk", alert_id, "bogus", NOW)

    def test_reset_failed_returns_to_pending(self):
        self.engine.outbox_enqueue("wazuh", NOW)
        batch = self.engine.outbox_batch("wazuh", 10)
        first_id, second_id = batch[0][0], batch[1][0]
        self.engine.outbox_mark("wazuh", first_id, "failed", NOW, error="down")
        remaining = self.engine.outbox_batch("wazuh", 10)
        self.assertEqual([alert_id for alert_id, _ in remaining], [second_id])
        self.assertEqual(self.engine.outbox_reset_failed("wazuh", NOW), 1)
        self.assertEqual(len(self.engine.outbox_batch("wazuh", 10)), 2)

    def test_unsupported_format_rejected(self):
        with self.assertRaises(ContractError):
            self.engine.outbox_enqueue("email", NOW)


class WazuhDeliveryTests(unittest.TestCase):
    def test_deliver_appends_records_exactly_once(self):
        engine = Engine(Registry(registry()), ":memory:")
        try:
            engine.process(s3(), NOW)
            engine.process(s3("synthetic-s3-002"), NOW + _secs(3))
            with tempfile.TemporaryDirectory() as folder:
                sink = Path(folder) / "wazuh.log"
                summary = deliver(engine, "wazuh", NOW, wazuh_output=str(sink))
                self.assertTrue(summary["complete"])
                self.assertEqual(summary["sent"], 2)
                lines = sink.read_text(encoding="utf-8").splitlines()
                self.assertEqual(len(lines), 2)
                self.assertTrue(
                    all("fg_alert_id" in json.loads(line) for line in lines)
                )
                summary = deliver(engine, "wazuh", NOW, wazuh_output=str(sink))
                self.assertEqual(summary["sent"], 0)
                self.assertEqual(len(sink.read_text(encoding="utf-8").splitlines()), 2)
        finally:
            engine.close()

    def test_deliver_requires_output_path(self):
        engine = Engine(Registry(registry()), ":memory:")
        try:
            with self.assertRaises(ContractError):
                deliver(engine, "wazuh", NOW)
        finally:
            engine.close()

    def test_output_requires_existing_trusted_directory(self):
        engine = Engine(Registry(registry()), ":memory:")
        try:
            engine.process(s3(), NOW)
            with tempfile.TemporaryDirectory() as folder:
                missing = Path(folder) / "nowhere" / "wazuh.log"
                summary = deliver(engine, "wazuh", NOW, wazuh_output=str(missing))
                self.assertFalse(summary["complete"])
                self.assertIsNotNone(summary["error"])
                self.assertEqual(
                    engine.outbox_report()["outbox"]["wazuh"].get("failed"), 1
                )
        finally:
            engine.close()


class SplunkDeliveryTests(unittest.TestCase):
    def setUp(self):
        self.engine = Engine(Registry(registry()), ":memory:")
        self.engine.process(s3(), NOW)

    def tearDown(self):
        self.engine.close()

    def _deliver(self, responses, *, token="synthetic-test-token", **kwargs):
        old = FakeConnection.responses
        FakeConnection.responses = responses
        try:
            with patch("fools_gold.transport.SEND_INTERVAL_SECONDS", 0), patch(
                "fools_gold.transport.BACKOFF_SECONDS", (0.0, 0.0)
            ):
                return deliver(
                    self.engine,
                    "splunk",
                    NOW,
                    splunk_host="hec.internal.example",
                    splunk_port=8088,
                    token=token,
                    connection_factory=lambda host, port: FakeConnection(host, port),
                    **kwargs,
                )
        finally:
            FakeConnection.responses = old

    def test_successful_delivery_posts_hec_contract(self):
        summary = self._deliver([(200, b'{"text":"Success","code":0}')])
        self.assertTrue(summary["complete"])
        self.assertEqual(summary["sent"], 1)
        method, path, headers = FakeConnection.requests[0]
        self.assertEqual((method, path), ("POST", "/services/collector/event"))
        self.assertEqual(headers["Authorization"], "Splunk synthetic-test-token")

    def test_rejection_marks_failed_and_stops_run(self):
        summary = self._deliver([(200, b'{"code":1}')])
        self.assertFalse(summary["complete"])
        self.assertIsNotNone(summary["failed"])
        self.assertEqual(
            self.engine.outbox_report()["outbox"]["splunk"].get("failed"), 1
        )

    def test_transport_errors_exhaust_bounded_attempts(self):
        summary = self._deliver([(500, b"down")])
        self.assertFalse(summary["complete"])
        attempts = self.engine.db.execute(
            "SELECT attempts FROM outbox WHERE payload_format='splunk'"
        ).fetchone()[0]
        self.assertEqual(attempts, 3)

    def test_retry_failed_requeues_and_succeeds(self):
        summary = self._deliver([(500, b"down")])
        self.assertFalse(summary["complete"])
        summary = self._deliver([(200, b'{"code":0}')], retry_failed=True)
        self.assertTrue(summary["complete"])
        self.assertEqual(summary["sent"], 1)

    def test_host_and_port_validation(self):
        with self.assertRaises(ContractError):
            post_hec("http://evil.example/", 8088, "t", b"{}")
        with self.assertRaises(ContractError):
            post_hec("hec.example", True, "t", b"{}")
        with self.assertRaises(ContractError):
            post_hec("hec.example", 70000, "t", b"{}")

    def test_token_required_from_environment(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(ContractError):
                hec_token()
        with patch.dict(os.environ, {TOKEN_VARIABLE: "x" * 300}):
            with self.assertRaises(ContractError):
                hec_token()
        with patch.dict(os.environ, {TOKEN_VARIABLE: "synthetic-ok"}):
            self.assertEqual(hec_token(), "synthetic-ok")


class RealLoopbackDeliveryTests(unittest.TestCase):
    def test_local_receiver_accepts_one_post(self):
        received = []

        class Receiver(BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers["Content-Length"])
                received.append(self.rfile.read(length))
                body = b'{"text":"Success","code":0}'
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_):
                pass

        server = HTTPServer(("127.0.0.1", 0), Receiver)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            engine = Engine(Registry(registry()), ":memory:")
            try:
                engine.process(s3(), NOW)
                with patch("fools_gold.transport.SEND_INTERVAL_SECONDS", 0):
                    summary = deliver(
                        engine,
                        "splunk",
                        NOW,
                        splunk_host="127.0.0.1",
                        splunk_port=server.server_port,
                        token="synthetic-offline-token",
                        connection_factory=lambda host, port: http.client.HTTPConnection(
                            host, port, timeout=2
                        ),
                    )
                self.assertTrue(summary["complete"])
                self.assertEqual(summary["sent"], 1)
                self.assertEqual(
                    json.loads(received[0])["event"]["product"], "fools-gold"
                )
            finally:
                engine.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
