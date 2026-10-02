import copy
import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from fools_gold.collection import cloudtrail_export, windows_event_xml
from fools_gold.core import ContractError, Engine, Registry
from fools_gold.delivery import send_splunk_mock, splunk_hec_packet, wazuh_json_record
from tests.test_pilot import NOW, registry, s3, windows

WINDOWS_XML = b"""<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System><Provider Name="Microsoft-Windows-Security-Auditing"/>
<EventID>4663</EventID><Keywords>0x8020000000000000</Keywords>
<TimeCreated SystemTime="2026-10-02T11:59:58Z"/><EventRecordID>101</EventRecordID>
<Channel>Security</Channel><Computer>synthetic-fs01</Computer></System>
<EventData><Data Name="SubjectUserSid">S-1-5-21-111-222-333-1001</Data>
<Data Name="ObjectType">File</Data><Data Name="ObjectName">C:\\SyntheticDecoys\\config-export.txt</Data>
<Data Name="AccessMask">0x1</Data><Data Name="ProcessName">C:\\Windows\\System32\\notepad.exe</Data>
</EventData></Event>"""


class CollectionTests(unittest.TestCase):
    def test_windows_xml_maps_to_existing_contract(self):
        self.assertEqual(
            windows_event_xml(WINDOWS_XML, log_epoch="synthetic-installation-1"),
            windows(),
        )

    def test_xml_dtd_entities_encoding_namespace_and_duplicates_rejected(self):
        examples = (
            b'<!DOCTYPE Event [<!ENTITY x "expanded">]>' + WINDOWS_XML,
            WINDOWS_XML.replace(b"/events/event", b"/events/unknown"),
            WINDOWS_XML.replace(
                b"<EventID>4663</EventID>",
                b"<EventID>4663</EventID><EventID>4663</EventID>",
            ),
            WINDOWS_XML.replace(
                b"</EventData>", b'<Data Name="AccessMask">0x2</Data></EventData>'
            ),
            WINDOWS_XML.decode().encode("utf-16"),
            b"x" * 65537,
        )
        for payload in examples:
            with self.subTest(payload=payload[:40]), self.assertRaises(ContractError):
                windows_event_xml(payload, log_epoch="synthetic-installation-1")

    def test_xml_outcome_is_checked_not_invented(self):
        for keywords in (
            b"0x8010000000000000",
            b"0x8030000000000000",
            b"0x8000000000000000",
        ):
            with self.assertRaises(ContractError):
                windows_event_xml(
                    WINDOWS_XML.replace(b"0x8020000000000000", keywords),
                    log_epoch="test",
                )

    def test_unused_native_fields_can_be_multiline_or_empty(self):
        payload = WINDOWS_XML.replace(
            b"</EventData>",
            b'<Data Name="AccessList">%%4416\n%%4417</Data><Data Name="Unused"/></EventData>',
        )
        self.assertEqual(
            windows_event_xml(payload, log_epoch="synthetic-installation-1"), windows()
        )

    def test_cloudtrail_envelope_yields_validated_records(self):
        self.assertEqual(
            cloudtrail_export(json.dumps({"Records": [s3()]}).encode()), [s3()]
        )

    def test_cloudtrail_invalid_batch_does_not_partially_accept(self):
        for doc in (
            {"Records": []},
            {"Records": [s3(), {}]},
            {"Records": [windows()]},
            {"Records": [s3()], "extra": True},
        ):
            with self.assertRaises(ContractError):
                cloudtrail_export(json.dumps(doc).encode())
        with self.assertRaises(ContractError):
            cloudtrail_export(b' {"Records": [], "Records": []}')

    def test_registry_snapshot_cannot_change_from_callers_input(self):
        document = registry()
        snapshot = Registry(document)
        document["decoys"][0]["exceptions"][0]["actor"] = "changed-by-caller"
        self.assertNotEqual(
            snapshot.decoys[0]["exceptions"][0]["actor"], "changed-by-caller"
        )

    def test_replay_delimiters_and_falsey_error_code_are_rejected(self):
        raw = windows()
        raw["computer"] = "host:ambiguous"
        with self.assertRaises(ContractError):
            from fools_gold.core import normalize

            normalize(raw)
        for value in (False, None, ""):
            raw = s3()
            raw["errorCode"] = value
            with self.assertRaises(ContractError):
                normalize(raw)


class DeliveryTests(unittest.TestCase):
    def setUp(self):
        self.engine = Engine(Registry(registry()), ":memory:")
        self.alert = self.engine.process(s3(), NOW)["alert"]

    def tearDown(self):
        self.engine.close()

    def test_splunk_packet_preserves_original_alert_identity_and_time(self):
        payload = json.loads(splunk_hec_packet(self.alert))
        self.assertEqual(payload["event"], self.alert)
        self.assertEqual(payload["sourcetype"], "fools_gold:alert:json")
        self.assertEqual(payload["time"], NOW.timestamp() - 5)

    def test_wazuh_local_record_round_trip(self):
        payload = wazuh_json_record(self.alert)
        with tempfile.TemporaryDirectory() as folder:
            sink = Path(folder) / "synthetic-wazuh.log"
            sink.write_bytes(payload)
            record = json.loads(sink.read_bytes())
        self.assertEqual(record["fg_alert_id"], self.alert["alert_id"])
        self.assertEqual(record["fg_outcome"], "success")
        self.assertEqual(record["fg_actor"], self.alert["event"]["actor"])
        self.assertTrue(payload.endswith(b"\n"))

    def test_invalid_or_oversized_packets_fail_closed(self):
        for change in (
            {"alert_id": "not-an-alert"},
            {"schema_version": True},
            {"event": {"source": []}},
        ):
            value = copy.deepcopy(self.alert)
            value.update(change)
            with self.assertRaises(ContractError):
                splunk_hec_packet(value)
        value = copy.deepcopy(self.alert)
        value["extra"] = "x" * 65536
        with self.assertRaises(ContractError):
            splunk_hec_packet(value)

    def test_local_mock_acceptance_failure_and_redirect(self):
        received = []
        response = {"status": 200, "body": b'{"text":"Success","code":0}'}

        class Receiver(BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers["Content-Length"])
                received.append(
                    (
                        self.path,
                        self.headers["Authorization"],
                        json.loads(self.rfile.read(length)),
                    )
                )
                self.send_response(response["status"])
                self.send_header("Content-Length", str(len(response["body"])))
                self.end_headers()
                self.wfile.write(response["body"])

            def log_message(self, *_):
                pass

        server = HTTPServer(("127.0.0.1", 0), Receiver)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            outcome = send_splunk_mock(self.alert, port=server.server_port)
            self.assertTrue(outcome["accepted"])
            self.assertFalse(outcome["indexing_verified"])
            self.assertFalse(outcome["analyst_acknowledged"])
            self.assertEqual(received[0][0], "/services/collector/event")
            self.assertEqual(received[0][1], "Splunk synthetic-offline-token")
            self.assertEqual(
                received[0][2]["event"]["alert_id"], self.alert["alert_id"]
            )
            for status, body in (
                (302, b"redirect"),
                (401, b"denied"),
                (200, b'{"code":1}'),
                (200, b'{"code":1,"code":0}'),
                (200, b"x" * 4097),
            ):
                response.update(status=status, body=body)
                with self.assertRaises(ContractError):
                    send_splunk_mock(self.alert, port=server.server_port)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_mock_configuration_cannot_choose_a_remote_host(self):
        for port in (True, 0, 65536, "8088"):
            with self.assertRaises(ContractError):
                send_splunk_mock(self.alert, port=port)
