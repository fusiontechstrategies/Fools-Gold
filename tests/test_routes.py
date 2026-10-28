"""Route mappings must affect delivery, and retries must be route-scoped."""

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from fools_gold.cli import main
from fools_gold.core import ContractError, Engine, Registry
from fools_gold.transport import deliver
from tests.test_contracts_v2 import linux
from tests.test_pilot import NOW, registry


def two_route_registry():
    document = registry()
    document["decoys"].append(
        {
            "id": "synthetic-linux-secondary",
            "owner": "synthetic-soc",
            "source": "linux.audit",
            "locator": {
                "host": "synthetic-linux01",
                "path": "/opt/decoys/secondary.txt",
            },
            "created_at": "2026-10-01T00:00:00Z",
            "expires_at": "2026-11-01T00:00:00Z",
            "expected_actions": ["read"],
            "response_procedure": "Synthetic triage: secondary",
            "route": "soc-secondary",
        }
    )
    return document


def two_route_events():
    return [
        linux("601"),
        linux("602", path="/opt/decoys/secondary.txt"),
    ]


def engine_in(folder):
    return Engine(Registry(two_route_registry()), Path(folder) / "db.sqlite")


class RouteMappingTests(unittest.TestCase):
    def test_enqueue_refuses_a_conflicting_mapped_destination(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = engine_in(folder)
            try:
                for event in two_route_events():
                    engine.process(event, NOW)
                a = Path(folder) / "a.log"
                b = Path(folder) / "b.log"
                engine.add_destination(NOW, "a", "wazuh", path=str(a))
                engine.add_destination(NOW, "b", "wazuh", path=str(b))
                engine.map_route(NOW, "soc-primary", "a")
                with self.assertRaises(ContractError):
                    engine.outbox_enqueue("b", NOW, route="soc-primary")
                self.assertEqual(
                    engine.outbox_enqueue("a", NOW, route="soc-primary"), 1
                )
            finally:
                engine.close()

    def test_mapped_route_selects_the_destination(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = engine_in(folder)
            try:
                for event in two_route_events():
                    engine.process(event, NOW)
                sink = Path(folder) / "mapped.log"
                engine.add_destination(NOW, "mapped", "wazuh", path=str(sink))
                engine.map_route(NOW, "soc-primary", "mapped")
                summary = deliver(engine, "mapped", NOW, route="soc-primary")
                self.assertTrue(summary["complete"])
                self.assertEqual(summary["sent"], 1)
                self.assertEqual(
                    len(sink.read_text(encoding="utf-8").splitlines()), 1
                )
            finally:
                engine.close()

    def test_route_retries_are_scoped_to_their_alert_set(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = engine_in(folder)
            try:
                for event in two_route_events():
                    engine.process(event, NOW)
                sink = Path(folder) / "shared.log"
                engine.add_destination(NOW, "shared", "wazuh", path=str(sink))
                engine.map_route(NOW, "soc-primary", "shared")
                engine.map_route(NOW, "soc-secondary", "shared")
                engine.outbox_enqueue("shared", NOW)
                primary_alert = next(
                    alert
                    for alert in engine.export_alerts()
                    if alert["route"] == "soc-primary"
                )["alert_id"]
                engine.outbox_mark(
                    "shared", primary_alert, "failed", NOW, error="simulated"
                )
                self.assertEqual(
                    engine.outbox_report()["outbox"]["shared"].get("failed"), 1
                )
                summary = deliver(
                    engine, "shared", NOW, route="soc-secondary", retry_failed=True
                )
                self.assertTrue(summary["complete"])
                self.assertEqual(summary["sent"], 1)
                report = engine.outbox_report()["outbox"]["shared"]
                self.assertEqual(report.get("failed"), 1)
                # A no-op retry of the unrelated route must not claim success.
                noop = deliver(engine, "shared", NOW, route="soc-primary")
                self.assertFalse(noop["complete"])
                self.assertEqual(noop["failed_remaining"], 1)
                retried = deliver(
                    engine, "shared", NOW, route="soc-primary", retry_failed=True
                )
                self.assertTrue(retried["complete"])
                self.assertEqual(retried["sent"], 1)
                self.assertEqual(
                    engine.outbox_report()["outbox"]["shared"],
                    {"sent": 2},
                )
            finally:
                engine.close()

    def test_noop_completion_is_false_while_failures_remain(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = engine_in(folder)
            try:
                engine.process(linux("603"), NOW)
                sink = Path(folder) / "s.log"
                engine.add_destination(NOW, "s", "wazuh", path=str(sink))
                engine.outbox_enqueue("s", NOW)
                alert_id = engine.outbox_batch("s", 10)[0][0]
                engine.outbox_mark("s", alert_id, "failed", NOW, error="x")
                summary = deliver(engine, "s", NOW)
                self.assertEqual(summary["sent"], 0)
                self.assertEqual(summary["failed_remaining"], 1)
                self.assertFalse(summary["complete"])
                again = deliver(engine, "s", NOW, retry_failed=True)
                self.assertTrue(again["complete"])
            finally:
                engine.close()


class RouteCliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.folder = Path(self.temp.name)
        self.registry = self.folder / "registry.json"
        self.registry.write_text(
            json.dumps(two_route_registry()), encoding="utf-8"
        )
        self.database = self.folder / "db.sqlite"
        self.base = [
            "--registry",
            str(self.registry),
            "--database",
            str(self.database),
        ]

    def tearDown(self):
        self.temp.cleanup()

    def invoke(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(self.base + list(args))
        return code, out.getvalue(), err.getvalue()

    def seed(self, sink):
        events = self.folder / "events.jsonl"
        events.write_text(
            "".join(json.dumps(event) + "\n" for event in two_route_events()),
            encoding="utf-8",
        )
        self.assertEqual(self.invoke("ingest", str(events))[0], 0)
        self.assertEqual(
            self.invoke(
                "destination", "add", "--name", "mapped", "--format", "wazuh",
                "--path", str(sink),
            )[0],
            0,
        )
        self.assertEqual(
            self.invoke(
                "route", "map", "--route", "soc-primary", "--destination", "mapped"
            )[0],
            0,
        )

    def test_route_alone_selects_the_mapped_destination(self):
        sink = self.folder / "mapped.log"
        self.seed(sink)
        code, output, error = self.invoke("deliver", "--route", "soc-primary")
        self.assertEqual(code, 0, error)
        self.assertEqual(json.loads(output)["destination"], "mapped")
        self.assertEqual(len(sink.read_text(encoding="utf-8").splitlines()), 1)

    def test_conflicting_destination_is_rejected(self):
        sink = self.folder / "a.log"
        other = self.folder / "b.log"
        self.seed(sink)
        self.invoke(
            "destination", "add", "--name", "other", "--format", "wazuh",
            "--path", str(other),
        )
        code, _, error = self.invoke(
            "deliver", "--destination", "other", "--route", "soc-primary"
        )
        self.assertEqual(code, 2)
        self.assertIn("mapped to destination", error)

    def test_unmapped_route_requires_a_selector(self):
        self.seed(self.folder / "x.log")
        code, _, error = self.invoke("deliver", "--route", "unmapped-route")
        self.assertEqual(code, 2)
        self.assertIn("not mapped", error)


if __name__ == "__main__":
    unittest.main()
