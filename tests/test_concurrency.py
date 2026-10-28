"""Cross-process integration: dashboard, ingestion, live assurance, writers."""

import contextlib
import json
import os
import platform
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.request
from datetime import UTC, datetime, timedelta
from pathlib import Path

from fools_gold.core import Engine, Registry
from fools_gold.onboarding import write_registry
from fools_gold.ui import make_server
from tests.test_contracts_v2 import linux
from tests.test_pilot import NOW, registry, s3, windows

ROOT = Path(__file__).resolve().parents[1]
TOKEN = "synthetic-cross-process-token"


def run_cli(args, *, timeout=90):
    env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
    return subprocess.run(
        [sys.executable, "-m", "fools_gold", *args],
        cwd=str(ROOT),
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def current_s3(event_id):
    event = s3(event_id)
    event["eventTime"] = (datetime.now(UTC) - timedelta(seconds=2)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    return event


def writer_files(folder):
    registry_path = Path(folder) / "registry.json"
    registry_path.write_text(json.dumps(registry()), encoding="utf-8")
    return registry_path, Path(folder) / "evidence.sqlite"


def write_events(folder, name, events):
    path = Path(folder) / name
    path.write_text(
        "".join(json.dumps(event) + "\n" for event in events), encoding="utf-8"
    )
    return path


@contextlib.contextmanager
def dashboard(engine):
    server = make_server(engine, TOKEN, 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def api_get(base, path):
    request = urllib.request.Request(base + path)
    request.add_header("Authorization", f"Bearer {TOKEN}")
    with urllib.request.urlopen(request, timeout=10) as response:  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
        return json.loads(response.read())


class DashboardIngestionTests(unittest.TestCase):
    def test_ingestion_succeeds_while_the_dashboard_is_open(self):
        with tempfile.TemporaryDirectory() as folder:
            registry_path, database = writer_files(folder)
            engine = Engine(Registry(registry()), database, thread_safe=True)
            try:
                with dashboard(engine) as base:
                    events = write_events(
                        folder, "events.jsonl", [current_s3("cross-1")]
                    )
                    completed = run_cli(
                        [
                            "--registry",
                            str(registry_path),
                            "--database",
                            str(database),
                            "ingest",
                            str(events),
                        ]
                    )
                    self.assertEqual(completed.returncode, 0, completed.stderr)
                    alerts = api_get(base, "/api/alerts")["alerts"]
                    self.assertEqual(len(alerts), 1)
                    self.assertEqual(
                        alerts[0]["event"]["id"], "cross-1"
                    )
            finally:
                engine.close()

    def test_dashboard_acknowledgment_interleaves_with_ingestion(self):
        with tempfile.TemporaryDirectory() as folder:
            registry_path, database = writer_files(folder)
            engine = Engine(Registry(registry()), database, thread_safe=True)
            try:
                first = write_events(folder, "first.jsonl", [current_s3("ack-1")])
                run_cli(
                    [
                        "--registry",
                        str(registry_path),
                        "--database",
                        str(database),
                        "ingest",
                        str(first),
                    ]
                )
                alert_id = next(engine.export_alerts())["alert_id"]
                with dashboard(engine) as base:
                    second = write_events(
                        folder, "second.jsonl", [current_s3("ack-2")]
                    )
                    writer = subprocess.Popen(
                        [
                            sys.executable,
                            "-m",
                            "fools_gold",
                            "--registry",
                            str(registry_path),
                            "--database",
                            str(database),
                            "ingest",
                            str(second),
                        ],
                        cwd=str(ROOT),
                        env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                    )
                    request = urllib.request.Request(
                        base + "/api/acknowledge",
                        data=json.dumps(
                            {"alert_id": alert_id, "analyst": "dash-1"}
                        ).encode(),
                        method="POST",
                    )
                    request.add_header("Content-Type", "application/json")
                    request.add_header("Authorization", f"Bearer {TOKEN}")
                    with urllib.request.urlopen(request, timeout=20) as response:  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
                        self.assertEqual(response.status, 200)
                    _, stderr = writer.communicate(timeout=60)
                    self.assertEqual(writer.returncode, 0, stderr)
                    self.assertEqual(engine.report()["alerts_acknowledged"], 1)
                    self.assertEqual(engine.report()["decisions"]["alert"], 2)
            finally:
                engine.close()


class LiveAssuranceIntegrationTests(unittest.TestCase):
    def test_live_assurance_succeeds_when_a_separate_process_ingests(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            host = platform.node()
            decoy_path = root / "decoy.txt"
            decoy_path.write_text("SYNTHETIC DECOY\n", encoding="utf-8")
            spec = {"host": host, "path": str(decoy_path)}
            if os.name == "nt":
                selector = {"windows": spec}
                event = windows()
                event["time"] = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
                event["record_id"] = "9001"
                event["object_name"] = str(decoy_path)
                event["computer"] = host
            else:
                selector = {"linux": spec}
                event = linux("9001")
                event["time"] = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
                event["path"] = str(decoy_path)
                event["host"] = host
                event["uid"] = str(os.getuid())
            registry_path = Path(
                write_registry(root, owner="synthetic-soc", now=NOW, **selector)
            )
            database = root / "evidence.sqlite"
            events = write_events(root, "live.jsonl", [event])
            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
            assure = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "fools_gold",
                    "--registry",
                    str(registry_path),
                    "--database",
                    str(database),
                    "assure",
                    "--live",
                    "--wait-seconds",
                    "45",
                ],
                cwd=str(ROOT),
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            time.sleep(3)
            ingested = run_cli(
                [
                    "--registry",
                    str(registry_path),
                    "--database",
                    str(database),
                    "ingest",
                    str(events),
                ]
            )
            self.assertEqual(ingested.returncode, 0, ingested.stderr)
            stdout, stderr = assure.communicate(timeout=90)
            self.assertEqual(assure.returncode, 0, stderr + stdout)
            result = json.loads(stdout)
            self.assertTrue(result["ok"], result)
            self.assertEqual(result["stages"]["live"]["status"], "pass")
            self.assertEqual(
                result["live"]["detected"], ["decoy-windows-1"]
                if os.name == "nt"
                else ["decoy-linux-1"]
            )


class ConcurrentWriterTests(unittest.TestCase):
    def test_concurrent_ingestion_preserves_dedup_and_chain(self):
        with tempfile.TemporaryDirectory() as folder:
            registry_path, database = writer_files(folder)
            key = Path(folder) / "evidence.key"
            key.write_text("ab" * 32, encoding="utf-8")
            files = [
                write_events(folder, "a.jsonl", [s3("w-1"), s3("w-2")]),
                write_events(folder, "b.jsonl", [s3("w-2"), s3("w-3")]),
                write_events(folder, "c.jsonl", [s3("w-3"), s3("w-4")]),
            ]
            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
            processes = [
                subprocess.Popen(
                    [
                        sys.executable,
                        "-m",
                        "fools_gold",
                        "--registry",
                        str(registry_path),
                        "--database",
                        str(database),
                        "--evidence-key-file",
                        str(key),
                        "ingest",
                        str(path),
                    ],
                    cwd=str(ROOT),
                    env=env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                for path in files
            ]
            for process in processes:
                _, stderr = process.communicate(timeout=90)
                self.assertEqual(process.returncode, 0, stderr)
            engine = Engine(
                Registry(registry()), database, mac_key=bytes.fromhex("ab" * 32)
            )
            try:
                self.assertEqual(engine.report()["decisions"]["alert"], 4)
                ids = [alert["event"]["id"] for alert in engine.export_alerts()]
                self.assertEqual(sorted(ids), ["w-1", "w-2", "w-3", "w-4"])
                outcome = engine.verify_integrity()
                self.assertTrue(outcome["ok"], outcome)
                self.assertEqual(outcome["alerts"], 4)
            finally:
                engine.close()


if __name__ == "__main__":
    unittest.main()
