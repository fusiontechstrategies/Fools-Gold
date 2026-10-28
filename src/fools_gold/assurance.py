"""Self-contained synthetic assurance check.

Every value below is synthetic and local. The check exercises the complete
offline path: registry, normalization, decisions, deduplication, scoped
exception, acknowledgment and, when the operator configures transport,
durable delivery. It never touches live collection and never invents
deployment results.
"""

import json
import math
import platform
import tempfile
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

from .core import ContractError, Engine, Registry, instant, stamp
from .transport import deliver

CANARY_PREFIX = "fg-canary"


def canary_registry(now: datetime) -> dict:
    return {
        "schema_version": 1,
        "decoys": [
            {
                "id": f"{CANARY_PREFIX}-s3",
                "owner": "canary-soc",
                "source": "aws.cloudtrail.s3",
                "locator": {
                    "account": "000000000000",
                    "region": "us-gov-west-1",
                    "arn": "arn:aws-us-gov:s3:::canary-decoy-bucket/backups/inventory.txt",
                },
                "created_at": stamp(now - timedelta(days=1)),
                "expires_at": stamp(now + timedelta(days=30)),
                "expected_actions": ["read", "write", "append", "delete"],
                "response_procedure": "Canary triage: verify actor and contact owner",
                "exceptions": [
                    {
                        "id": f"{CANARY_PREFIX}-backup-test",
                        "actor": "arn:aws-us-gov:sts::000000000000:assumed-role/canary-backup/canary-session",
                        "owner": "canary-backup-owner",
                        "reason": "Authorized canary read test",
                        "actions": ["read"],
                        "starts_at": stamp(now - timedelta(hours=1)),
                        "expires_at": stamp(now + timedelta(hours=1)),
                    }
                ],
            },
            {
                "id": f"{CANARY_PREFIX}-windows",
                "owner": "canary-soc",
                "source": "windows.security",
                "locator": {
                    "host": "canary-fs01",
                    "path": "C:\\CanaryDecoys\\config-export.txt",
                },
                "created_at": stamp(now - timedelta(days=1)),
                "expires_at": stamp(now + timedelta(days=30)),
                "expected_actions": ["read", "write", "append", "delete"],
                "response_procedure": "Canary triage: inspect process and confirm authorized testing",
            },
        ],
    }


def _canary_s3(now: datetime) -> dict:
    return {
        "eventSource": "s3.amazonaws.com",
        "eventCategory": "Data",
        "eventName": "GetObject",
        "eventID": f"{CANARY_PREFIX}-s3-001",
        "eventTime": stamp(now - timedelta(seconds=5)),
        "awsRegion": "us-gov-west-1",
        "recipientAccountId": "000000000000",
        "requestParameters": {
            "bucketName": "canary-decoy-bucket",
            "key": "backups/inventory.txt",
        },
        "resources": [
            {
                "type": "AWS::S3::Object",
                "ARN": "arn:aws-us-gov:s3:::canary-decoy-bucket/backups/inventory.txt",
            }
        ],
        "userIdentity": {
            "type": "AssumedRole",
            "arn": "arn:aws-us-gov:sts::000000000000:assumed-role/canary-intrusion-test/canary-session",
        },
        "sourceIPAddress": "192.0.2.10",
    }


def _canary_windows(now: datetime) -> dict:
    return {
        "source": "windows.security",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "event_id": 4663,
        "audit_outcome": "success",
        "object_type": "File",
        "computer": "canary-fs01",
        "log_epoch": "canary-installation-1",
        "record_id": "101",
        "time": stamp(now - timedelta(seconds=2)),
        "object_name": "C:\\CanaryDecoys\\config-export.txt",
        "access_mask": "0x1",
        "subject_sid": "S-1-5-21-111-222-333-1001",
        "process_name": "C:\\Windows\\System32\\notepad.exe",
    }


def canary_events(now: datetime) -> list[tuple[str, dict]]:
    """Named canary events reused by the demo and the assurance suite."""
    return [
        ("Canary GovCloud object read", _canary_s3(now)),
        ("Canary Windows document read", _canary_windows(now)),
    ]


def _scenario(name, passed, detail=None):
    result = {"name": name, "passed": passed}
    if detail:
        result.update(detail)
    return result


def run_check(now: datetime | None = None, transport_config: dict | None = None) -> dict:
    now = now or datetime.now(UTC)
    with tempfile.TemporaryDirectory(prefix="fools-gold-check-") as folder:
        engine = Engine(Registry(canary_registry(now)), Path(folder) / "evidence.sqlite")
        try:
            scenarios = []
            for name, event in (
                ("Canary GovCloud object read", _canary_s3(now)),
                ("Canary Windows document read", _canary_windows(now)),
            ):
                result = engine.process(event, now)
                if result["decision"] != "alert":
                    return {"ok": False, "error": f"missed canary trigger: {name}"}
                engine.acknowledge(
                    result["alert"]["alert_id"], "canary-analyst", now + timedelta(seconds=30)
                )
                scenarios.append(
                    _scenario(
                        name,
                        True,
                        {
                            "decoy_id": result["decoy_id"],
                            "alert_id": result["alert"]["alert_id"],
                            "telemetry_delay_seconds": result["alert"][
                                "telemetry_delay_seconds"
                            ],
                        },
                    )
                )
            benign = _canary_s3(now)
            benign["eventID"] = f"{CANARY_PREFIX}-authorized-backup"
            benign["userIdentity"]["arn"] = canary_registry(now)["decoys"][0][
                "exceptions"
            ][0]["actor"]
            expected = engine.process(benign, now)
            scenarios.append(
                _scenario(
                    "Authorized canary exception",
                    expected["decision"] == "expected_access",
                    {
                        "exception_owner": expected.get("exception_owner"),
                        "decision": expected["decision"],
                    },
                )
            )
            replay = engine.process(_canary_s3(now), now)
            scenarios.append(
                _scenario(
                    "Replay deduplication",
                    replay["decision"] == "duplicate",
                    {"decision": replay["decision"]},
                )
            )
            summary = engine.report()
            if transport_config:
                delivery = deliver(
                    engine,
                    transport_config["format"],
                    now,
                    splunk_host=transport_config.get("splunk_host"),
                    splunk_port=transport_config.get("splunk_port"),
                    wazuh_output=transport_config.get("wazuh_output"),
                    token=transport_config.get("token"),
                    connection_factory=transport_config.get("connection_factory"),
                )
                scenarios.append(
                    _scenario(
                        "Durable canary delivery",
                        delivery["complete"],
                        {
                            "format": delivery["format"],
                            "sent": delivery["sent"],
                            "error": delivery["error"],
                        },
                    )
                )
            else:
                delivery = None
            ok = all(s["passed"] for s in scenarios)
            return {
                "synthetic": True,
                "ok": ok,
                "scenarios": scenarios,
                "failed_scenarios": sum(1 for s in scenarios if not s["passed"]),
                "decisions": summary["decisions"],
                "acknowledgment_seconds": summary["acknowledgment_seconds"],
                "delivery": delivery,
                "notice": "Synthetic canary events and simulated analyst acknowledgment. Delivery stage runs only when transport is explicitly configured.",
            }
        finally:
            engine.close()


def default_live_probe(registry: Registry, host: str | None = None) -> dict:
    """Read bounded bytes from registered decoy files present on this host.

    Returns the decoy ids touched so the caller can look for a matching alert.
    Reading only occurs for decoys registered to this machine name.
    """
    host = (host or platform.node() or "").casefold()
    probed = []
    for decoy in registry.decoys[:100]:
        if decoy["source"] not in ("windows.security", "linux.audit"):
            continue
        if decoy["locator"]["host"] != host:
            continue
        try:
            with open(decoy["locator"]["path"], "rb") as handle:
                handle.read(64)
        except OSError:
            continue
        probed.append(decoy["id"])
    return {"decoy_ids": probed, "probed": len(probed)}


def _run_live_probe(engine, probe, wait_seconds, sleep, clock):
    started = clock()
    outcome = probe() or {}
    decoys = set(outcome.get("decoy_ids") or [])
    if not decoys:
        return {
            "passed": False,
            "reason": "no registered decoy was readable on this host",
        }
    deadline = started.timestamp() + wait_seconds
    while clock().timestamp() <= deadline:
        for (evidence,) in engine.db.execute("SELECT evidence FROM alerts"):
            alert = json.loads(evidence)
            if alert["decoy_id"] in decoys and instant(alert["observed_at"]) >= started:
                return {
                    "passed": True,
                    "alert_id": alert["alert_id"],
                    "decoy_ids": sorted(decoys),
                }
        sleep(1)
    return {
        "passed": False,
        "reason": "no alert observed within the wait window",
        "decoy_ids": sorted(decoys),
    }


def run_assurance(
    report_engine: Engine,
    *,
    now: datetime | None = None,
    transport_config: dict | None = None,
    probe=None,
    wait_seconds: int = 10,
    sleep=time.sleep,
    clock=None,
):
    """Run the canary suite, optionally a live probe, and record the outcome."""
    now = now or datetime.now(UTC)
    if type(wait_seconds) is not int or not 1 <= wait_seconds <= 300:
        raise ContractError("wait seconds must be an integer from 1 to 300")
    clock = clock or (lambda: datetime.now(UTC))
    result = run_check(now=now, transport_config=transport_config)
    result["mode"] = "live" if probe is not None else "canary"
    if probe is not None:
        live = _run_live_probe(report_engine, probe, wait_seconds, sleep, clock)
        result["live"] = live
        result["scenarios"].append({"name": "Live decoy probe", **live})
        if not live["passed"]:
            result["ok"] = False
            result["failed_scenarios"] += 1
    report_engine.record_assurance(
        now,
        result["mode"],
        result["ok"],
        result["failed_scenarios"],
        {"scenarios": result["scenarios"], "delivery": result.get("delivery")},
    )
    return result


def _percentile(values, fraction):
    if not values:
        return None
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, math.ceil(fraction * len(ordered)) - 1))
    return ordered[index]


def assurance_report(engine: Engine, *, max_age_hours=None, now: datetime | None = None):
    """Summarize assurance history and detection/acknowledgment latencies."""
    now = now or datetime.now(UTC)
    if max_age_hours is not None and (
        type(max_age_hours) is not int or not 0 <= max_age_hours <= 24 * 3650
    ):
        raise ContractError("max age hours must be a nonnegative integer")
    history = engine.assurance_history(1000)
    alerts = list(engine.export_alerts())
    delays = [alert["telemetry_delay_seconds"] for alert in alerts]
    acknowledgments = engine.report()["acknowledgment_seconds"]
    last_ok = next((run for run in history if run["ok"]), None)
    age_hours = None
    if last_ok is not None:
        age_hours = round(
            (now - instant(last_ok["ran_at"])).total_seconds() / 3600, 3
        )
    stale = None
    if max_age_hours is not None:
        stale = age_hours is None or age_hours > max_age_hours
    return {
        "schema_version": 1,
        "runs": len(history),
        "passed": sum(1 for run in history if run["ok"]),
        "failed": sum(1 for run in history if not run["ok"]),
        "last_ok_at": last_ok["ran_at"] if last_ok else None,
        "last_ok_age_hours": age_hours,
        "mttd_seconds": {
            "p50": _percentile(delays, 0.50),
            "p95": _percentile(delays, 0.95),
            "max": max(delays) if delays else None,
            "samples": len(delays),
        },
        "mtta_seconds": {
            "p50": _percentile(acknowledgments, 0.50),
            "p95": _percentile(acknowledgments, 0.95),
            "max": max(acknowledgments) if acknowledgments else None,
            "samples": len(acknowledgments),
        },
        "max_age_hours": max_age_hours,
        "stale": stale,
    }
