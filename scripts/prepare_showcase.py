"""Create reproducible synthetic data for the console walkthrough/screenshots.

Run from a source checkout with PYTHONPATH=src. No live sensor, AWS request,
SIEM connection, audit-policy change or task registration is performed.
"""

import argparse
import copy
import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

from fools_gold.assurance import canary_events, canary_registry, run_assurance
from fools_gold.core import ContractError, Engine, Registry, stamp
from fools_gold.onboarding import write_key
from fools_gold.reporting import build_bundle, verify_bundle
from fools_gold.transport import deliver


def prepare(folder):
    if os.name != "nt":
        os.umask(0o077)
    root = Path(folder)
    if root.is_symlink() or (root.exists() and any(root.iterdir())):
        raise ContractError("showcase requires a new or empty trusted directory")
    root.mkdir(parents=True, mode=0o700, exist_ok=True)
    now = datetime.now(UTC)
    document = canary_registry(now)
    document["decoys"].append(
        {
            "id": "synthetic-linux-config",
            "owner": "synthetic-soc",
            "source": "linux.audit",
            "locator": {
                "host": "synthetic-linux01",
                "path": "/opt/decoys/config-export.txt",
            },
            "created_at": stamp(now - timedelta(days=1)),
            "expires_at": stamp(now + timedelta(days=30)),
            "expected_actions": ["read", "write", "append", "delete", "recon"],
            "response_procedure": "Synthetic triage: inspect uid, process and path",
        }
    )
    routes = {
        "aws.cloudtrail.s3": "cloud-soc",
        "windows.security": "windows-soc",
        "linux.audit": "linux-soc",
    }
    for decoy in document["decoys"]:
        decoy["owner"] = "synthetic-soc"
        decoy["route"] = routes[decoy["source"]]
    (root / "registry.json").write_text(
        json.dumps(document, indent=2) + "\n", encoding="utf-8"
    )
    key_path = Path(write_key(root))
    key = bytes.fromhex(key_path.read_text(encoding="ascii").strip())
    engine = Engine(Registry(document), root / "evidence.sqlite", mac_key=key)
    try:
        templates = [item[1] for item in canary_events(now)]
        for index in range(12):
            received = now - timedelta(minutes=12 - index)
            event_at = stamp(received - timedelta(seconds=2 + index % 4))
            if index % 3 == 0:
                event = copy.deepcopy(templates[0])
                event.update(
                    eventID=f"synthetic-showcase-s3-{index}", eventTime=event_at
                )
                if index == 6:
                    event["errorCode"] = "AccessDenied"
            elif index % 3 == 1:
                event = copy.deepcopy(templates[1])
                event.update(record_id=str(7000 + index), time=event_at)
                if index == 7:
                    event.update(event_id=4656, audit_outcome="failure")
            else:
                event = {
                    "source": "linux.audit",
                    "host": "synthetic-linux01",
                    "path": "/opt/decoys/config-export.txt",
                    "sensor_epoch": "synthetic-boot-1",
                    "record_id": str(8000 + index),
                    "time": event_at,
                    "uid": "1001",
                    "process_name": "/usr/bin/cat",
                    "action": "write" if index == 8 else "read",
                    "audit_outcome": "denied" if index == 8 else "success",
                }
            outcome = engine.process(event, received)
            if outcome["decision"] != "alert":
                raise ContractError("showcase fixture did not produce an alert")
            if index < 4:
                engine.acknowledge(
                    outcome["alert"]["alert_id"],
                    "synthetic-analyst",
                    received + timedelta(seconds=30),
                )
        assurance = run_assurance(engine, now=now)
        if not assurance["ok"]:
            raise ContractError("showcase canary check failed")
        for route in routes.values():
            engine.add_destination(
                now, route, "wazuh", path=str((root / f"{route}.jsonl").resolve())
            )
            engine.map_route(now, route, route)
            outcome = deliver(engine, route, now, route=route)
            if not outcome["complete"] or outcome["sent"] != 4:
                raise ContractError("showcase local JSONL delivery failed")
        bundle = root / "synthetic-case.zip"
        build_bundle(engine, bundle, now=now)
        if not verify_bundle(bundle, key)["authenticated"]:
            raise ContractError("showcase bundle did not authenticate")
        engine.backup(root / "backup.sqlite")
    finally:
        engine.close()
    profile = {
        "registry": "registry.json",
        "database": "evidence.sqlite",
        "evidence_key_file": "evidence.key",
    }
    (root / "profile.json").write_text(
        json.dumps(profile, indent=2) + "\n", encoding="utf-8"
    )
    result = {
        "synthetic": True,
        "alerts": 12,
        "simulated_acknowledgments": 4,
        "local_jsonl_deliveries": 12,
        "assurance_mode": "canary",
        "bundle_authenticated": True,
        "profile": str(root / "profile.json"),
        "notice": "Synthetic contract events and simulated analyst timing. Local JSONL delivery only; live sensors, AWS, SIEM indexing and real analyst response are unverified.",
    }
    (root / "summary.json").write_text(
        json.dumps(result, indent=2) + "\n", encoding="utf-8"
    )
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default="runtime/showcase")
    args = parser.parse_args()
    try:
        print(json.dumps(prepare(args.out), indent=2))
    except (ContractError, OSError) as exc:
        parser.exit(2, f"Showcase: {exc}\n")


if __name__ == "__main__":
    main()
