"""Explicit operator commands.

Local by default: ingest, acknowledge, report, export-alerts, verify-integrity,
trail-inbox and check never transmit. Only deliver transmits, and only when
the operator explicitly supplies a configured endpoint and runs it.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import sqlite3
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

from .assurance import (
    assurance_report,
    default_live_probe,
    run_assurance,
    run_check,
)
from .core import (
    ContractError,
    Engine,
    Registry,
    canonical,
    no_duplicate_keys,  # noqa: F401  (re-exported compatibility surface)
    parse_json,
    restore_database,
)
from .reporting import build_bundle, incidents, verify_bundle
from .trail_inbox import MAX_INBOX_BYTES, cloudtrail_records_file
from .transport import deliver


def load_registry(path):
    with Path(path).open("rb") as handle:
        payload = handle.read(1024 * 1024 + 1)
    if len(payload) > 1024 * 1024:
        raise ContractError("registry exceeds 1 MiB")
    return Registry(parse_json(payload))


def load_evidence_key(path) -> bytes:
    with Path(path).open("rb") as handle:
        payload = handle.read(1025)
    if len(payload) > 1024:
        raise ContractError("evidence key file exceeds 1 KiB")
    try:
        value = payload.decode("ascii").strip()
    except UnicodeError as exc:
        raise ContractError("evidence key file must be ASCII") from exc
    if not re.fullmatch(r"[0-9a-fA-F]{64}", value):
        raise ContractError("evidence key must be 64 hexadecimal characters (32 bytes)")
    return bytes.fromhex(value)


def _transport_config(args, command):
    if (args.splunk_host is not None) and (args.wazuh_output is not None):
        raise ContractError(f"{command} accepts at most one transport target")
    if args.splunk_host is None and args.splunk_port is not None:
        raise ContractError(f"{command} --splunk-port requires --splunk-host")
    if args.splunk_host is not None:
        if args.splunk_port is None:
            raise ContractError(f"{command} Splunk transport requires --splunk-port")
        return {
            "format": "splunk",
            "splunk_host": args.splunk_host,
            "splunk_port": args.splunk_port,
        }
    if args.wazuh_output is not None:
        return {"format": "wazuh", "wazuh_output": args.wazuh_output}
    return None


def run_windows_collector(
    registry: Registry, *, log_epoch, follow, interval_seconds, max_events
):
    from .winlog import collect

    try:
        while True:
            events, skipped = collect(
                registry, log_epoch=log_epoch, max_events=max_events
            )
            for event in events:
                print(canonical(event))
            if skipped:
                print(
                    f"Fool's Gold collector: skipped {skipped} non-contract event(s)",
                    file=sys.stderr,
                )
            if not follow:
                return 0
            time.sleep(interval_seconds)
    except KeyboardInterrupt:
        return 0


def run_trail_inbox(engine: Engine, directory: str):
    folder = Path(directory)
    if not folder.is_dir():
        raise ContractError("trail inbox must be an existing directory")
    candidates = sorted(
        path
        for path in folder.iterdir()
        if path.is_file()
        and (path.name.endswith(".json") or path.name.endswith(".json.gz"))
    )
    errors = 0
    skipped = 0
    for path in candidates:
        with path.open("rb") as handle:
            payload = handle.read(MAX_INBOX_BYTES + 1)
        if len(payload) > MAX_INBOX_BYTES:
            errors += 1
            print(
                canonical(
                    {
                        "decision": "rejected",
                        "file": path.name,
                        "error": "CloudTrail log file exceeds 16 MiB",
                    }
                )
            )
            continue
        digest = hashlib.sha256(payload).hexdigest()
        if engine.trail_file_processed(digest):
            skipped += 1
            continue
        try:
            records = cloudtrail_records_file(payload)
        except ContractError as exc:
            errors += 1
            print(
                canonical(
                    {"decision": "rejected", "file": path.name, "error": str(exc)}
                )
            )
            continue
        had_error = False
        for record in records:
            try:
                result = engine.process(record, datetime.now(UTC))
            except ContractError as exc:
                had_error = True
                errors += 1
                print(
                    canonical(
                        {
                            "decision": "rejected",
                            "file": path.name,
                            "error": str(exc),
                        }
                    )
                )
            else:
                print(canonical(result))
        if not had_error:
            engine.mark_trail_file(digest, datetime.now(UTC))
    return 2 if errors else 0


def main(argv=None):
    parser = argparse.ArgumentParser(description="Fool's Gold decoy detection pilot")
    parser.add_argument("--registry", help="Protected exact-location registry JSON")
    parser.add_argument(
        "--database", help="Protected local SQLite evidence database"
    )
    parser.add_argument(
        "--evidence-key-file",
        help="File holding 64 hexadecimal characters (32 bytes) for HMAC evidence chaining",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    ingest = commands.add_parser(
        "ingest", help="Read JSONL events; print decision JSONL"
    )
    ingest.add_argument("events")
    inbox = commands.add_parser(
        "trail-inbox", help="Process CloudTrail log files from a local inbox directory"
    )
    inbox.add_argument("directory")
    collector = commands.add_parser(
        "collect-windows",
        help="Emit contract JSONL for registered decoy locations from the local Security log",
    )
    collector.add_argument(
        "--log-epoch", required=True, help="Collector-supplied log generation identity"
    )
    collector.add_argument(
        "--follow", action="store_true", help="Repeat the query until interrupted"
    )
    collector.add_argument(
        "--interval-seconds", type=int, default=5, help="Follow-mode poll interval"
    )
    collector.add_argument(
        "--max-events", type=int, default=128, help="Maximum events per query"
    )
    ack = commands.add_parser(
        "acknowledge", help="Record a local analyst acknowledgment"
    )
    ack.add_argument("alert_id")
    ack.add_argument("--analyst", required=True)
    commands.add_parser("report", help="Summarize stored local evidence")
    commands.add_parser(
        "export-alerts",
        help="Read retained alerts as decision JSONL; does not deliver or acknowledge",
    )
    commands.add_parser(
        "verify-integrity",
        help="Recompute the HMAC evidence chain; requires --evidence-key-file",
    )
    deliver_parser = commands.add_parser(
        "deliver",
        help="Deliver retained alerts to an operator-configured endpoint",
    )
    deliver_parser.add_argument(
        "--format", choices=("wazuh", "splunk"), required=True
    )
    deliver_parser.add_argument("--splunk-host")
    deliver_parser.add_argument("--splunk-port", type=int)
    deliver_parser.add_argument("--wazuh-output")
    deliver_parser.add_argument("--limit", type=int, default=64)
    deliver_parser.add_argument(
        "--route", help="Only enqueue alerts whose decoy uses this route"
    )
    deliver_parser.add_argument(
        "--retry-failed", action="store_true", help="Requeue previously failed packets"
    )
    check = commands.add_parser(
        "check", help="Run the self-contained synthetic assurance exercise"
    )
    check.add_argument("--splunk-host")
    check.add_argument("--splunk-port", type=int)
    check.add_argument("--wazuh-output")
    assure = commands.add_parser(
        "assure",
        help="Run the canary suite against this deployment and record the result",
    )
    assure.add_argument("--live", action="store_true", help="Also probe real decoy files")
    assure.add_argument("--wait-seconds", type=int, default=10)
    assure.add_argument("--splunk-host")
    assure.add_argument("--splunk-port", type=int)
    assure.add_argument("--wazuh-output")
    report = commands.add_parser(
        "assure-report",
        help="Show assurance history and MTTD/MTTA metrics",
    )
    report.add_argument("--max-age-hours", type=int)
    prune = commands.add_parser(
        "prune", help="Delete evidence older than a retention window"
    )
    prune.add_argument("--older-than-days", type=int, required=True)
    backup = commands.add_parser("backup", help="Write a consistent database copy")
    backup.add_argument("--out", required=True)
    restore = commands.add_parser(
        "restore", help="Replace the database with a verified backup"
    )
    restore.add_argument("--source", required=True)
    timeline = commands.add_parser(
        "incidents", help="Cluster alerts per actor into incidents"
    )
    timeline.add_argument("--gap-seconds", type=int, default=300)
    bundle = commands.add_parser(
        "bundle", help="Write a tamper-evident evidence bundle"
    )
    bundle.add_argument("--out", required=True)
    verify = commands.add_parser(
        "verify-bundle", help="Validate an evidence bundle's hashes and signature"
    )
    verify.add_argument("--file", required=True)
    args = parser.parse_args(argv)
    engine = None
    try:
        # Protect new POSIX runtime files. Windows deployment requires explicit ACLs.
        if os.name != "nt":
            os.umask(0o077)
        if args.command == "collect-windows":
            if not args.registry:
                raise ContractError("collect-windows requires --registry")
            if not 1 <= args.interval_seconds <= 3600:
                raise ContractError("--interval-seconds must be 1 to 3600")
            return run_windows_collector(
                load_registry(args.registry),
                log_epoch=args.log_epoch,
                follow=args.follow,
                interval_seconds=args.interval_seconds,
                max_events=args.max_events,
            )
        if args.command == "restore":
            if not args.database:
                raise ContractError("restore requires --database")
            destination = Path(args.database)
            if destination.is_symlink() or not destination.parent.is_dir():
                raise ContractError(
                    "restore requires an existing trusted directory and a nonsymlink leaf"
                )
            restore_database(args.source, destination)
            print(canonical({"restored": True, "database": str(destination)}))
            return 0
        if args.command == "verify-bundle":
            mac_key = (
                load_evidence_key(args.evidence_key_file)
                if args.evidence_key_file
                else None
            )
            outcome = verify_bundle(args.file, mac_key)
            print(canonical(outcome))
            return 0 if outcome["ok"] else 2
        if args.command == "check":
            result = run_check(transport_config=_transport_config(args, "check"))
            print(canonical(result))
            return 0 if result["ok"] else 2
        if not args.registry or not args.database:
            raise ContractError("this command requires --registry and --database")
        path = Path(args.database)
        if path.is_symlink() or not path.parent.is_dir():
            raise ContractError(
                "database requires an existing trusted directory and a nonsymlink leaf"
            )
        mac_key = (
            load_evidence_key(args.evidence_key_file)
            if args.evidence_key_file
            else None
        )
        engine = Engine(load_registry(args.registry), path, mac_key=mac_key)
        if args.command == "assure":
            result = run_assurance(
                engine,
                transport_config=_transport_config(args, "assure"),
                probe=default_live_probe(engine.registry) if args.live else None,
                wait_seconds=args.wait_seconds,
            )
            print(canonical(result))
            return 0 if result["ok"] else 2
        if args.command == "assure-report":
            outcome = assurance_report(engine, max_age_hours=args.max_age_hours)
            print(canonical(outcome))
            return 2 if outcome["stale"] else 0
        if args.command == "prune":
            counts = engine.prune(datetime.now(UTC), args.older_than_days)
            print(canonical({"pruned": counts}))
            return 0
        if args.command == "backup":
            print(canonical({"backup": engine.backup(args.out)}))
            return 0
        if args.command == "incidents":
            print(canonical(incidents(engine, args.gap_seconds)))
            return 0
        if args.command == "bundle":
            print(canonical({"bundle": build_bundle(engine, args.out)}))
            return 0
        if args.command == "ingest":
            errors = 0
            with Path(args.events).open("rb") as handle:
                line_number = 0
                while True:
                    line = handle.readline(65537)
                    if not line:
                        break
                    line_number += 1
                    if line_number > 100000:
                        raise ContractError(
                            "one ingest run is limited to 100000 records"
                        )
                    if len(line) > 65536:
                        raise ContractError(
                            f"record {line_number} exceeds 64 KiB; ingestion stopped"
                        )
                    try:
                        result = engine.process(parse_json(line), datetime.now(UTC))
                    except ContractError as exc:
                        errors += 1
                        print(
                            canonical(
                                {
                                    "decision": "rejected",
                                    "line": line_number,
                                    "error": str(exc),
                                }
                            )
                        )
                    else:
                        print(canonical(result))
            return 2 if errors else 0
        if args.command == "trail-inbox":
            return run_trail_inbox(engine, args.directory)
        if args.command == "deliver":
            if args.format == "splunk" and (
                args.splunk_host is None or args.splunk_port is None
            ):
                raise ContractError(
                    "Splunk delivery requires --splunk-host and --splunk-port"
                )
            if args.format == "wazuh" and args.wazuh_output is None:
                raise ContractError("Wazuh delivery requires --wazuh-output")
            summary = deliver(
                engine,
                args.format,
                datetime.now(UTC),
                splunk_host=args.splunk_host,
                splunk_port=args.splunk_port,
                wazuh_output=args.wazuh_output,
                retry_failed=args.retry_failed,
                limit=args.limit,
                route=args.route,
            )
            summary.update(engine.outbox_report())
            print(canonical(summary))
            return 0 if summary["complete"] else 2
        if args.command == "export-alerts":
            for alert in engine.export_alerts():
                print(canonical({"decision": "alert", "alert": alert}))
        elif args.command == "acknowledge":
            engine.acknowledge(args.alert_id, args.analyst, datetime.now(UTC))
            print(canonical({"alert_id": args.alert_id, "acknowledged": True}))
        elif args.command == "verify-integrity":
            if not args.evidence_key_file:
                raise ContractError("verify-integrity requires --evidence-key-file")
            outcome = engine.verify_integrity()
            print(canonical(outcome))
            return 0 if outcome["ok"] else 2
        else:
            print(canonical(engine.report()))
        return 0
    except (ContractError, OSError, UnicodeError, sqlite3.Error) as exc:
        print(f"Fool's Gold: {exc}", file=sys.stderr)
        return 2
    finally:
        if engine:
            engine.close()


if __name__ == "__main__":
    raise SystemExit(main())
