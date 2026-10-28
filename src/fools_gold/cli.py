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
from .config import load_profile
from .core import (
    ContractError,
    Engine,
    Registry,
    canonical,
    no_duplicate_keys,  # noqa: F401  (re-exported compatibility surface)
    parse_json,
    restore_database,
)
from .doctor import run_doctor
from .onboarding import create_demo, write_decoy, write_key, write_registry
from .reporting import build_bundle, incidents, verify_bundle
from .trail_inbox import MAX_INBOX_BYTES, cloudtrail_records_file
from .transport import deliver
from .ui import make_server


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
    registry: Registry,
    *,
    log_epoch,
    follow,
    interval_seconds,
    max_events,
    state_file=None,
    pages_per_cycle=10,
    fetch=None,
):
    from .winlog import collect, load_state, save_state

    if type(pages_per_cycle) is not int or not 1 <= pages_per_cycle <= 50:
        raise ContractError("--pages-per-cycle must be 1 to 50")
    state = load_state(state_file) if state_file else {}
    if state_file and state.get("log_epoch") not in (None, log_epoch):
        print(
            "Fool's Gold collector: log epoch changed; restarting from the "
            "newest event",
            file=sys.stderr,
        )
        state = {"log_epoch": log_epoch, "last_record_id": None}
    try:
        while True:
            since = state.get("last_record_id")
            for _ in range(pages_per_cycle):
                events, report = collect(
                    registry,
                    log_epoch=log_epoch,
                    fetch=fetch,
                    max_events=max_events,
                    since_record_id=since,
                )
                for event in events:
                    print(canonical(event))
                if report["skipped"]:
                    print(
                        "Fool's Gold collector: skipped "
                        f"{report['skipped']} unsupported event(s)",
                        file=sys.stderr,
                    )
                if report["rolled_over"]:
                    print(
                        "Fool's Gold collector: coverage gap - log rollover "
                        f"detected (cursor {since}, observed "
                        f"{report['observed_min']})",
                        file=sys.stderr,
                    )
                    since = 0
                else:
                    since = report["next_since"]
                state = {"log_epoch": log_epoch, "last_record_id": since}
                if state_file:
                    save_state(state_file, state)
                if report["fetched"] < max_events and not report["rolled_over"]:
                    break
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
    parser.add_argument(
        "--profile",
        help="JSON profile with non-secret defaults (CLI arguments win)",
    )
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
    collector.add_argument(
        "--state-file",
        help="Durable EventRecordID cursor file for restart recovery",
    )
    collector.add_argument(
        "--pages-per-cycle", type=int, default=10, help="Bounded catch-up pages"
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
        "--destination", help="Named destination registered with `destination add`"
    )
    deliver_parser.add_argument("--format", choices=("wazuh", "splunk"))
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
    report.add_argument("--require-mode", choices=("canary", "live"))
    accept = commands.add_parser(
        "accept",
        help="Record operator confirmation of ingestion or analyst acknowledgment",
    )
    accept.add_argument(
        "--stage",
        choices=("ingestion", "analyst_acknowledgment"),
        required=True,
    )
    accept.add_argument("--note", required=True)
    accept.add_argument("--actor", required=True)
    destination_parser = commands.add_parser(
        "destination", help="Manage named delivery destinations"
    )
    destination_commands = destination_parser.add_subparsers(
        dest="destination_command", required=True
    )
    destination_add = destination_commands.add_parser("add")
    destination_add.add_argument("--name", required=True)
    destination_add.add_argument(
        "--format", choices=("wazuh", "splunk"), required=True
    )
    destination_add.add_argument("--host")
    destination_add.add_argument("--port", type=int)
    destination_add.add_argument("--path")
    destination_commands.add_parser("list")
    route_parser = commands.add_parser(
        "route", help="Manage route-to-destination mappings"
    )
    route_commands = route_parser.add_subparsers(
        dest="route_command", required=True
    )
    route_map = route_commands.add_parser("map")
    route_map.add_argument("--route", required=True)
    route_map.add_argument("--destination", required=True)
    route_commands.add_parser("list")
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
    doctor = commands.add_parser(
        "doctor", help="Check local deployment readiness"
    )
    doctor.add_argument("--inbox", help="Trail inbox directory to check")
    doctor.add_argument("--max-assurance-hours", type=int)
    doctor.add_argument("--assurance-mode", choices=("canary", "live"))
    doctor.add_argument("--max-collection-hours", type=int)
    init = commands.add_parser(
        "init", help="Write a starter registry (and optional evidence key)"
    )
    init.add_argument("--out", required=True)
    init.add_argument("--owner", required=True)
    init.add_argument("--s3-bucket")
    init.add_argument("--s3-key")
    init.add_argument("--s3-account")
    init.add_argument("--s3-region", default="us-gov-west-1")
    init.add_argument("--windows-host")
    init.add_argument("--windows-path")
    init.add_argument("--linux-host")
    init.add_argument("--linux-path")
    init.add_argument("--write-key", action="store_true")
    plant = commands.add_parser(
        "plant", help="Write a watermarked synthetic decoy file"
    )
    plant.add_argument(
        "--type",
        choices=("aws-credentials", "ssh-key", "config-export"),
        required=True,
    )
    plant.add_argument("--out", required=True)
    plant.add_argument("--force", action="store_true")
    demo = commands.add_parser(
        "demo", help="Create a self-contained synthetic demo with an HTML report"
    )
    demo.add_argument("--out", default="runtime/demo")
    serve = commands.add_parser(
        "serve", help="Serve the loopback dashboard (bearer token required)"
    )
    serve.add_argument("--port", type=int, default=8080)
    serve.add_argument("--token-file")
    args = parser.parse_args(argv)
    engine = None
    try:
        # Protect new POSIX runtime files. Windows deployment requires explicit ACLs.
        if os.name != "nt":
            os.umask(0o077)
        if args.profile:
            for name, value in load_profile(args.profile).items():
                if getattr(args, name, None) is None:
                    setattr(args, name, value)
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
                state_file=args.state_file,
                pages_per_cycle=args.pages_per_cycle,
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
        if args.command == "init":
            s3 = None
            if args.s3_bucket:
                if not (args.s3_key and args.s3_account):
                    raise ContractError(
                        "init S3 decoy requires --s3-key and --s3-account"
                    )
                s3 = {
                    "bucket": args.s3_bucket,
                    "key": args.s3_key,
                    "account": args.s3_account,
                    "region": args.s3_region,
                }
            windows = None
            if args.windows_host or args.windows_path:
                if not (args.windows_host and args.windows_path):
                    raise ContractError(
                        "init Windows decoy requires --windows-host and --windows-path"
                    )
                windows = {"host": args.windows_host, "path": args.windows_path}
            linux_decoy = None
            if args.linux_host or args.linux_path:
                if not (args.linux_host and args.linux_path):
                    raise ContractError(
                        "init Linux decoy requires --linux-host and --linux-path"
                    )
                linux_decoy = {"host": args.linux_host, "path": args.linux_path}
            outputs = {
                "registry": write_registry(
                    args.out,
                    owner=args.owner,
                    s3=s3,
                    windows=windows,
                    linux=linux_decoy,
                )
            }
            if args.write_key:
                outputs["key"] = write_key(args.out)
            print(canonical(outputs))
            return 0
        if args.command == "plant":
            print(
                canonical(
                    {"decoy": write_decoy(args.type, args.out, force=args.force)}
                )
            )
            return 0
        if args.command == "demo":
            print(canonical(create_demo(args.out)))
            return 0
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
        engine = Engine(
            load_registry(args.registry),
            path,
            mac_key=mac_key,
            thread_safe=args.command == "serve",
        )
        if args.command == "doctor":
            outcome = run_doctor(
                engine,
                inbox=args.inbox,
                max_assurance_hours=args.max_assurance_hours,
                assurance_mode=args.assurance_mode,
                max_collection_hours=args.max_collection_hours,
            )
            print(canonical(outcome))
            return 0 if outcome["ok"] else 2
        if args.command == "serve":
            token = ""
            if args.token_file:
                with Path(args.token_file).open("rb") as handle:
                    token = handle.read(257).decode("ascii", "replace").strip()
            else:
                token = os.environ.get("FG_UI_TOKEN", "")
            server = make_server(engine, token, args.port)
            host, port = server.server_address
            print(
                f"Fool's Gold dashboard: http://{host}:{port}/",
                file=sys.stderr,
            )
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                pass
            finally:
                server.server_close()
            return 0
        if args.command == "assure":
            result = run_assurance(
                engine,
                transport_config=_transport_config(args, "assure"),
                probe=(
                    (lambda: default_live_probe(engine.registry))
                    if args.live
                    else None
                ),
                wait_seconds=args.wait_seconds,
            )
            print(canonical(result))
            return 0 if result["ok"] else 2
        if args.command == "assure-report":
            outcome = assurance_report(
                engine,
                max_age_hours=args.max_age_hours,
                require_mode=args.require_mode,
            )
            print(canonical(outcome))
            return 2 if outcome["stale"] else 0
        if args.command == "accept":
            acceptance_id = engine.record_acceptance(
                datetime.now(UTC), args.stage, args.note, args.actor
            )
            print(
                canonical(
                    {
                        "accepted": True,
                        "id": acceptance_id,
                        "stage": args.stage,
                    }
                )
            )
            return 0
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
            if bool(args.destination) == bool(args.format):
                raise ContractError(
                    "deliver requires exactly one of --destination or --format"
                )
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
                args.destination or args.format,
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
        if args.command == "destination":
            if args.destination_command == "add":
                engine.add_destination(
                    datetime.now(UTC),
                    args.name,
                    args.format,
                    host=args.host,
                    port=args.port,
                    path=args.path,
                )
                print(canonical({"destination": args.name, "format": args.format}))
            else:
                print(canonical({"destinations": engine.destinations()}))
            return 0
        if args.command == "route":
            if args.route_command == "map":
                engine.map_route(datetime.now(UTC), args.route, args.destination)
                print(
                    canonical(
                        {"route": args.route, "destination": args.destination}
                    )
                )
            else:
                print(canonical({"routes": engine.routes()}))
            return 0
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
