"""Explicit offline commands. No command deploys or transmits telemetry."""

from __future__ import annotations

import argparse
import json
import math
import os
import sqlite3
import sys
from datetime import UTC, datetime
from pathlib import Path

from .core import ContractError, Engine, Registry, canonical


def no_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ContractError("duplicate JSON object key")
        result[key] = value
    return result


def parse_json(data):
    try:
        value = json.loads(
            data,
            object_pairs_hook=no_duplicate_keys,
            parse_constant=lambda _: (_ for _ in ()).throw(
                ContractError("nonfinite JSON number")
            ),
        )
        pending = [(value, 0)]
        nodes = 0
        while pending:
            node, depth = pending.pop()
            nodes += 1
            if depth > 32 or nodes > 100000:
                raise ContractError("JSON exceeds depth/node limits")
            if isinstance(node, float) and not math.isfinite(node):
                raise ContractError("nonfinite JSON number")
            if isinstance(node, dict):
                pending.extend((child, depth + 1) for child in node.values())
            elif isinstance(node, list):
                pending.extend((child, depth + 1) for child in node)
        return value
    except (ValueError, RecursionError) as exc:
        raise ContractError("invalid JSON input") from exc


def load_registry(path):
    with Path(path).open("rb") as handle:
        payload = handle.read(1024 * 1024 + 1)
    if len(payload) > 1024 * 1024:
        raise ContractError("registry exceeds 1 MiB")
    return Registry(parse_json(payload))


def main(argv=None):
    parser = argparse.ArgumentParser(description="Fool's Gold offline detection pilot")
    parser.add_argument("--registry", required=True)
    parser.add_argument(
        "--database", required=True, help="Protected local SQLite evidence database"
    )
    commands = parser.add_subparsers(dest="command", required=True)
    ingest = commands.add_parser(
        "ingest", help="Read JSONL events; print decision JSONL"
    )
    ingest.add_argument("events")
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
    args = parser.parse_args(argv)
    engine = None
    try:
        # Protect new POSIX runtime files. Windows deployment requires explicit ACLs.
        if os.name != "nt":
            os.umask(0o077)
        path = Path(args.database)
        if path.is_symlink() or not path.parent.is_dir():
            raise ContractError(
                "database requires an existing trusted directory and a nonsymlink leaf"
            )
        engine = Engine(load_registry(args.registry), path)
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
        if args.command == "export-alerts":
            for alert in engine.export_alerts():
                print(canonical({"decision": "alert", "alert": alert}))
        elif args.command == "acknowledge":
            engine.acknowledge(args.alert_id, args.analyst, datetime.now(UTC))
            print(canonical({"alert_id": args.alert_id, "acknowledged": True}))
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
