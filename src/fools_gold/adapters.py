"""Offline export conversion and packet rendering. No sender command exists."""

import argparse
import sys
from pathlib import Path

from .cli import parse_json
from .collection import (
    MAX_EVENT_BYTES,
    MAX_EXPORT_BYTES,
    cloudtrail_export,
    windows_event_xml,
)
from .core import ContractError, canonical, required_dict
from .delivery import splunk_hec_packet, wazuh_json_record


def bounded_read(path, limit):
    with Path(path).open("rb") as handle:
        data = handle.read(limit + 1)
    if len(data) > limit:
        raise ContractError("export exceeds input size limit")
    return data


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Fool's Gold offline collection and payload adapters"
    )
    commands = parser.add_subparsers(dest="command", required=True)
    windows = commands.add_parser(
        "windows-export", help="Convert one UTF-8 4663 XML export"
    )
    windows.add_argument("file")
    windows.add_argument("--log-epoch", required=True)
    cloud = commands.add_parser(
        "cloudtrail-export", help="Validate and unwrap a Records export"
    )
    cloud.add_argument("file")
    render = commands.add_parser(
        "render-alerts", help="Render alert decisions; does not deliver"
    )
    render.add_argument("file")
    render.add_argument("--format", choices=("wazuh", "splunk"), required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "windows-export":
            event = windows_event_xml(
                bounded_read(args.file, MAX_EVENT_BYTES), log_epoch=args.log_epoch
            )
            print(canonical(event))
        elif args.command == "cloudtrail-export":
            events = cloudtrail_export(bounded_read(args.file, MAX_EXPORT_BYTES))
            for event in events:
                print(canonical(event))
        else:
            renderer = (
                wazuh_json_record if args.format == "wazuh" else splunk_hec_packet
            )
            with Path(args.file).open("rb") as handle:
                count = 0
                while True:
                    line = handle.readline(MAX_EVENT_BYTES + 1)
                    if not line:
                        break
                    count += 1
                    if count > 100000 or len(line) > MAX_EVENT_BYTES:
                        raise ContractError(
                            "decision stream exceeds record/count limits"
                        )
                    decision = required_dict(parse_json(line), "decision")
                    kind = decision.get("decision")
                    if kind == "alert":
                        print(
                            renderer(decision.get("alert")).decode("ascii").rstrip("\n")
                        )
                    elif kind not in ("expected_access", "unmatched", "duplicate"):
                        raise ContractError(
                            "decision stream contains a rejection or unknown decision; inspect before rendering"
                        )
        return 0
    except (ContractError, OSError, UnicodeError) as exc:
        print(f"Fool's Gold adapter: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
