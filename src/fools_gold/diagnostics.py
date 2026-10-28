"""Structured operational logs with secret redaction."""

import json
import re
import sys
from datetime import UTC, datetime

SECRET_PATTERN = re.compile(
    r"(token|secret|password|passwd|credential|api[_-]?key)", re.IGNORECASE
)
MAX_FIELD = 256


def redact(fields: dict) -> dict:
    cleaned = {}
    for key, value in fields.items():
        if SECRET_PATTERN.search(str(key)):
            cleaned[str(key)] = "[redacted]"
            continue
        text = str(value)
        text = "".join(c if ord(c) >= 32 else " " for c in text)[:MAX_FIELD]
        cleaned[str(key)] = text
    return cleaned


def log(component: str, event: str, *, stream=None, **fields):
    payload = {
        "ts": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "component": component,
        "event": event,
        **redact(fields),
    }
    print(
        json.dumps(payload, sort_keys=True),
        file=stream if stream is not None else sys.stderr,
    )


GUIDANCE = (
    (
        "locked by another Fool's Gold writer",
        "stop the other writer; only one writer may hold a database at a time",
    ),
    (
        "restore source has uncommitted WAL",
        "create the source with `backup` instead of copying a live database",
    ),
    (
        "requires --registry and --database",
        "pass both arguments, or supply a --profile with those paths",
    ),
    (
        "unknown delivery destination",
        "register it with `destination add`, or use the legacy --format options",
    ),
    (
        "requires exactly one of --destination or --format",
        "pick --destination for a registered queue or --format for an ad-hoc send",
    ),
)


def guidance(message: str):
    for needle, text in GUIDANCE:
        if needle in message:
            return text
    return None
