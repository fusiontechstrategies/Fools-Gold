"""Windows Security log collector. Local wevtutil queries only.

The XPath query is fixed collector configuration. Events are filtered to
registered decoy locations before emission; unregistered activity stays in
the native log. Collector authenticity must be secured by deployment.

Follow mode pages from a durable EventRecordID cursor, reports coverage gaps
on log rollover/clear, and never changes audit policy.
"""

import os
import re
import subprocess
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from .collection import (
    MAX_ENVELOPE_BYTES,
    windows_events_batch,
    windows_record_fingerprints,
)
from .core import (
    ContractError,
    Registry,
    canonical,
    instant,
    normalize,
    parse_json,
    stamp,
)

MAX_BATCH_EVENTS = 128
MAX_QUERY_TIMEOUT_SECONDS = 30
MAX_STATE_BYTES = 4096
QUERY = "*[System[(EventID=4663 or EventID=4656)]]"


def spool_page(directory, events) -> Path | None:
    """Publish a durable, complete page before its cursor can be committed.

    A crash after publication but before cursor commit can replay a page, which
    ingestion deduplicates. It cannot skip a page whose output was discarded.
    """
    folder = Path(directory)
    if folder.is_symlink() or not folder.is_dir():
        raise ContractError("collector spool requires an existing trusted directory")
    if not events:
        return None
    descriptor, name = tempfile.mkstemp(
        prefix="events-", suffix=".jsonl.tmp", dir=folder
    )
    temporary = Path(name)
    target = temporary.with_suffix("")
    try:
        with os.fdopen(descriptor, "wb") as writer:
            for event in events:
                writer.write((canonical(event) + "\n").encode("utf-8"))
            writer.flush()
            os.fsync(writer.fileno())
        os.replace(temporary, target)
    except OSError as exc:
        temporary.unlink(missing_ok=True)
        raise ContractError("collector could not persist its spool page") from exc
    return target


def decode_query_output(raw: bytes) -> bytes:
    """Normalize wevtutil output (UTF-8 or UTF-16) to UTF-8 for the parser."""
    if not isinstance(raw, bytes) or len(raw) > MAX_ENVELOPE_BYTES:
        raise ContractError("wevtutil output exceeds bounds")
    for encoding in ("utf-8-sig", "utf-16"):
        try:
            return raw.decode(encoding).encode("utf-8")
        except UnicodeError:
            continue
    raise ContractError("unreadable wevtutil output")


def query_security_log(
    *,
    max_events=MAX_BATCH_EVENTS,
    timeout=10,
    since_record_id=None,
    newest_first=False,
    record_id=None,
) -> bytes:
    """Run one fixed wevtutil query; return UTF-8 output bytes.

    Normal collection pages oldest-first from the cursor so bursts larger than
    one batch are not missed. The newest-first form is used only for the
    rollover probe when a cursor query returns nothing.
    """
    if type(max_events) is not int or not 1 <= max_events <= MAX_BATCH_EVENTS:
        raise ContractError("query event limit must be 1 to 128")
    if type(timeout) is not int or not 1 <= timeout <= MAX_QUERY_TIMEOUT_SECONDS:
        raise ContractError("query timeout must be 1 to 30 seconds")
    if type(newest_first) is not bool:
        raise ContractError("newest_first must be a boolean")
    if since_record_id is not None and (
        type(since_record_id) is not int or since_record_id < 0
    ):
        raise ContractError("cursor must be a nonnegative integer")
    if record_id is not None and (type(record_id) is not int or record_id < 0):
        raise ContractError("record id must be a nonnegative integer")
    if record_id is not None and since_record_id is not None:
        raise ContractError("record id and cursor queries are mutually exclusive")
    query = QUERY
    if record_id is not None:
        query = (
            "*[System[(EventID=4663 or EventID=4656) and "
            f"EventRecordID = {record_id}]]"
        )
    elif since_record_id is not None:
        query = (
            "*[System[(EventID=4663 or EventID=4656) and "
            f"EventRecordID > {since_record_id}]]"
        )
    if os.name != "nt":
        raise ContractError("Windows Security log collection requires Windows")
    completed = subprocess.run(
        [
            "wevtutil",
            "qe",
            "Security",
            f"/q:{query}",
            "/f:xml",
            "/rd:true" if newest_first else "/rd:false",
            f"/c:{max_events}",
        ],
        capture_output=True,
        timeout=timeout,
        shell=False,
    )
    if completed.returncode != 0:
        raise ContractError(
            f"wevtutil query failed with status {completed.returncode}"
        )
    return decode_query_output(completed.stdout)


def collect(
    registry: Registry,
    *,
    log_epoch: str,
    fetch=None,
    max_events=MAX_BATCH_EVENTS,
    since_record_id=None,
):
    """Emit contract events for registered decoy locations on this page.

    Returns (events, report) where report carries fetched/skipped counts, the
    observed record-id range, the next cursor, and a rollover flag.
    """
    fetch = fetch or query_security_log
    payload = fetch(
        max_events=max_events,
        since_record_id=since_record_id,
        newest_first=False,
    )
    mapped, skipped, observed, total = windows_events_batch(
        payload, log_epoch=log_epoch, max_events=max_events
    )
    fingerprints = windows_record_fingerprints(payload)
    rolled_over = False
    if since_record_id is not None and total == 0:
        # A cursor query returning nothing can mean the log was cleared and
        # record ids restarted. Probe the newest records to detect the gap.
        probe = fetch(
            max_events=max_events,
            since_record_id=None,
            newest_first=True,
        )
        _, _, probe_observed, _ = windows_events_batch(
            probe, log_epoch=log_epoch, max_events=max_events
        )
        probe_fingerprints = windows_record_fingerprints(probe)
        # Rollover means record ids went *backwards* (clear/reset). Ordinary
        # inactivity returns the same or older ids than the cursor but must not
        # be treated as a gap.
        rolled_over = bool(probe_observed) and max(probe_observed) < since_record_id
        observed = probe_observed if rolled_over else observed
        fingerprints = probe_fingerprints if rolled_over else fingerprints
    events = []
    for item in mapped:
        try:
            normalized = normalize(item)
        except ContractError:
            skipped += 1
            continue
        if registry.match(normalized) is not None:
            events.append(item)
    next_since = max(observed) if observed else since_record_id
    return events, {
        "fetched": total,
        "skipped": skipped,
        "observed_min": min(observed) if observed else None,
        "next_since": next_since,
        "cursor_fingerprint": fingerprints.get(next_since),
        "rolled_over": rolled_over,
    }


def load_state(path) -> dict:
    """Read a durable collector cursor. Missing state means no cursor."""
    if path is None:
        return {}
    state_path = Path(path)
    if state_path.is_symlink():
        raise ContractError("collector state must not be a symlink")
    if not state_path.exists():
        return {}
    with state_path.open("rb") as handle:
        payload = handle.read(MAX_STATE_BYTES + 1)
    if len(payload) > MAX_STATE_BYTES:
        raise ContractError("collector state exceeds bounds")
    document = parse_json(payload)
    required = {"log_epoch", "last_record_id", "updated_at"}
    allowed = required | {"generation", "cursor_fingerprint"}
    if (
        not isinstance(document, dict)
        or not required <= set(document)
        or not set(document) <= allowed
    ):
        raise ContractError("collector state has an unexpected shape")
    if not isinstance(document["log_epoch"], str) or not document["log_epoch"]:
        raise ContractError("collector state has an invalid log epoch")
    cursor = document["last_record_id"]
    if cursor is not None and (type(cursor) is not int or cursor < 0):
        raise ContractError("collector state has an invalid cursor")
    generation = document.get("generation", 0)
    if type(generation) is not int or generation < 0:
        raise ContractError("collector state has an invalid generation")
    cursor_fingerprint = document.get("cursor_fingerprint")
    if cursor_fingerprint is not None and (
        not isinstance(cursor_fingerprint, str)
        or not re.fullmatch(r"[0-9a-f]{64}", cursor_fingerprint)
    ):
        raise ContractError("collector state has an invalid cursor fingerprint")
    instant(document["updated_at"])
    return {**document, "generation": generation}


def save_state(path, state: dict, now=None) -> None:
    """Atomically persist the cursor with restrictive permissions."""
    if path is None:
        return
    state_path = Path(path)
    if state_path.is_symlink() or not state_path.parent.is_dir():
        raise ContractError(
            "collector state requires an existing trusted directory and a nonsymlink leaf"
        )
    payload = canonical(
        {
            "log_epoch": state.get("log_epoch"),
            "last_record_id": state.get("last_record_id"),
            "generation": state.get("generation", 0),
            "cursor_fingerprint": state.get("cursor_fingerprint"),
            "updated_at": stamp(now or datetime.now(UTC)),
        }
    ).encode()
    temporary = state_path.with_suffix(state_path.suffix + ".tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0)
    descriptor = (
        os.open(temporary, flags, 0o600)
        if os.name != "nt"
        else os.open(temporary, flags)
    )
    try:
        written = 0
        while written < len(payload):
            written += os.write(descriptor, payload[written:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, state_path)
