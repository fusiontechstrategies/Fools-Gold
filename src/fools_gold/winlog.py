"""Windows Security log collector. Local wevtutil queries only.

The XPath query is fixed collector configuration. Events are filtered to
registered decoy locations before emission; unregistered activity stays
in the native log. Collector authenticity must be secured by deployment.
"""

import os
import subprocess

from .collection import windows_events_xml_envelope
from .core import ContractError, Registry, normalize

MAX_BATCH_EVENTS = 128
# Both successful access (4663) and denied handle attempts (4656).
QUERY = "*[System[(EventID=4663 or EventID=4656)]]"
MAX_QUERY_TIMEOUT_SECONDS = 30


def query_security_log(*, max_events=MAX_BATCH_EVENTS, timeout=10) -> bytes:
    """Run one fixed wevtutil query; return UTF-8 XML envelope bytes."""
    if type(max_events) is not int or not 1 <= max_events <= MAX_BATCH_EVENTS:
        raise ContractError("query event limit must be 1 to 128")
    if type(timeout) is not int or not 1 <= timeout <= MAX_QUERY_TIMEOUT_SECONDS:
        raise ContractError("query timeout must be 1 to 30 seconds")
    if os.name != "nt":
        raise ContractError("Windows Security log collection requires Windows")
    completed = subprocess.run(
        [
            "wevtutil",
            "qe",
            "Security",
            f"/q:{QUERY}",
            "/f:xml",
            "/rd:true",
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
    # wevtutil redirected output may arrive as UTF-16; normalize to UTF-8 for
    # the hardened envelope parser, which still enforces bounds and structure.
    try:
        content = completed.stdout.decode("utf-8-sig")
    except UnicodeError:
        try:
            content = completed.stdout.decode("utf-16")
        except UnicodeError as exc:
            raise ContractError("unreadable wevtutil output") from exc
    return content.encode("utf-8")


def collect(registry: Registry, *, log_epoch: str, fetch=None, max_events=MAX_BATCH_EVENTS):
    """Emit contract events for registered decoy locations.

    Returns (events, skipped). Events failing the strict contract are skipped
    and counted, never silently accepted. The caller decides follow-up pacing.
    """
    fetch = fetch or query_security_log
    payload = fetch(max_events=max_events)
    mapped_events = windows_events_xml_envelope(
        payload, log_epoch=log_epoch, max_events=max_events
    )
    events, skipped = [], 0
    for mapped in mapped_events:
        try:
            normalized = normalize(mapped)
        except ContractError:
            skipped += 1
            continue
        if registry.match(normalized) is not None:
            events.append(mapped)
    return events, skipped
