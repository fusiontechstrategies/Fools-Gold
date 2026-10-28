"""Explicit production delivery. Runs only when the operator supplies an endpoint.

Delivery is always an operator-initiated command with operator-selected
arguments. Tokens come from the environment, never source or telemetry.
Failures are recorded durably and never appear as analyst acknowledgment.
"""

import http.client
import os
import ssl
import time
from pathlib import Path

from .core import ContractError, parse_json, required_dict, text
from .delivery import splunk_hec_packet, wazuh_json_record
from .diagnostics import log as log_event

MAX_RESPONSE_BYTES = 4096
SEND_INTERVAL_SECONDS = 0.25
MAX_ATTEMPTS = 3
BACKOFF_SECONDS = (1.0, 2.0)
HEC_PATH = "/services/collector/event"
TOKEN_VARIABLE = "FG_SPLUNK_HEC_TOKEN"


def _valid_token(value) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 256
        or any(ord(c) < 32 for c in value)
    ):
        raise ContractError(
            f"{TOKEN_VARIABLE} must contain a bounded printable token"
        )
    return value


def hec_token() -> str:
    return _valid_token(os.environ.get(TOKEN_VARIABLE, ""))


def _https_factory(host: str, port: int):
    # Production delivery is intentionally HTTPS: the default context keeps
    # hostname and certificate-chain verification enabled with no bypass.
    # (Suppression below is justified by that verified-TLS construction.)
    return http.client.HTTPSConnection(  # nosemgrep: python.lang.security.audit.httpsconnection-detected.httpsconnection-detected
        host, port, timeout=5, context=ssl.create_default_context()
    )


def post_hec(host: str, port: int, token: str, body: bytes, *, connection_factory=None):
    """One HTTPS HEC POST. Fixed path, no redirects, bounded response."""
    host = text(host, "Splunk host", 255)
    if "/" in host or "\\" in host or host.strip(".") != host or not host:
        raise ContractError("Splunk host must be a bare hostname or address")
    if type(port) is not int or not 1 <= port <= 65535:
        raise ContractError("Splunk port must be an integer from 1 to 65535")
    factory = connection_factory or _https_factory
    connection = factory(host, port)
    try:
        connection.request(
            "POST",
            HEC_PATH,
            body,
            {
                "Content-Type": "application/json",
                "Authorization": f"Splunk {token}",
            },
        )
        response = connection.getresponse()
        content = response.read(MAX_RESPONSE_BYTES + 1)
        if response.status != 200 or len(content) > MAX_RESPONSE_BYTES:
            raise ContractError(
                "Splunk HEC rejected the packet or exceeded response bounds"
            )
        try:
            result = parse_json(content)
        except (ValueError, UnicodeError) as exc:
            raise ContractError("Splunk HEC returned invalid JSON") from exc
        required_dict(result, "Splunk HEC response")
        if type(result.get("code")) is not int or result["code"] != 0:
            raise ContractError("Splunk HEC did not confirm acceptance")
    except (OSError, http.client.HTTPException) as exc:
        raise ContractError("Splunk HEC transport failed") from exc
    finally:
        connection.close()


def wazuh_append(path, packet: bytes):
    """Append one rendered record to a protected operator-selected local file.

    A successful append is file delivery only. It never establishes manager
    ingestion, alerting or analyst acknowledgment.
    """
    target = Path(path)
    if target.is_symlink() or not target.parent.is_dir():
        raise ContractError(
            "Wazuh output requires an existing trusted directory and a nonsymlink leaf"
        )
    # O_BINARY prevents Windows CRLF translation from rewriting JSONL delimiters.
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_BINARY", 0)
    try:
        if os.name != "nt":
            # Protect a newly created transport file on POSIX; Windows needs ACLs.
            descriptor = os.open(target, flags, 0o600)
        else:
            descriptor = os.open(target, flags)
    except OSError as exc:
        raise ContractError("Wazuh output could not be opened") from exc
    try:
        written = 0
        while written < len(packet):
            try:
                count = os.write(descriptor, packet[written:])
            except OSError as exc:
                raise ContractError("Wazuh output write failed") from exc
            if count <= 0:
                raise ContractError("Wazuh output made no write progress")
            written += count
        try:
            os.fsync(descriptor)
        except OSError as exc:
            raise ContractError("Wazuh output fsync failed") from exc
    finally:
        try:
            os.close(descriptor)
        except OSError:
            pass


def resolve_destination(
    engine,
    destination: str,
    *,
    splunk_host=None,
    splunk_port=None,
    wazuh_output=None,
) -> dict:
    """Resolve a stored destination, or an ad-hoc legacy format destination."""
    spec = engine.destination(destination)
    if spec is not None:
        return spec
    if destination == "splunk" and splunk_host is not None and splunk_port is not None:
        return {
            "name": destination,
            "payload_format": "splunk",
            "host": splunk_host,
            "port": splunk_port,
            "path": None,
        }
    if destination == "wazuh" and wazuh_output is not None:
        return {
            "name": destination,
            "payload_format": "wazuh",
            "host": None,
            "port": None,
            "path": wazuh_output,
        }
    raise ContractError(
        "unknown delivery destination; add it with `destination add` or supply "
        "the legacy --format options"
    )


def deliver(
    engine,
    destination: str,
    now,
    *,
    splunk_host=None,
    splunk_port=None,
    wazuh_output=None,
    token=None,
    connection_factory=None,
    retry_failed=False,
    limit=64,
    route=None,
) -> dict:
    """Send pending outbox packets for one destination; stop at first failure.

    connection_factory exists for loopback tests only. Production delivery
    always uses verified HTTPS; no insecure context is selectable here.
    """
    spec = resolve_destination(
        engine,
        destination,
        splunk_host=splunk_host,
        splunk_port=splunk_port,
        wazuh_output=wazuh_output,
    )
    payload_format = spec["payload_format"]
    if route is not None:
        mapped = engine.route_destination(route)
        if mapped is not None and mapped != destination:
            raise ContractError(
                f"route {route} is mapped to destination {mapped}"
            )
    if retry_failed:
        engine.outbox_reset_failed(destination, now, route=route)
    engine.outbox_enqueue(destination, now, route=route)
    sent = 0
    if payload_format == "splunk":
        splunk_host = spec["host"]
        splunk_port = spec["port"]
        if splunk_host is None or splunk_port is None:
            raise ContractError("Splunk destination is missing host or port")
        token = hec_token() if token is None else _valid_token(token)
    else:
        wazuh_output = spec["path"]
        if wazuh_output is None:
            raise ContractError("Wazuh destination is missing an output path")
    while True:
        batch = engine.outbox_batch(destination, limit, route=route)
        if not batch:
            break
        for alert_id, alert in batch:
            if sent:
                # Keep at least SEND_INTERVAL_SECONDS between sends, with no
                # trailing sleep after the last packet.
                time.sleep(SEND_INTERVAL_SECONDS)
            packet = (
                splunk_hec_packet(alert)
                if payload_format == "splunk"
                else wazuh_json_record(alert)
            )
            error = None
            for attempt in range(MAX_ATTEMPTS):
                try:
                    if payload_format == "splunk":
                        post_hec(
                            splunk_host,
                            splunk_port,
                            token,
                            packet,
                            connection_factory=connection_factory,
                        )
                    else:
                        wazuh_append(wazuh_output, packet)
                except ContractError as exc:
                    # Each failed attempt is recorded durably so the outbox
                    # reflects every real try, not just the final outcome.
                    engine.outbox_mark(
                        destination, alert_id, "failed", now, error=str(exc)
                    )
                    engine.db.commit()
                    error = str(exc)
                    if attempt + 1 < MAX_ATTEMPTS:
                        time.sleep(BACKOFF_SECONDS[attempt])
                else:
                    error = None
                    break
            if error is not None:
                log_event(
                    "transport",
                    "delivery_failed",
                    destination=destination,
                    format=payload_format,
                    alert_id=alert_id,
                    error=error,
                )
                return {
                    "destination": destination,
                    "format": payload_format,
                    "route": route,
                    "sent": sent,
                    "failed": alert_id,
                    "error": error,
                    "failed_remaining": engine.outbox_failed_count(
                        destination, route=route
                    ),
                    "complete": False,
                }
            engine.outbox_mark(destination, alert_id, "sent", now)
            engine.db.commit()
            sent += 1
    failed_remaining = engine.outbox_failed_count(destination, route=route)
    return {
        "destination": destination,
        "format": payload_format,
        "route": route,
        "sent": sent,
        "failed": None,
        "error": None,
        "failed_remaining": failed_remaining,
        "complete": failed_remaining == 0,
    }
