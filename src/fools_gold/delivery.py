"""Offline payload adapters and loopback-only mock delivery.

No production URL, token lookup or production sender is implemented.
"""

import http.client
import json
import re

from .core import ContractError, instant, parse_json, required_dict, text

MAX_PACKET_BYTES = 65536


def validate_alert(alert: dict):
    required_dict(alert, "alert")
    if (
        type(alert.get("schema_version")) is not int
        or alert["schema_version"] != 1
        or alert.get("product") != "fools-gold"
    ):
        raise ContractError("delivery requires a Fool's Gold v1 alert")
    if not re.fullmatch(
        r"fg-[0-9a-f]{32}", text(alert.get("alert_id"), "alert id", 64)
    ):
        raise ContractError("invalid alert id")
    for field in ("decoy_id", "owner", "response_procedure"):
        text(alert.get(field), field)
    if alert.get("route") is not None:
        text(alert["route"], "alert route", 64)
    techniques = alert.get("mitre_techniques")
    if techniques is not None and (
        not isinstance(techniques, list)
        or any(
            not isinstance(name, str)
            or not re.fullmatch(r"T[0-9]{4}(\.[0-9]{3})?", name)
            for name in techniques
        )
    ):
        raise ContractError("invalid technique tags")
    event = required_dict(alert.get("event"), "normalized event")
    if text(event.get("source"), "event source", 64) not in {
        "windows.security",
        "aws.cloudtrail.s3",
        "linux.audit",
    }:
        raise ContractError("invalid normalized event source")
    if type(event.get("schema_version")) is not int or event["schema_version"] != 1:
        raise ContractError("invalid normalized event schema")
    if event.get("outcome") not in ("success", "denied"):
        raise ContractError("invalid normalized event outcome")
    for field in ("id", "actor", "time"):
        text(event.get(field), field)
    instant(event["time"])
    instant(alert.get("observed_at"))
    if (
        not isinstance(event.get("actions"), list)
        or not event["actions"]
        or any(
            action not in ("read", "write", "append", "delete", "recon")
            for action in event["actions"]
        )
    ):
        raise ContractError("invalid normalized actions")
    return event


def packet(value) -> bytes:
    try:
        payload = json.dumps(
            value, ensure_ascii=True, allow_nan=False, separators=(",", ":")
        ).encode()
    except (ValueError, TypeError, RecursionError) as exc:
        raise ContractError("delivery packet cannot be serialized") from exc
    if len(payload) > MAX_PACKET_BYTES:
        raise ContractError("delivery packet exceeds 64 KiB")
    return payload


def splunk_hec_packet(alert: dict) -> bytes:
    event = validate_alert(alert)
    return packet(
        {
            "time": instant(event["time"]).timestamp(),
            "source": "fools-gold",
            "sourcetype": "fools_gold:alert:json",
            "event": alert,
        }
    )


def wazuh_json_record(alert: dict) -> bytes:
    event = validate_alert(alert)
    # A flat record avoids unsupported arrays of objects in JSON decoder paths.
    return (
        packet(
            {
                "fg_product": "fools-gold",
                "fg_alert_id": alert["alert_id"],
                "fg_decoy_id": alert["decoy_id"],
                "fg_owner": alert["owner"],
                "fg_source": event["source"],
                "fg_actor": event["actor"],
                "fg_actions": ",".join(event["actions"]),
                "fg_event_id": event["id"],
                "fg_event_time": event["time"],
                "fg_observed_at": alert["observed_at"],
                "fg_outcome": event["outcome"],
                "fg_route": alert.get("route") or "",
                "fg_mitre": ",".join(alert.get("mitre_techniques") or []),
                "fg_runbook": alert["response_procedure"],
            }
        )
        + b"\n"
    )


def send_splunk_mock(alert: dict, *, port: int) -> dict:
    """One local mock POST. Fixed host/token/path; no redirects or retries.

    Success describes only mock transport receipt. It does not establish indexing
    or analyst acknowledgment. A non-success response raises, never marks success.
    """
    if type(port) is not int or not 1024 <= port <= 65535:
        raise ContractError("mock port must be an integer from 1024 to 65535")
    body = splunk_hec_packet(alert)
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=1)
    try:
        connection.request(
            "POST",
            "/services/collector/event",
            body,
            {
                "Content-Type": "application/json",
                "Authorization": "Splunk synthetic-offline-token",
            },
        )
        response = connection.getresponse()
        content = response.read(4097)
        if response.status != 200 or len(content) > 4096:
            raise ContractError(
                "mock receiver rejected the packet or exceeded response bounds"
            )
        try:
            result = parse_json(content)
        except (ValueError, UnicodeError) as exc:
            raise ContractError("mock receiver returned invalid JSON") from exc
        if (
            not isinstance(result, dict)
            or type(result.get("code")) is not int
            or result["code"] != 0
        ):
            raise ContractError("mock receiver did not confirm acceptance")
        return {
            "alert_id": alert["alert_id"],
            "transport": "loopback_mock",
            "accepted": True,
            "indexing_verified": False,
            "analyst_acknowledged": False,
        }
    except (OSError, http.client.HTTPException) as exc:
        raise ContractError("local mock transport failed") from exc
    finally:
        connection.close()
