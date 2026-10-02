"""Bounded export adapters. No live collection or credential lookup."""

import json
import re
import xml.etree.ElementTree as ET

from .cli import parse_json
from .core import ContractError, normalize, text

EVENT_NS = "http://schemas.microsoft.com/win/2004/08/events/event"
MAX_EVENT_BYTES = 65536
MAX_EXPORT_BYTES = 1024 * 1024


def windows_event_xml(payload: bytes, *, log_epoch: str) -> dict:
    """Map one genuine Windows Event XML export into the v1 collector contract.

    log_epoch is trusted collector configuration, not an event-provided alias.
    Input is untrusted even though collector authenticity must be secured outside
    this function. DTDs, entities, oversized trees and duplicate fields fail.
    """
    text(log_epoch, "collector log epoch", 128)
    if not isinstance(payload, bytes) or not 0 < len(payload) <= MAX_EVENT_BYTES:
        raise ContractError("Windows XML must be bytes of at most 64 KiB")
    # Require UTF-8. This also prevents declaration scanning bypass via UTF-16.
    try:
        content = payload.decode("utf-8-sig")
    except UnicodeError as exc:
        raise ContractError("Windows XML export must be UTF-8") from exc
    lowered = content.casefold()
    if "<!doctype" in lowered or "<!entity" in lowered:
        raise ContractError("Windows XML DTD/entity declarations are forbidden")
    try:
        root = ET.fromstring(content)
    except (ET.ParseError, ValueError) as exc:
        raise ContractError("invalid Windows XML") from exc
    prefix = "{" + EVENT_NS + "}"
    if root.tag != prefix + "Event":
        raise ContractError("unexpected Windows Event namespace")
    queue = [(root, 0)]
    count = 0
    while queue:
        node, depth = queue.pop()
        count += 1
        if depth > 6 or count > 128:
            raise ContractError("Windows XML tree exceeds depth/element bounds")
        queue.extend((child, depth + 1) for child in node)

    def one(parent, name):
        found = parent.findall(prefix + name)
        if len(found) != 1:
            raise ContractError(f"Windows XML requires one {name}")
        return found[0]

    system = one(root, "System")
    event_data = one(root, "EventData")
    event_id = text(one(system, "EventID").text, "XML event ID", 16)
    if event_id != "4663":
        raise ContractError("Windows XML adapter supports only event 4663")
    keywords = text(one(system, "Keywords").text, "audit keywords", 18)
    if not re.fullmatch(r"0x[0-9a-fA-F]{1,16}", keywords):
        raise ContractError("invalid audit keywords")
    bits = int(keywords, 16)
    # Windows event keyword bits: success 0x0020000000000000,
    # failure 0x0010000000000000. Never infer outcome from EventID alone.
    if not bits & 0x0020000000000000 or bits & 0x0010000000000000:
        raise ContractError(
            "Windows XML must carry Audit Success without Audit Failure"
        )
    fields = {}
    for node in event_data:
        if node.tag != prefix + "Data" or len(node):
            raise ContractError("unexpected Windows EventData child")
        name = text(node.attrib.get("Name"), "EventData name", 128)
        if name in fields:
            raise ContractError("duplicate Windows EventData name")
        # Unused native fields such as AccessList can contain newlines or be
        # empty. Preserve bounded text internally; validate consumed fields below.
        value = node.text or ""
        if len(value) > 2048:
            raise ContractError("Windows EventData value exceeds bounds")
        fields[name] = value
    required = {
        "SubjectUserSid",
        "ObjectType",
        "ObjectName",
        "AccessMask",
        "ProcessName",
    }
    if not required.issubset(fields):
        raise ContractError("Windows XML is missing required EventData")
    for name in required:
        text(fields[name], name, 2048)
    mapped = {
        "source": "windows.security",
        "provider": one(system, "Provider").attrib.get("Name"),
        "channel": one(system, "Channel").text,
        "event_id": 4663,
        "audit_outcome": "success",
        "object_type": fields["ObjectType"],
        "computer": one(system, "Computer").text,
        "log_epoch": log_epoch,
        "record_id": one(system, "EventRecordID").text,
        "time": one(system, "TimeCreated").attrib.get("SystemTime"),
        "subject_sid": fields["SubjectUserSid"],
        "object_name": fields["ObjectName"],
        "access_mask": fields["AccessMask"],
        "process_name": fields["ProcessName"],
    }
    normalize(mapped)
    return mapped


def cloudtrail_export(payload: bytes) -> list[dict]:
    """Unwrap one bounded S3 CloudTrail Records export, failing the whole batch.

    The operator can then inspect unsupported records without accepting a partial
    result as complete coverage. No gzip decompression or S3 fetching occurs.
    """
    if not isinstance(payload, bytes) or not 0 < len(payload) <= MAX_EXPORT_BYTES:
        raise ContractError("CloudTrail export must be bytes of at most 1 MiB")
    try:
        document = parse_json(payload)
    except UnicodeError as exc:
        raise ContractError("CloudTrail export must be UTF-8 JSON") from exc
    if not isinstance(document, dict) or set(document) != {"Records"}:
        raise ContractError("CloudTrail export requires an exact Records envelope")
    records = document["Records"]
    if not isinstance(records, list) or not 1 <= len(records) <= 1000:
        raise ContractError("CloudTrail export requires 1 to 1000 records")
    for record in records:
        if not isinstance(record, dict):
            raise ContractError("CloudTrail record must be an object")
        if len(json.dumps(record, ensure_ascii=True).encode()) > MAX_EVENT_BYTES:
            raise ContractError("CloudTrail record exceeds 64 KiB")
        if normalize(record)["source"] != "aws.cloudtrail.s3":
            raise ContractError("CloudTrail batch contains a different source")
    return records
