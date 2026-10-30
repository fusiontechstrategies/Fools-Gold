"""Bounded export adapters. No live collection or credential lookup."""

import hashlib
import json
import re

# stdlib ElementTree is a deliberate zero-dependency choice. The pre-scan in
# windows_event_xml rejects DOCTYPE and entity declarations before parsing, so
# XXE and expansion-bomb payloads never reach expat; tree size and depth are
# bounded afterwards. See docs/ADAPTERS.md. defusedxml remains test-only.
import xml.etree.ElementTree as ET  # nosemgrep: python.lang.security.use-defused-xml.use-defused-xml

from .core import ContractError, normalize, parse_json, text

EVENT_NS = "http://schemas.microsoft.com/win/2004/08/events/event"
MAX_EVENT_BYTES = 65536
MAX_EXPORT_BYTES = 1024 * 1024
MAX_ENVELOPE_BYTES = 1024 * 1024
MAX_ENVELOPE_EVENTS = 128


def _hardened_xml(content: str):
    lowered = content.casefold()
    if "<!doctype" in lowered or "<!entity" in lowered:
        raise ContractError("Windows XML DTD/entity declarations are forbidden")
    try:
        return ET.fromstring(content)
    except (ET.ParseError, ValueError) as exc:
        raise ContractError("invalid Windows XML") from exc


def _bounded_element(root, *, max_elements=128, max_depth=6):
    queue = [(root, 0)]
    count = 0
    while queue:
        node, depth = queue.pop()
        count += 1
        if depth > max_depth or count > max_elements:
            raise ContractError("Windows XML tree exceeds depth/element bounds")
        queue.extend((child, depth + 1) for child in node)


def _mapped_from_event_element(root, log_epoch: str) -> dict:
    prefix = "{" + EVENT_NS + "}"

    def one(parent, name):
        found = parent.findall(prefix + name)
        if len(found) != 1:
            raise ContractError(f"Windows XML requires one {name}")
        return found[0]

    system = one(root, "System")
    event_data = one(root, "EventData")
    event_id = text(one(system, "EventID").text, "XML event ID", 16)
    if event_id not in ("4663", "4656"):
        raise ContractError(
            "Windows XML adapter supports only events 4663 and 4656"
        )
    keywords = text(one(system, "Keywords").text, "audit keywords", 18)
    if not re.fullmatch(r"0x[0-9a-fA-F]{1,16}", keywords):
        raise ContractError("invalid audit keywords")
    bits = int(keywords, 16)
    # Windows event keyword bits: success 0x0020000000000000,
    # failure 0x0010000000000000. Never infer outcome from EventID alone.
    success = bool(bits & 0x0020000000000000)
    failure = bool(bits & 0x0010000000000000)
    if event_id == "4663":
        if not success or failure:
            raise ContractError(
                "Windows XML 4663 must carry Audit Success without Audit Failure"
            )
        audit_outcome = "success"
    else:
        # 4656 is the denied-access tripwire; a success-keyword 4656 is not
        # the contract this pilot documents.
        if not failure or success:
            raise ContractError(
                "Windows XML 4656 must carry Audit Failure without Audit Success"
            )
        audit_outcome = "failure"
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
    return {
        "source": "windows.security",
        "provider": one(system, "Provider").attrib.get("Name"),
        "channel": one(system, "Channel").text,
        "event_id": int(event_id),
        "audit_outcome": audit_outcome,
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
    root = _hardened_xml(content)
    prefix = "{" + EVENT_NS + "}"
    if root.tag != prefix + "Event":
        raise ContractError("unexpected Windows Event namespace")
    _bounded_element(root)
    mapped = _mapped_from_event_element(root, log_epoch)
    normalize(mapped)
    return mapped


EVENT_DECLARATION = re.compile(r"<\?xml[^>]*\?>", re.IGNORECASE)
EVENTS_ROOT = re.compile(r"^<Events(?:\s|>)", re.IGNORECASE)


def normalize_events_payload(payload: bytes) -> bytes:
    """Accept wevtutil output with or without an Events wrapper.

    Real wevtutil results can be empty, a single Event, several concatenated
    Event roots (producing multiple XML roots), or an Events envelope. XML
    declarations are stripped and an envelope is added when needed. Structural
    rejection still happens in the hardened parser afterwards.
    """
    if not isinstance(payload, bytes) or len(payload) > MAX_ENVELOPE_BYTES:
        raise ContractError("Windows XML envelope must be bytes of at most 1 MiB")
    try:
        content = payload.decode("utf-8-sig")
    except UnicodeError as exc:
        raise ContractError("Windows XML envelope must be UTF-8") from exc
    content = EVENT_DECLARATION.sub("", content).strip()
    if not content:
        return f'<Events xmlns="{EVENT_NS}"></Events>'.encode()
    if EVENTS_ROOT.match(content):
        if "xmlns" not in content.split(">", 1)[0]:
            content = content.replace(
                "<Events", f'<Events xmlns="{EVENT_NS}"', 1
            )
        normalized = content
    else:
        normalized = f'<Events xmlns="{EVENT_NS}">{content}</Events>'
    encoded = normalized.encode()
    if len(encoded) > MAX_ENVELOPE_BYTES + 256:
        raise ContractError("Windows XML envelope exceeds bounds")
    return encoded


def windows_events_batch(
    payload: bytes, *, log_epoch: str, max_events=MAX_ENVELOPE_EVENTS
):
    """Map a bounded query result, skipping unsupported individual events.

    A malformed envelope still fails closed; individual contract violations
    (for example an ordinary successful 4656) are counted and skipped so they
    cannot abort a batch of valid events.

    Returns (mapped_events, skipped, observed_record_ids, total_events).
    """
    text(log_epoch, "collector log epoch", 128)
    if type(max_events) is not int or not 1 <= max_events <= MAX_ENVELOPE_EVENTS:
        raise ContractError("envelope event limit must be 1 to 128")
    normalized = normalize_events_payload(payload)
    root = _hardened_xml(normalized.decode("utf-8"))
    prefix = "{" + EVENT_NS + "}"
    if root.tag != prefix + "Events":
        raise ContractError("unexpected Windows Events envelope namespace")
    if root.text and root.text.strip():
        raise ContractError("unexpected text in Windows Events envelope")
    events = [child for child in root if child.tag == prefix + "Event"]
    if len(events) > max_events:
        raise ContractError("Windows XML envelope exceeds the event limit")
    if len(root) != len(events):
        raise ContractError("unexpected Windows Events envelope child")
    mapped_events, skipped, observed = [], 0, []
    for event in events:
        record = None
        try:
            _bounded_element(event)
            system = event.find(prefix + "System")
            if system is not None:
                identifier = system.find(prefix + "EventRecordID")
                if (
                    identifier is not None
                    and identifier.text
                    and identifier.text.isdecimal()
                ):
                    record = int(identifier.text)
            mapped_events.append(_mapped_from_event_element(event, log_epoch))
        except ContractError:
            skipped += 1
        if record is not None:
            observed.append(record)
    return mapped_events, skipped, observed, len(events)


def windows_record_fingerprints(payload: bytes) -> dict[int, str]:
    """Fingerprint each bounded Event by record id, including skipped events."""
    normalized = normalize_events_payload(payload)
    root = _hardened_xml(normalized.decode("utf-8"))
    prefix = "{" + EVENT_NS + "}"
    if root.tag != prefix + "Events" or len(root) > MAX_ENVELOPE_EVENTS:
        raise ContractError("unexpected Windows Events envelope")
    fingerprints = {}
    for event in root:
        if event.tag != prefix + "Event":
            raise ContractError("unexpected Windows Events envelope child")
        _bounded_element(event)
        system = event.find(prefix + "System")
        identifier = None if system is None else system.find(prefix + "EventRecordID")
        if (
            identifier is None
            or not identifier.text
            or not identifier.text.isdecimal()
        ):
            continue
        record_id = int(identifier.text)
        if record_id in fingerprints:
            raise ContractError("duplicate Windows EventRecordID in query result")
        fingerprints[record_id] = hashlib.sha256(
            ET.tostring(event, encoding="utf-8")
        ).hexdigest()
    return fingerprints


def windows_events_xml_envelope(payload: bytes, *, log_epoch: str, max_events=MAX_ENVELOPE_EVENTS) -> list[dict]:
    """Strict envelope mapping: any unsupported event fails the whole batch."""
    mapped_events, skipped, _, _ = windows_events_batch(
        payload, log_epoch=log_epoch, max_events=max_events
    )
    if skipped:
        raise ContractError("Windows XML contains an unsupported event")
    return mapped_events


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
