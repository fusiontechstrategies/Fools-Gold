"""Strict event contracts and persistent, observable decoy decisions.

No network calls, deployment, containment, or source content reads occur here.
"""

from __future__ import annotations

import copy
import hashlib
import json
import ntpath
import re
import sqlite3
from datetime import UTC, datetime
from pathlib import Path


class ContractError(ValueError):
    """An input cannot be safely interpreted under the documented contract."""


def text(value, name: str, limit: int = 2048) -> str:
    if not isinstance(value, str) or not value or len(value) > limit:
        raise ContractError(
            f"{name} must be a nonempty string of at most {limit} characters"
        )
    if any(ord(c) < 32 for c in value):
        raise ContractError(f"{name} contains control characters")
    return value


def instant(value) -> datetime:
    try:
        parsed = datetime.fromisoformat(
            text(value, "timestamp", 64).replace("Z", "+00:00")
        )
        if parsed.tzinfo is None:
            raise ContractError("timestamp must include a timezone")
        return parsed.astimezone(UTC)
    except (ValueError, OverflowError) as exc:
        raise ContractError("timestamp must be ISO 8601 with a timezone") from exc


def stamp(value: datetime) -> str:
    if value.tzinfo is None:
        raise ContractError("clock must be timezone aware")
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def canonical(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def digest(value) -> str:
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def windows_path(value: str) -> str:
    value = text(value, "Windows object path")
    # Collector contract uses absolute local paths, never drive-relative/UNC aliases.
    if not re.match(r"^[A-Za-z]:\\", value) or ".." in value.replace("/", "\\").split(
        "\\"
    ):
        raise ContractError(
            "Windows object path must be an absolute local path without parent traversal"
        )
    return ntpath.normpath(value).casefold()


def windows_host(value: str) -> str:
    value = text(value, "Windows host", 255)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,254}", value):
        raise ContractError(
            "Windows host must be an ASCII computer name without delimiters"
        )
    return value.casefold()


def required_dict(value, name):
    if not isinstance(value, dict):
        raise ContractError(f"{name} must be an object")
    return value


def normalize(raw: dict) -> dict:
    required_dict(raw, "event")
    if raw.get("source") == "windows.security":
        # This is a flattened collector contract, not raw Wazuh/Splunk XML.
        if (
            raw.get("provider") != "Microsoft-Windows-Security-Auditing"
            or raw.get("channel") != "Security"
        ):
            raise ContractError("Windows provider/channel mismatch")
        if type(raw.get("event_id")) is not int or raw["event_id"] != 4663:
            raise ContractError("only Windows Security event 4663 is supported")
        if raw.get("audit_outcome") != "success" or raw.get("object_type") != "File":
            raise ContractError("4663 contract requires a successful File access audit")
        host = windows_host(raw.get("computer"))
        epoch = text(raw.get("log_epoch"), "log epoch", 128)
        record = text(raw.get("record_id"), "record id", 64)
        if not record.isdecimal():
            raise ContractError("record id must be decimal")
        mask = raw.get("access_mask")
        if not isinstance(mask, str) or not re.fullmatch(r"0x[0-9a-fA-F]{1,8}", mask):
            raise ContractError("access mask must be a bounded hexadecimal string")
        bits = int(mask, 16)
        actions = [
            name
            for bit, name in (
                (1, "read"),
                (2, "write"),
                (4, "append"),
                (0x10000, "delete"),
            )
            if bits & bit
        ]
        if not actions:
            raise ContractError("access mask has no supported content access")
        return {
            "schema_version": 1,
            "source": raw["source"],
            "id": f"windows:{host}:{epoch}:{record}",
            "time": stamp(instant(raw.get("time"))),
            "actor": text(raw.get("subject_sid"), "subject SID", 256),
            "locator": {"host": host, "path": windows_path(raw.get("object_name"))},
            "actions": actions,
            "outcome": "success",
            "context": {"process": text(raw.get("process_name"), "process", 2048)},
        }
    if (
        raw.get("eventSource") != "s3.amazonaws.com"
        or raw.get("eventCategory") != "Data"
    ):
        raise ContractError(
            "only S3 CloudTrail data events or the Windows contract are supported"
        )
    region = text(raw.get("awsRegion"), "region", 64)
    if region not in {"us-gov-east-1", "us-gov-west-1"}:
        raise ContractError("pilot accepts only AWS GovCloud regions")
    account = text(raw.get("recipientAccountId"), "recipient account", 12)
    if not re.fullmatch(r"[0-9]{12}", account):
        raise ContractError("recipient account must contain 12 digits")
    params = required_dict(raw.get("requestParameters"), "request parameters")
    bucket = text(params.get("bucketName"), "bucket", 63)
    key = text(params.get("key"), "key", 1024)
    arn = f"arn:aws-us-gov:s3:::{bucket}/{key}"
    resources = raw.get("resources")
    if not isinstance(resources, list) or not any(
        isinstance(r, dict)
        and r.get("type") == "AWS::S3::Object"
        and r.get("ARN") == arn
        for r in resources
    ):
        raise ContractError(
            "exact GovCloud object ARN must agree with request parameters"
        )
    actions = {"GetObject": "read", "PutObject": "write", "DeleteObject": "delete"}
    operation = text(raw.get("eventName"), "S3 operation", 64)
    if operation not in actions:
        raise ContractError("unsupported S3 operation")
    identity = required_dict(raw.get("userIdentity"), "user identity")
    actor = text(identity.get("arn"), "principal ARN", 2048)
    if not actor.startswith("arn:aws-us-gov:"):
        raise ContractError("principal must use the GovCloud partition")
    if "errorCode" in raw:
        text(raw["errorCode"], "S3 error code", 128)
    return {
        "schema_version": 1,
        "source": "aws.cloudtrail.s3",
        "id": text(raw.get("eventID"), "event id", 128),
        "time": stamp(instant(raw.get("eventTime"))),
        "actor": actor,
        "locator": {"account": account, "region": region, "arn": arn},
        "actions": [actions[operation]],
        "outcome": "denied" if raw.get("errorCode") else "success",
        "context": {
            "source_ip": text(raw.get("sourceIPAddress"), "source address", 256)
        },
    }


class Registry:
    def __init__(self, document: dict):
        required_dict(document, "registry")
        document = copy.deepcopy(document)
        if (
            type(document.get("schema_version")) is not int
            or document["schema_version"] != 1
        ):
            raise ContractError("unsupported registry schema")
        entries = document.get("decoys")
        if not isinstance(entries, list) or not 1 <= len(entries) <= 1000:
            raise ContractError("registry must contain 1 to 1000 decoys")
        self.decoys = []
        ids, locations = set(), set()
        for original in entries:
            d = dict(required_dict(original, "decoy"))
            for field in ("id", "owner", "response_procedure"):
                text(d.get(field), field)
            if d["id"] in ids:
                raise ContractError("duplicate decoy id")
            ids.add(d["id"])
            if text(d.get("source"), "decoy source", 64) not in {
                "aws.cloudtrail.s3",
                "windows.security",
            }:
                raise ContractError("unsupported decoy source")
            if instant(d.get("expires_at")) <= instant(d.get("created_at")):
                raise ContractError("decoy expiry must follow creation")
            loc = dict(required_dict(d.get("locator"), "decoy locator"))
            if d["source"] == "windows.security":
                if set(loc) != {"host", "path"}:
                    raise ContractError("Windows locator requires host and path only")
                loc = {
                    "host": windows_host(loc["host"]),
                    "path": windows_path(loc["path"]),
                }
            else:
                if set(loc) != {"account", "region", "arn"} or text(
                    loc["region"], "registry region", 64
                ) not in {
                    "us-gov-east-1",
                    "us-gov-west-1",
                }:
                    raise ContractError(
                        "S3 locator requires GovCloud account, region and object ARN"
                    )
                if not re.fullmatch(r"[0-9]{12}", text(loc["account"], "account", 12)):
                    raise ContractError("invalid registry account")
                if not re.fullmatch(
                    r"arn:aws-us-gov:s3:::[^/]+/.+", text(loc["arn"], "object ARN")
                ):
                    raise ContractError(
                        "registry requires an exact GovCloud object ARN"
                    )
            d["locator"] = loc
            location = d["source"] + canonical(loc)
            if location in locations:
                raise ContractError("duplicate decoy location")
            locations.add(location)
            if d.get("expected_actions") not in (
                ["read"],
                ["write"],
                ["delete"],
                ["read", "write", "append", "delete"],
            ):
                raise ContractError("expected actions must use a documented action set")
            exceptions = d.get("exceptions", [])
            if not isinstance(exceptions, list) or len(exceptions) > 100:
                raise ContractError(
                    "decoy exceptions must be a list of at most 100 items"
                )
            for e in exceptions:
                required_dict(e, "exception")
                for name in ("actor", "owner", "reason", "id"):
                    text(e.get(name), f"exception {name}")
                if instant(e.get("expires_at")) <= instant(e.get("starts_at")):
                    raise ContractError("exception expiry must follow its start")
                if (
                    not isinstance(e.get("actions"), list)
                    or not e["actions"]
                    or any(a not in d["expected_actions"] for a in e["actions"])
                ):
                    raise ContractError("exception actions must be explicitly scoped")
            self.decoys.append(d)
        self.fingerprint = digest(document)

    def match(self, event: dict):
        return next(
            (
                d
                for d in self.decoys
                if d["source"] == event["source"] and d["locator"] == event["locator"]
            ),
            None,
        )


class Engine:
    def __init__(self, registry: Registry, database: str | Path):
        self.registry = registry
        self.db = sqlite3.connect(str(database))
        try:
            self._initialize()
        except BaseException:
            self.db.close()
            raise

    def _initialize(self):
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS decisions (
                event_key TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, result TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS alerts (
                id TEXT PRIMARY KEY, decoy TEXT NOT NULL, actor TEXT NOT NULL,
                opened_at TEXT NOT NULL, received_at TEXT NOT NULL, evidence TEXT NOT NULL,
                acknowledged_at TEXT, acknowledged_by TEXT
            );
            CREATE INDEX IF NOT EXISTS alert_correlation ON alerts(decoy, actor, received_at DESC);
        """)

    def close(self):
        self.db.close()

    def process(self, raw: dict, received_at: datetime) -> dict:
        now = instant(stamp(received_at))
        event = normalize(raw)
        event_time = instant(event["time"])
        if event_time > now:
            raise ContractError("event timestamp is in the future")
        key = event["source"] + ":" + event["id"]
        fingerprint = digest(raw)
        previous = self.db.execute(
            "SELECT fingerprint,result FROM decisions WHERE event_key=?", (key,)
        ).fetchone()
        if previous:
            if previous[0] != fingerprint:
                raise ContractError(
                    "event identifier collision with different evidence"
                )
            return {
                "decision": "duplicate",
                "original_decision": json.loads(previous[1])["decision"],
                "event_id": event["id"],
            }
        decoy = self.registry.match(event)
        result = {
            "schema_version": 1,
            "event_id": event["id"],
            "decision": "unmatched",
            "registry_sha256": self.registry.fingerprint,
        }
        with self.db:
            if decoy:
                expired = now >= instant(decoy["expires_at"]) or event_time >= instant(
                    decoy["expires_at"]
                )
                exception = next(
                    (
                        e
                        for e in decoy.get("exceptions", [])
                        if not expired
                        and event["outcome"] == "success"
                        and event_time >= instant(decoy["created_at"])
                        and e["actor"] == event["actor"]
                        and set(event["actions"]).issubset(e["actions"])
                        and instant(e["starts_at"])
                        <= event_time
                        < instant(e["expires_at"])
                        and instant(e["starts_at"]) <= now < instant(e["expires_at"])
                    ),
                    None,
                )
                result.update(decoy_id=decoy["id"], registry_expired=expired)
                if exception:
                    result.update(
                        decision="expected_access",
                        exception_id=exception["id"],
                        exception_owner=exception["owner"],
                        reason=exception["reason"],
                    )
                else:
                    alert_id = "fg-" + digest({"key": key})[:32]
                    # Correlation is evidence context, never a reason to drop an event.
                    prior = self.db.execute(
                        "SELECT id,received_at FROM alerts WHERE decoy=? AND actor=? ORDER BY received_at DESC LIMIT 1",
                        (decoy["id"], event["actor"]),
                    ).fetchone()
                    related = (
                        prior[0]
                        if prior
                        and 0 <= (now - instant(prior[1])).total_seconds() <= 300
                        else None
                    )
                    evidence = {
                        "schema_version": 1,
                        "product": "fools-gold",
                        "alert_id": alert_id,
                        "decoy_id": decoy["id"],
                        "owner": decoy["owner"],
                        "response_procedure": decoy["response_procedure"],
                        "event": event,
                        "observed_at": stamp(now),
                        "telemetry_delay_seconds": (now - event_time).total_seconds(),
                        "registry_expired": expired,
                        "registry_sha256": self.registry.fingerprint,
                        "raw_event_sha256": fingerprint,
                        "related_alert_id": related,
                        "severity": "high",
                        "interpretation": "Unexpected decoy interaction. Investigate before attributing intent.",
                    }
                    self.db.execute(
                        "INSERT INTO alerts(id,decoy,actor,opened_at,received_at,evidence) VALUES(?,?,?,?,?,?)",
                        (
                            alert_id,
                            decoy["id"],
                            event["actor"],
                            event["time"],
                            stamp(now),
                            canonical(evidence),
                        ),
                    )
                    result.update(decision="alert", alert=evidence)
            self.db.execute(
                "INSERT INTO decisions VALUES(?,?,?)",
                (key, fingerprint, canonical(result)),
            )
        return result

    def acknowledge(self, alert_id: str, actor: str, at: datetime):
        text(alert_id, "alert id", 64)
        text(actor, "analyst", 256)
        row = self.db.execute(
            "SELECT received_at,acknowledged_at FROM alerts WHERE id=?", (alert_id,)
        ).fetchone()
        if not row:
            raise ContractError("unknown alert")
        if instant(stamp(at)) < instant(row[0]):
            raise ContractError("acknowledgment cannot precede receipt")
        if row[1]:
            raise ContractError("alert has already been acknowledged")
        with self.db:
            self.db.execute(
                "UPDATE alerts SET acknowledged_at=?,acknowledged_by=? WHERE id=?",
                (stamp(at), actor, alert_id),
            )

    def report(self) -> dict:
        rows = self.db.execute("SELECT result FROM decisions").fetchall()
        counts = {"alert": 0, "expected_access": 0, "unmatched": 0}
        for (r,) in rows:
            counts[json.loads(r)["decision"]] += 1
        acks = self.db.execute(
            "SELECT received_at,acknowledged_at FROM alerts WHERE acknowledged_at IS NOT NULL"
        ).fetchall()
        return {
            "schema_version": 1,
            "decisions": counts,
            "alerts_acknowledged": len(acks),
            "acknowledgment_seconds": [
                (instant(a) - instant(r)).total_seconds() for r, a in acks
            ],
            "delivery_scope": "local SQLite evidence only; no SIEM delivery measured",
        }

    def export_alerts(self):
        """Read retained evidence for offline packaging/recovery, not delivery ack."""
        for (evidence,) in self.db.execute(
            "SELECT evidence FROM alerts ORDER BY received_at,id"
        ):
            yield json.loads(evidence)
