"""Strict event contracts and persistent, observable decoy decisions.

No network calls, deployment, containment, or source content reads occur here.
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
import math
import ntpath
import os
import posixpath
import re
import sqlite3
from datetime import UTC, datetime, timedelta
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


def no_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ContractError("duplicate JSON object key")
        result[key] = value
    return result


def parse_json(data, max_nodes: int = 100000):
    if type(max_nodes) is not int or not 1 <= max_nodes <= 10000000:
        raise ContractError("JSON node limit must be 1 to 10000000")
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
            if depth > 32 or nodes > max_nodes:
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


def posix_path(value: str) -> str:
    value = text(value, "POSIX object path")
    if not value.startswith("/") or "\x00" in value:
        raise ContractError("POSIX object path must be an absolute local path")
    if ".." in value.split("/"):
        raise ContractError("POSIX object path must not contain parent traversal")
    # POSIX paths stay case sensitive: normpath only collapses separators.
    return posixpath.normpath(value)


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


WINDOWS_EVENT_OUTCOMES = {4663: "success", 4656: "failure"}
GOVCLOUD_REGIONS = {"us-gov-east-1", "us-gov-west-1"}
S3_OPERATIONS = {
    "GetObject": (["read"], False),
    "GetObjectVersion": (["read"], False),
    "HeadObject": (["recon"], False),
    "PutObject": (["write"], False),
    "CopyObject": (["write"], False),
    "DeleteObject": (["delete"], False),
    "ListObjects": (["recon"], True),
    "ListObjectsV2": (["recon"], True),
}
LINUX_AUDIT_ACTIONS = {"read", "write", "append", "delete", "recon"}
DOCUMENTED_ACTION_SETS = (
    ["read"],
    ["write"],
    ["delete"],
    ["recon"],
    ["read", "recon"],
    ["read", "write", "append", "delete"],
    ["read", "write", "append", "delete", "recon"],
)


def normalize(raw: dict) -> dict:
    required_dict(raw, "event")
    if raw.get("source") == "windows.security":
        # This is a flattened collector contract, not raw Wazuh/Splunk XML.
        if (
            raw.get("provider") != "Microsoft-Windows-Security-Auditing"
            or raw.get("channel") != "Security"
        ):
            raise ContractError("Windows provider/channel mismatch")
        event_id = raw.get("event_id")
        if type(event_id) is not int or event_id not in WINDOWS_EVENT_OUTCOMES:
            raise ContractError(
                "only Windows Security events 4663 (success) and 4656 (denied)"
                " are supported"
            )
        expected_audit = WINDOWS_EVENT_OUTCOMES[event_id]
        if (
            raw.get("audit_outcome") != expected_audit
            or raw.get("object_type") != "File"
        ):
            raise ContractError(
                f"{event_id} contract requires a {expected_audit} File access audit"
            )
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
            "outcome": "denied" if event_id == 4656 else "success",
            "context": {"process": text(raw.get("process_name"), "process", 2048)},
        }
    if raw.get("source") == "linux.audit":
        # Documented Linux audit sensor contract: a collector maps raw auditd
        # records to these fields; case-sensitive POSIX paths, no aliasing.
        host = windows_host(raw.get("host"))
        epoch = text(raw.get("sensor_epoch"), "sensor epoch", 128)
        record = text(raw.get("record_id"), "record id", 64)
        if not record.isdecimal():
            raise ContractError("record id must be decimal")
        action = text(raw.get("action"), "audit action", 16)
        if action not in LINUX_AUDIT_ACTIONS:
            raise ContractError("unsupported Linux audit action")
        outcome = raw.get("audit_outcome")
        if outcome not in ("success", "denied"):
            raise ContractError("Linux audit outcome must be success or denied")
        return {
            "schema_version": 1,
            "source": "linux.audit",
            "id": f"linux:{host}:{epoch}:{record}",
            "time": stamp(instant(raw.get("time"))),
            "actor": "uid:" + text(raw.get("uid"), "uid", 64),
            "locator": {"host": host, "path": posix_path(raw.get("path"))},
            "actions": [action],
            "outcome": outcome,
            "context": {
                "process": text(raw.get("process_name", "unknown"), "process", 2048)
            },
        }
    if raw.get("eventSource") != "s3.amazonaws.com":
        raise ContractError(
            "only S3 CloudTrail events, the Windows contract or linux.audit are"
            " supported"
        )
    operation = text(raw.get("eventName"), "S3 operation", 64)
    if operation not in S3_OPERATIONS:
        raise ContractError("unsupported S3 operation")
    actions, prefix_match = S3_OPERATIONS[operation]
    category = raw.get("eventCategory")
    if prefix_match:
        # Bucket listings are management events; they reveal recon of the prefix.
        if category != "Management":
            raise ContractError(
                f"{operation} requires eventCategory Management"
            )
    elif category != "Data":
        raise ContractError("S3 object operations require eventCategory Data")
    region = text(raw.get("awsRegion"), "region", 64)
    if region not in GOVCLOUD_REGIONS:
        raise ContractError("pilot accepts only AWS GovCloud regions")
    account = text(raw.get("recipientAccountId"), "recipient account", 12)
    if not re.fullmatch(r"[0-9]{12}", account):
        raise ContractError("recipient account must contain 12 digits")
    params = required_dict(raw.get("requestParameters"), "request parameters")
    bucket = text(params.get("bucketName"), "bucket", 63)
    if prefix_match:
        prefix = params.get("prefix", "")
        if not isinstance(prefix, str) or len(prefix) > 1024:
            raise ContractError("prefix must be a bounded string")
        if any(ord(c) < 32 for c in prefix):
            raise ContractError("prefix contains control characters")
        arn = f"arn:aws-us-gov:s3:::{bucket}/{prefix}"
    else:
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
    identity = required_dict(raw.get("userIdentity"), "user identity")
    actor = text(identity.get("arn"), "principal ARN", 2048)
    if not actor.startswith("arn:aws-us-gov:"):
        raise ContractError("principal must use the GovCloud partition")
    if "errorCode" in raw:
        text(raw["errorCode"], "S3 error code", 128)
    event = {
        "schema_version": 1,
        "source": "aws.cloudtrail.s3",
        "id": text(raw.get("eventID"), "event id", 128),
        "time": stamp(instant(raw.get("eventTime"))),
        "actor": actor,
        "locator": {"account": account, "region": region, "arn": arn},
        "actions": actions,
        "outcome": "denied" if raw.get("errorCode") else "success",
        "context": {
            "source_ip": text(raw.get("sourceIPAddress"), "source address", 256)
        },
    }
    if prefix_match:
        event["prefix_match"] = True
    return event


def mitre_techniques(event: dict) -> list[str]:
    """Coarse ATT&CK hints for triage context, never an attribution claim."""
    tags = {"T1530"} if event["source"] == "aws.cloudtrail.s3" else {"T1005"}
    if "recon" in event["actions"]:
        tags.add("T1526")
    return sorted(tags)


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
                "linux.audit",
            }:
                raise ContractError("unsupported decoy source")
            if d.get("route") is not None:
                text(d["route"], "decoy route", 64)
            if instant(d.get("expires_at")) <= instant(d.get("created_at")):
                raise ContractError("decoy expiry must follow creation")
            loc = dict(required_dict(d.get("locator"), "decoy locator"))
            if d["source"] in ("windows.security", "linux.audit"):
                if set(loc) != {"host", "path"}:
                    raise ContractError(
                        "file locator requires host and path only"
                    )
                path_field = (
                    windows_path if d["source"] == "windows.security" else posix_path
                )
                loc = {
                    "host": windows_host(loc["host"]),
                    "path": path_field(loc["path"]),
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
            if d.get("expected_actions") not in DOCUMENTED_ACTION_SETS:
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
        locator = event["locator"]
        for d in self.decoys:
            if d["source"] != event["source"]:
                continue
            if event.get("prefix_match"):
                # A bucket listing matches every registered decoy under the
                # listed bucket/prefix; the first (registry order) is reported.
                if (
                    d["source"] == "aws.cloudtrail.s3"
                    and d["locator"]["account"] == locator["account"]
                    and d["locator"]["region"] == locator["region"]
                    and d["locator"]["arn"].startswith(locator["arn"])
                ):
                    return d
            elif d["locator"] == locator:
                return d
        return None


class Engine:
    def __init__(
        self,
        registry: Registry,
        database: str | Path,
        mac_key: bytes | None = None,
        thread_safe: bool = False,
    ):
        self.registry = registry
        if mac_key is not None and (not isinstance(mac_key, bytes) or len(mac_key) != 32):
            raise ContractError("evidence key must be exactly 32 bytes")
        self.mac_key = mac_key
        # The dashboard shares one connection across request threads under a
        # lock; every other caller keeps sqlite3's same-thread guarantee.
        self.db = sqlite3.connect(str(database), check_same_thread=not thread_safe)
        try:
            self._initialize()
        except BaseException:
            self.db.close()
            raise

    def _initialize(self):
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA busy_timeout=5000")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS decisions (
                event_key TEXT PRIMARY KEY, fingerprint TEXT NOT NULL,
                result TEXT NOT NULL, created_at TEXT
            );
            CREATE TABLE IF NOT EXISTS alerts (
                id TEXT PRIMARY KEY, decoy TEXT NOT NULL, actor TEXT NOT NULL,
                opened_at TEXT NOT NULL, received_at TEXT NOT NULL, evidence TEXT NOT NULL,
                acknowledged_at TEXT, acknowledged_by TEXT, route TEXT
            );
            CREATE INDEX IF NOT EXISTS alert_correlation ON alerts(decoy, actor, received_at DESC);
            CREATE TABLE IF NOT EXISTS outbox (
                alert_id TEXT NOT NULL, payload_format TEXT NOT NULL,
                state TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
                last_error TEXT, updated_at TEXT NOT NULL,
                PRIMARY KEY (alert_id, payload_format)
            );
            CREATE INDEX IF NOT EXISTS outbox_pending ON outbox(payload_format, state);
            CREATE TABLE IF NOT EXISTS trail_files (
                digest TEXT PRIMARY KEY, processed_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS assurance_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ran_at TEXT NOT NULL, mode TEXT NOT NULL, ok INTEGER NOT NULL,
                failed_scenarios INTEGER NOT NULL, details TEXT NOT NULL
            );
        """)
        columns = {row[1] for row in self.db.execute("PRAGMA table_info(alerts)")}
        migrations = {
            "evidence_mac": "ALTER TABLE alerts ADD COLUMN evidence_mac TEXT",
            "prev_mac": "ALTER TABLE alerts ADD COLUMN prev_mac TEXT",
            "route": "ALTER TABLE alerts ADD COLUMN route TEXT",
        }
        for name, statement in migrations.items():
            if name not in columns:
                self.db.execute(statement)
        decision_columns = {
            row[1] for row in self.db.execute("PRAGMA table_info(decisions)")
        }
        if "created_at" not in decision_columns:
            self.db.execute("ALTER TABLE decisions ADD COLUMN created_at TEXT")

    def close(self):
        self.db.close()

    def evidence_mac(self, evidence: dict, prev_mac: str | None):
        if self.mac_key is None:
            return None
        linked = (prev_mac or "").encode() + canonical(evidence).encode()
        return hmac.new(self.mac_key, linked, hashlib.sha256).hexdigest()

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
                        "route": decoy.get("route"),
                        "mitre_techniques": mitre_techniques(event),
                        "severity": "high",
                        "interpretation": "Unexpected decoy interaction. Investigate before attributing intent.",
                    }
                    # The chain links every stored alert to its predecessor when
                    # an evidence key is configured; without a key both stay NULL.
                    prior_mac = self.db.execute(
                        "SELECT evidence_mac FROM alerts ORDER BY rowid DESC LIMIT 1"
                    ).fetchone()
                    prev_mac = prior_mac[0] if prior_mac else None
                    mac = self.evidence_mac(evidence, prev_mac)
                    self.db.execute(
                        "INSERT INTO alerts(id,decoy,actor,opened_at,received_at,evidence,evidence_mac,prev_mac,route) VALUES(?,?,?,?,?,?,?,?,?)",
                        (
                            alert_id,
                            decoy["id"],
                            event["actor"],
                            event["time"],
                            stamp(now),
                            canonical(evidence),
                            mac,
                            prev_mac,
                            decoy.get("route"),
                        ),
                    )
                    result.update(decision="alert", alert=evidence)
            self.db.execute(
                "INSERT INTO decisions(event_key,fingerprint,result,created_at) VALUES(?,?,?,?)",
                (key, fingerprint, canonical(result), stamp(now)),
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

    def verify_integrity(self) -> dict:
        """Recompute the stored HMAC chain; requires the same evidence key."""
        if self.mac_key is None:
            raise ContractError("integrity verification requires an evidence key")
        rows = self.db.execute(
            "SELECT id,evidence,prev_mac,evidence_mac FROM alerts ORDER BY rowid"
        ).fetchall()
        failures = []
        expected_prev = None
        for alert_id, evidence, prev_mac, mac in rows:
            if prev_mac != expected_prev:
                failures.append({"alert_id": alert_id, "reason": "chain break"})
            if self.evidence_mac(json.loads(evidence), prev_mac) != mac:
                failures.append({"alert_id": alert_id, "reason": "mac mismatch"})
            expected_prev = mac
        return {
            "schema_version": 1,
            "alerts": len(rows),
            "failures": failures,
            "ok": not failures,
        }

    def outbox_enqueue(self, payload_format: str, now: datetime, route=None) -> int:
        if payload_format not in ("wazuh", "splunk"):
            raise ContractError("unsupported delivery format")
        if route is not None:
            text(route, "delivery route", 64)
        with self.db:
            cursor = self.db.execute(
                "INSERT OR IGNORE INTO outbox(alert_id,payload_format,state,attempts,updated_at) "
                "SELECT id,?,'pending',0,? FROM alerts WHERE (? IS NULL OR route = ?)",
                (payload_format, stamp(now), route, route),
            )
        return cursor.rowcount

    def outbox_batch(self, payload_format: str, limit: int) -> list[tuple[str, dict]]:
        if payload_format not in ("wazuh", "splunk"):
            raise ContractError("unsupported delivery format")
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise ContractError("delivery batch limit must be 1 to 1000")
        rows = self.db.execute(
            "SELECT o.alert_id,a.evidence FROM outbox o JOIN alerts a ON a.id=o.alert_id "
            "WHERE o.payload_format=? AND o.state='pending' ORDER BY o.rowid LIMIT ?",
            (payload_format, limit),
        ).fetchall()
        return [(alert_id, json.loads(evidence)) for alert_id, evidence in rows]

    def outbox_mark(
        self, payload_format: str, alert_id: str, state: str, now: datetime, error=None
    ):
        if state not in ("sent", "failed"):
            raise ContractError("unsupported outbox state")
        # Diagnostics must never abort failure recording: sanitize and bound.
        if error is None:
            bounded_error = None
        else:
            cleaned = "".join(c if ord(c) >= 32 else " " for c in str(error))
            bounded_error = cleaned.strip()[:256] or None
        self.db.execute(
            "UPDATE outbox SET state=?,attempts=attempts+1,last_error=?,updated_at=? "
            "WHERE payload_format=? AND alert_id=?",
            (state, bounded_error, stamp(now), payload_format, alert_id),
        )

    def outbox_reset_failed(self, payload_format: str, now: datetime) -> int:
        if payload_format not in ("wazuh", "splunk"):
            raise ContractError("unsupported delivery format")
        with self.db:
            cursor = self.db.execute(
                "UPDATE outbox SET state='pending',updated_at=? "
                "WHERE payload_format=? AND state='failed'",
                (stamp(now), payload_format),
            )
        return cursor.rowcount

    def outbox_report(self) -> dict:
        rows = self.db.execute(
            "SELECT payload_format,state,COUNT(*) FROM outbox GROUP BY payload_format,state"
        ).fetchall()
        counts: dict[str, dict[str, int]] = {}
        for payload_format, state, count in rows:
            counts.setdefault(payload_format, {})[state] = count
        return {"schema_version": 1, "outbox": counts}

    def trail_file_processed(self, digest: str) -> bool:
        return (
            self.db.execute(
                "SELECT 1 FROM trail_files WHERE digest=?", (digest,)
            ).fetchone()
            is not None
        )

    def mark_trail_file(self, digest: str, now: datetime):
        if (
            not isinstance(digest, str)
            or not re.fullmatch(r"[0-9a-fA-F]{64}", digest)
        ):
            raise ContractError("trail file digest must be SHA-256 hexadecimal")
        with self.db:
            self.db.execute(
                "INSERT OR IGNORE INTO trail_files(digest,processed_at) VALUES(?,?)",
                (digest, stamp(now)),
            )

    def record_assurance(
        self, now: datetime, mode: str, ok: bool, failed_scenarios: int, details: dict
    ):
        text(mode, "assurance mode", 32)
        if type(failed_scenarios) is not int or failed_scenarios < 0:
            raise ContractError("failed scenario count must be a nonnegative integer")
        with self.db:
            self.db.execute(
                "INSERT INTO assurance_runs(ran_at,mode,ok,failed_scenarios,details) "
                "VALUES(?,?,?,?,?)",
                (
                    stamp(now),
                    mode,
                    1 if ok else 0,
                    failed_scenarios,
                    canonical(required_dict(details, "assurance details")),
                ),
            )

    def assurance_history(self, limit: int = 50) -> list[dict]:
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise ContractError("assurance history limit must be 1 to 1000")
        rows = self.db.execute(
            "SELECT id,ran_at,mode,ok,failed_scenarios,details FROM assurance_runs "
            "ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [
            {
                "id": run_id,
                "ran_at": ran_at,
                "mode": mode,
                "ok": bool(ok),
                "failed_scenarios": failed,
                "details": json.loads(details),
            }
            for run_id, ran_at, mode, ok, failed, details in rows
        ]

    def last_assurance(self):
        history = self.assurance_history(1)
        return history[0] if history else None

    def prune(self, now: datetime, older_than_days: int) -> dict:
        if type(older_than_days) is not int or not 1 <= older_than_days <= 3650:
            raise ContractError("retention days must be 1 to 3650")
        cutoff = stamp(now - timedelta(days=older_than_days))
        counts = {}
        with self.db:
            counts["alerts"] = self.db.execute(
                "DELETE FROM alerts WHERE received_at < ?", (cutoff,)
            ).rowcount
            counts["outbox"] = self.db.execute(
                "DELETE FROM outbox WHERE updated_at < ?", (cutoff,)
            ).rowcount
            counts["assurance_runs"] = self.db.execute(
                "DELETE FROM assurance_runs WHERE ran_at < ?", (cutoff,)
            ).rowcount
            counts["trail_files"] = self.db.execute(
                "DELETE FROM trail_files WHERE processed_at < ?", (cutoff,)
            ).rowcount
            counts["decisions"] = self.db.execute(
                "DELETE FROM decisions WHERE created_at IS NOT NULL AND created_at < ?",
                (cutoff,),
            ).rowcount
        return counts

    def backup(self, target) -> str:
        path = Path(target)
        if path.is_symlink() or not path.parent.is_dir():
            raise ContractError(
                "backup requires an existing trusted directory and a nonsymlink leaf"
            )
        if path.exists():
            raise ContractError("backup target already exists")
        with self.db:
            self.db.execute("VACUUM INTO ?", (str(path),))
        return str(path)


def restore_database(source, destination) -> str:
    """Atomically replace a closed evidence database with a verified backup."""
    src = Path(source)
    dst = Path(destination)
    if src.is_symlink() or not src.is_file():
        raise ContractError("restore source must be a regular file")
    if dst.is_symlink() or not dst.parent.is_dir():
        raise ContractError(
            "restore requires an existing trusted directory and a nonsymlink leaf"
        )
    try:
        check = sqlite3.connect(str(src))
        try:
            tables = {
                row[0]
                for row in check.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
            if not {"alerts", "decisions"} <= tables:
                raise ContractError("restore source is not a Fool's Gold database")
        finally:
            check.close()
        temporary = dst.with_suffix(dst.suffix + ".restore-tmp")
        try:
            if temporary.exists():
                temporary.unlink()
            with src.open("rb") as reader, temporary.open("wb") as writer:
                while True:
                    chunk = reader.read(1024 * 1024)
                    if not chunk:
                        break
                    writer.write(chunk)
                writer.flush()
                os.fsync(writer.fileno())
            os.replace(temporary, dst)
        except OSError:
            # Never leave a partial restore file behind.
            try:
                temporary.unlink()
            except OSError:
                pass
            raise
    except sqlite3.Error as exc:
        raise ContractError("restore source is not a readable database") from exc
    return str(dst)
