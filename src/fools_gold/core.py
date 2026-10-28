"""Strict event contracts and persistent, observable decoy decisions.

No network calls, deployment, containment, or source content reads occur here.
"""

from __future__ import annotations

import contextlib
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
import threading
import time
import uuid
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


def _lock_file(handle) -> bool:
    """Non-blocking exclusive advisory lock on a lock file."""
    handle.seek(0, os.SEEK_END)
    if handle.tell() == 0:
        handle.write(b"0")
        handle.flush()
    handle.seek(0)
    try:
        if os.name == "nt":
            import msvcrt

            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        return True
    except OSError:
        return False


def _unlock_file(handle):
    handle.seek(0)
    try:
        if os.name == "nt":
            import msvcrt

            msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    except OSError:
        pass


def acquire_database_lock(database: str | Path, *, timeout: float = 0.0):
    """Take the short-lived writer lock; returns the open lock handle.

    Writers serialize per transaction (not for the engine lifetime) so the
    dashboard, ingestion and delivery can coexist. A timeout lets concurrent
    CLI writers queue instead of failing outright.
    """
    lock_path = Path(str(database) + ".lock")
    if lock_path.is_symlink() or not lock_path.parent.is_dir():
        raise ContractError(
            "database requires an existing trusted directory and a nonsymlink lock leaf"
        )
    handle = open(lock_path, "a+b")
    deadline = time.monotonic() + max(0.0, timeout)
    while not _lock_file(handle):
        if time.monotonic() >= deadline:
            handle.close()
            raise ContractError(
                "database is locked by another Fool's Gold writer; retry shortly"
            )
        time.sleep(0.05)
    return handle


def release_database_lock(handle):
    try:
        _unlock_file(handle)
    finally:
        handle.close()


SESSION_SLOTS = 64


class SessionLock:
    """Lifetime session marker used to make restore exclusive.

    POSIX takes a shared flock per session so destinations can be replaced only
    when no session holds the database. Windows has no shared lock, so each
    session locks one byte-range slot and restore must lock all slots.
    """

    def __init__(self, database: str | Path):
        self.path = Path(str(database) + ".session")
        self.handle = None
        self.slot = None

    def acquire(self, *, exclusive: bool = False, timeout: float = 0.0):
        if self.path.is_symlink() or not self.path.parent.is_dir():
            raise ContractError(
                "database requires an existing trusted directory and a nonsymlink session leaf"
            )
        handle = open(self.path, "a+b")
        handle.seek(0, os.SEEK_END)
        if handle.tell() < SESSION_SLOTS:
            handle.write(b"\0" * (SESSION_SLOTS - handle.tell()))
            handle.flush()
        deadline = time.monotonic() + max(0.0, timeout)
        while True:
            if os.name == "nt":
                import msvcrt

                if exclusive:
                    acquired = []
                    try:
                        for slot in range(SESSION_SLOTS):
                            handle.seek(slot)
                            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                            acquired.append(slot)
                    except OSError:
                        for slot in acquired:
                            handle.seek(slot)
                            try:
                                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
                            except OSError:
                                pass
                        if time.monotonic() >= deadline:
                            handle.close()
                            raise ContractError(
                                "another Fool's Gold session is using the database"
                            )
                        time.sleep(0.05)
                        continue
                    self.slot = "all"
                else:
                    for slot in range(SESSION_SLOTS):
                        try:
                            handle.seek(slot)
                            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                            self.slot = slot
                            break
                        except OSError:
                            continue
                    else:
                        if time.monotonic() >= deadline:
                            handle.close()
                            raise ContractError(
                                "too many concurrent Fool's Gold sessions"
                            )
                        time.sleep(0.05)
                        continue
            else:
                import fcntl

                mode = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
                try:
                    fcntl.flock(handle.fileno(), mode | fcntl.LOCK_NB)
                except OSError:
                    if time.monotonic() >= deadline:
                        handle.close()
                        raise ContractError(
                            "another Fool's Gold session is using the database"
                        )
                    time.sleep(0.05)
                    continue
            self.handle = handle
            return

    def release(self):
        if self.handle is None:
            return
        handle = self.handle
        self.handle = None
        try:
            if os.name == "nt":
                import msvcrt

                slots = (
                    range(SESSION_SLOTS) if self.slot == "all" else [self.slot]
                )
                for slot in slots:
                    handle.seek(slot)
                    try:
                        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
                    except OSError:
                        pass
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        finally:
            handle.close()


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
        # AWS documents listing activity as data events for bucket-level
        # resources; older trails may still surface it as management activity.
        if category not in ("Data", "Management"):
            raise ContractError(
                f"{operation} requires eventCategory Data or Management"
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
    context = {
        "source_ip": text(raw.get("sourceIPAddress"), "source address", 256)
    }
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
        if "versionId" in params:
            context["version_id"] = text(
                params["versionId"], "version id", 256
            )
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
        "context": context,
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
        single_writer: bool | None = None,
    ):
        self.registry = registry
        if mac_key is not None and (not isinstance(mac_key, bytes) or len(mac_key) != 32):
            raise ContractError("evidence key must be exactly 32 bytes")
        self.mac_key = mac_key
        self._chain_verified = False
        self._db_path = (
            None if str(database) == ":memory:" else Path(database)
        )
        # Writers take a short-lived lock per transaction; the session lock is
        # a lifetime marker that lets restore prove nobody has the DB open.
        self._thread_lock = threading.RLock()
        self._session_lock = None
        if self._db_path is not None and single_writer is not False:
            session = SessionLock(self._db_path)
            session.acquire()
            self._session_lock = session
        # Concurrent first starts must not race schema checks and ALTERs.
        init_lock = None
        if self._db_path is not None:
            init_lock = acquire_database_lock(self._db_path, timeout=60.0)
        try:
            # The dashboard shares one connection across request threads under
            # a lock; other callers keep sqlite3's same-thread guarantee.
            self.db = sqlite3.connect(
                str(database), check_same_thread=not thread_safe
            )
            self._initialize()
        except BaseException:
            self.db.close()
            if self._session_lock is not None:
                self._session_lock.release()
                self._session_lock = None
            raise
        finally:
            if init_lock is not None:
                release_database_lock(init_lock)

    @contextlib.contextmanager
    def _write_guard(self, timeout: float = 60.0):
        """Serialize one write transaction across threads and processes."""
        with self._thread_lock:
            handle = None
            if self._db_path is not None:
                handle = acquire_database_lock(self._db_path, timeout=timeout)
            try:
                if self.db.in_transaction:
                    self.db.commit()
                # IMMEDIATE takes the SQLite write lock up front, so a deferred
                # read can never race an upgrade to write.
                self.db.execute("BEGIN IMMEDIATE")
                try:
                    yield
                except BaseException:
                    self.db.rollback()
                    raise
                else:
                    self.db.commit()
            finally:
                if handle is not None:
                    release_database_lock(handle)

    def _alter_add(self, statement):
        # Idempotent if another process won a migration race.
        try:
            self.db.execute(statement)
        except sqlite3.OperationalError as exc:
            if "duplicate column name" not in str(exc):
                raise

    def _initialize(self):
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA busy_timeout=10000")
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
                alert_id TEXT NOT NULL, destination TEXT NOT NULL,
                payload_format TEXT NOT NULL,
                state TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
                last_error TEXT, updated_at TEXT NOT NULL,
                PRIMARY KEY (alert_id, destination)
            );
            CREATE TABLE IF NOT EXISTS destinations (
                name TEXT PRIMARY KEY, payload_format TEXT NOT NULL,
                host TEXT, port INTEGER, path TEXT, created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS routes (
                route TEXT PRIMARY KEY, destination TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS trail_files (
                digest TEXT PRIMARY KEY, processed_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS assurance_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ran_at TEXT NOT NULL, mode TEXT NOT NULL, ok INTEGER NOT NULL,
                failed_scenarios INTEGER NOT NULL, details TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS checkpoints (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL, pruned_before TEXT NOT NULL,
                deleted_alerts INTEGER NOT NULL, boundary_prev_mac TEXT NOT NULL,
                first_retained_id TEXT, mac TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS acceptances (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                stage TEXT NOT NULL, note TEXT NOT NULL, actor TEXT NOT NULL,
                recorded_at TEXT NOT NULL
            );
        """)
        assurance_columns = {
            row[1] for row in self.db.execute("PRAGMA table_info(assurance_runs)")
        }
        if "run_id" not in assurance_columns:
            self._alter_add("ALTER TABLE assurance_runs ADD COLUMN run_id TEXT")
        columns = {row[1] for row in self.db.execute("PRAGMA table_info(alerts)")}
        migrations = {
            "evidence_mac": "ALTER TABLE alerts ADD COLUMN evidence_mac TEXT",
            "prev_mac": "ALTER TABLE alerts ADD COLUMN prev_mac TEXT",
            "route": "ALTER TABLE alerts ADD COLUMN route TEXT",
        }
        for name, statement in migrations.items():
            if name not in columns:
                self._alter_add(statement)
        decision_columns = {
            row[1] for row in self.db.execute("PRAGMA table_info(decisions)")
        }
        if "created_at" not in decision_columns:
            self._alter_add("ALTER TABLE decisions ADD COLUMN created_at TEXT")
        self._migrate_outbox()
        # Bounded routine queries: dashboard pages, status and reports.
        self.db.execute(
            "CREATE INDEX IF NOT EXISTS alerts_received "
            "ON alerts(received_at DESC)"
        )
        self.db.execute(
            "CREATE INDEX IF NOT EXISTS assurance_ran "
            "ON assurance_runs(ran_at DESC)"
        )
        self.db.execute(
            "CREATE INDEX IF NOT EXISTS checkpoints_created "
            "ON checkpoints(created_at DESC)"
        )
        # Initialization must not leave an uncommitted transaction behind.
        if self.db.in_transaction:
            self.db.commit()

    def _migrate_outbox(self):
        """Move the pre-destination outbox onto the composite-key schema.

        The whole migration is one immediate transaction so an interruption
        cannot leave a partially renamed table. A pre-existing outbox_v2 is a
        previous interrupted artifact: the legacy outbox is authoritative and
        the artifact is rebuilt from it.
        """
        columns = {
            row[1] for row in self.db.execute("PRAGMA table_info(outbox)")
        }
        if "destination" in columns:
            if self.db.in_transaction:
                self.db.commit()
            self.db.execute("DROP TABLE IF EXISTS outbox_v2")
            self.db.execute(
                "CREATE INDEX IF NOT EXISTS outbox_destination_state "
                "ON outbox(destination, state)"
            )
            return
        if self.db.in_transaction:
            self.db.commit()
        self.db.execute("BEGIN IMMEDIATE")
        try:
            self.db.execute(
                "CREATE TABLE IF NOT EXISTS outbox_v2 ("
                "alert_id TEXT NOT NULL, destination TEXT NOT NULL, "
                "payload_format TEXT NOT NULL, state TEXT NOT NULL, "
                "attempts INTEGER NOT NULL DEFAULT 0, last_error TEXT, "
                "updated_at TEXT NOT NULL, PRIMARY KEY (alert_id, destination))"
            )
            # Discard any partial rows from an interrupted attempt.
            self.db.execute("DELETE FROM outbox_v2")
            self.db.execute(
                "INSERT INTO outbox_v2(alert_id,destination,payload_format,state,"
                "attempts,last_error,updated_at) "
                "SELECT alert_id,payload_format,payload_format,state,attempts,"
                "last_error,updated_at FROM outbox"
            )
            self.db.execute("DROP TABLE outbox")
            self.db.execute("ALTER TABLE outbox_v2 RENAME TO outbox")
            self.db.execute(
                "CREATE INDEX IF NOT EXISTS outbox_destination_state "
                "ON outbox(destination, state)"
            )
            self.db.commit()
        except BaseException:
            self.db.rollback()
            raise

    def close(self):
        try:
            self.db.close()
        finally:
            if self._session_lock is not None:
                self._session_lock.release()
                self._session_lock = None

    def evidence_mac(self, evidence: dict, prev_mac: str | None):
        if self.mac_key is None:
            return None
        linked = (prev_mac or "").encode() + canonical(evidence).encode()
        return hmac.new(self.mac_key, linked, hashlib.sha256).hexdigest()

    def _signed_alert_count(self) -> int:
        return self.db.execute(
            "SELECT COUNT(*) FROM alerts WHERE evidence_mac IS NOT NULL"
        ).fetchone()[0]

    def _ensure_chain_key(self):
        """Refuse chain writes that could mix unsigned evidence into a chain."""
        if self._signed_alert_count() == 0:
            return
        if self.mac_key is None:
            raise ContractError(
                "database contains signed evidence; supply the evidence key"
            )
        if self._chain_verified:
            return
        outcome = self.verify_integrity()
        if not outcome["ok"]:
            raise ContractError(
                "evidence key does not match the existing evidence chain"
            )
        self._chain_verified = True

    def process(self, raw: dict, received_at: datetime) -> dict:
        now = instant(stamp(received_at))
        event = normalize(raw)
        event_time = instant(event["time"])
        if event_time > now:
            raise ContractError("event timestamp is in the future")
        key = event["source"] + ":" + event["id"]
        fingerprint = digest(raw)
        with self._write_guard():
            # The predecessor/key check and the duplicate check must share the
            # write transaction so concurrent writers cannot fork the chain or
            # both insert the same decision.
            self._ensure_chain_key()
            previous = self.db.execute(
                "SELECT fingerprint,result FROM decisions WHERE event_key=?",
                (key,),
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
        with self._write_guard():
            row = self.db.execute(
                "SELECT received_at,acknowledged_at FROM alerts WHERE id=?",
                (alert_id,),
            ).fetchone()
            if not row:
                raise ContractError("unknown alert")
            if instant(stamp(at)) < instant(row[0]):
                raise ContractError("acknowledgment cannot precede receipt")
            if row[1]:
                raise ContractError("alert has already been acknowledged")
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

    def _checkpoint_fields(
        self,
        created_at,
        pruned_before,
        deleted_alerts,
        boundary_prev_mac,
        first_retained_id,
    ) -> dict:
        return {
            "schema_version": 1,
            "created_at": created_at,
            "pruned_before": pruned_before,
            "deleted_alerts": deleted_alerts,
            "boundary_prev_mac": boundary_prev_mac,
            "first_retained_id": first_retained_id,
        }

    def verify_integrity(self) -> dict:
        """Recompute the stored HMAC chain; requires the same evidence key.

        A signed retention checkpoint may explain a missing predecessor when
        alerts were pruned deliberately. Unauthorized deletions still show as
        chain breaks; replacing every alert is not locally detectable.
        """
        if self.mac_key is None:
            raise ContractError("integrity verification requires an evidence key")
        rows = self.db.execute(
            "SELECT id,evidence,prev_mac,evidence_mac FROM alerts ORDER BY rowid"
        ).fetchall()
        checkpoints = self.db.execute(
            "SELECT id,created_at,pruned_before,deleted_alerts,"
            "boundary_prev_mac,first_retained_id,mac FROM checkpoints ORDER BY id"
        ).fetchall()
        boundaries = {}
        for (
            checkpoint_id,
            created_at,
            pruned_before,
            deleted_alerts,
            boundary_prev_mac,
            first_retained_id,
            checkpoint_mac,
        ) in checkpoints:
            fields = self._checkpoint_fields(
                created_at,
                pruned_before,
                deleted_alerts,
                boundary_prev_mac,
                first_retained_id,
            )
            expected = hmac.new(
                self.mac_key, canonical(fields).encode(), hashlib.sha256
            ).hexdigest()
            boundaries[boundary_prev_mac] = hmac.compare_digest(
                expected, checkpoint_mac
            )
        failures = []
        expected_prev = None
        applied = 0
        for index, (alert_id, evidence, prev_mac, mac) in enumerate(rows):
            if index == 0 and prev_mac is not None:
                # The predecessor was pruned; only a valid signed checkpoint
                # may authorize that boundary.
                if prev_mac not in boundaries:
                    failures.append(
                        {
                            "alert_id": alert_id,
                            "reason": "chain break (no retention checkpoint)",
                        }
                    )
                elif not boundaries[prev_mac]:
                    failures.append(
                        {
                            "alert_id": alert_id,
                            "reason": "retention checkpoint mac mismatch",
                        }
                    )
                else:
                    applied += 1
            elif prev_mac != expected_prev:
                failures.append({"alert_id": alert_id, "reason": "chain break"})
            if self.evidence_mac(json.loads(evidence), prev_mac) != mac:
                failures.append({"alert_id": alert_id, "reason": "mac mismatch"})
            expected_prev = mac
        return {
            "schema_version": 1,
            "alerts": len(rows),
            "failures": failures,
            "retention": {
                "checkpoints": len(checkpoints),
                "applied": applied,
            },
            "ok": not failures,
        }

    def add_destination(
        self,
        now: datetime,
        name: str,
        payload_format: str,
        *,
        host=None,
        port=None,
        path=None,
    ):
        if not isinstance(name, str) or not re.fullmatch(
            r"[a-z0-9][a-z0-9-]{0,31}", name
        ):
            raise ContractError(
                "destination name must be 1 to 32 lowercase letters, digits or dashes"
            )
        if payload_format not in ("wazuh", "splunk"):
            raise ContractError("unsupported delivery format")
        if payload_format == "splunk":
            if host is None or port is None or path is not None:
                raise ContractError("Splunk destinations require host and port only")
            host = text(host, "destination host", 255)
            if "/" in host or "\\" in host:
                raise ContractError("destination host must be a bare hostname")
            if type(port) is not int or not 1 <= port <= 65535:
                raise ContractError("destination port must be 1 to 65535")
        else:
            if path is None or host is not None or port is not None:
                raise ContractError("Wazuh destinations require a path only")
            path = text(path, "destination path", 2048)
        try:
            with self._write_guard():
                self.db.execute(
                    "INSERT INTO destinations(name,payload_format,host,port,path,created_at) "
                    "VALUES(?,?,?,?,?,?)",
                    (name, payload_format, host, port, path, stamp(now)),
                )
        except sqlite3.IntegrityError as exc:
            raise ContractError("destination already exists") from exc

    def destination(self, name: str):
        text(name, "destination name", 32)
        row = self.db.execute(
            "SELECT name,payload_format,host,port,path FROM destinations WHERE name=?",
            (name,),
        ).fetchone()
        if row is None:
            return None
        return {
            "name": row[0],
            "payload_format": row[1],
            "host": row[2],
            "port": row[3],
            "path": row[4],
        }

    def destinations(self) -> list[dict]:
        return [
            {
                "name": name,
                "payload_format": payload_format,
                "host": host,
                "port": port,
                "path": path,
            }
            for name, payload_format, host, port, path in self.db.execute(
                "SELECT name,payload_format,host,port,path FROM destinations "
                "ORDER BY name"
            )
        ]

    def map_route(self, now: datetime, route: str, destination: str):
        text(route, "route", 64)
        if self.destination(destination) is None:
            raise ContractError("route destination does not exist")
        with self._write_guard():
            self.db.execute(
                "INSERT INTO routes(route,destination,updated_at) VALUES(?,?,?) "
                "ON CONFLICT(route) DO UPDATE SET "
                "destination=excluded.destination, updated_at=excluded.updated_at",
                (route, destination, stamp(now)),
            )

    def route_destination(self, route: str):
        row = self.db.execute(
            "SELECT destination FROM routes WHERE route=?", (route,)
        ).fetchone()
        return row[0] if row else None

    def routes(self) -> list[dict]:
        return [
            {
                "route": route,
                "destination": destination,
                "updated_at": updated,
            }
            for route, destination, updated in self.db.execute(
                "SELECT route,destination,updated_at FROM routes ORDER BY route"
            )
        ]

    def _destination_format(self, destination: str) -> str:
        spec = self.destination(destination)
        if spec is not None:
            return spec["payload_format"]
        if destination in ("wazuh", "splunk"):
            return destination
        raise ContractError("unknown delivery destination")

    def outbox_enqueue(self, destination: str, now: datetime, route=None) -> int:
        payload_format = self._destination_format(destination)
        if route is not None:
            text(route, "delivery route", 64)
            mapped = self.route_destination(route)
            if mapped is not None and mapped != destination:
                raise ContractError(
                    f"route {route} is mapped to destination {mapped}"
                )
        with self._write_guard():
            cursor = self.db.execute(
                "INSERT OR IGNORE INTO outbox(alert_id,destination,payload_format,"
                "state,attempts,updated_at) "
                "SELECT id,?,?,'pending',0,? FROM alerts "
                "WHERE (? IS NULL OR route = ?)",
                (destination, payload_format, stamp(now), route, route),
            )
        return cursor.rowcount

    def outbox_batch(
        self, destination: str, limit: int, route=None
    ) -> list[tuple[str, dict]]:
        self._destination_format(destination)
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise ContractError("delivery batch limit must be 1 to 1000")
        if route is not None:
            text(route, "delivery route", 64)
        rows = self.db.execute(
            "SELECT o.alert_id,a.evidence FROM outbox o JOIN alerts a ON a.id=o.alert_id "
            "WHERE o.destination=? AND o.state='pending' "
            "AND (? IS NULL OR a.route = ?) ORDER BY o.rowid LIMIT ?",
            (destination, route, route, limit),
        ).fetchall()
        return [(alert_id, json.loads(evidence)) for alert_id, evidence in rows]

    def outbox_mark(
        self, destination: str, alert_id: str, state: str, now: datetime, error=None
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
            "WHERE destination=? AND alert_id=?",
            (state, bounded_error, stamp(now), destination, alert_id),
        )

    def outbox_reset_failed(
        self, destination: str, now: datetime, route=None
    ) -> int:
        self._destination_format(destination)
        if route is not None:
            text(route, "delivery route", 64)
        with self._write_guard():
            cursor = self.db.execute(
                "UPDATE outbox SET state='pending',updated_at=? "
                "WHERE destination=? AND state='failed' "
                "AND alert_id IN ("
                "SELECT id FROM alerts WHERE (? IS NULL OR route = ?))",
                (stamp(now), destination, route, route),
            )
        return cursor.rowcount

    def outbox_failed_count(self, destination: str, route=None) -> int:
        self._destination_format(destination)
        if route is not None:
            text(route, "delivery route", 64)
        return self.db.execute(
            "SELECT COUNT(*) FROM outbox o JOIN alerts a ON a.id=o.alert_id "
            "WHERE o.destination=? AND o.state='failed' "
            "AND (? IS NULL OR a.route = ?)",
            (destination, route, route),
        ).fetchone()[0]

    def outbox_report(self) -> dict:
        rows = self.db.execute(
            "SELECT destination,state,COUNT(*) FROM outbox GROUP BY destination,state"
        ).fetchall()
        counts: dict[str, dict[str, int]] = {}
        for destination, state, count in rows:
            counts.setdefault(destination, {})[state] = count
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
        with self._write_guard():
            self.db.execute(
                "INSERT OR IGNORE INTO trail_files(digest,processed_at) VALUES(?,?)",
                (digest, stamp(now)),
            )

    def record_assurance(
        self, now: datetime, mode: str, ok: bool, failed_scenarios: int, details: dict
    ) -> str:
        text(mode, "assurance mode", 32)
        if type(failed_scenarios) is not int or failed_scenarios < 0:
            raise ContractError("failed scenario count must be a nonnegative integer")
        run_id = uuid.uuid4().hex
        with self._write_guard():
            self.db.execute(
                "INSERT INTO assurance_runs(ran_at,mode,ok,failed_scenarios,details,run_id) "
                "VALUES(?,?,?,?,?,?)",
                (
                    stamp(now),
                    mode,
                    1 if ok else 0,
                    failed_scenarios,
                    canonical(required_dict(details, "assurance details")),
                    run_id,
                ),
            )
        return run_id

    def assurance_history(self, limit: int = 50) -> list[dict]:
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise ContractError("assurance history limit must be 1 to 1000")
        rows = self.db.execute(
            "SELECT id,ran_at,mode,ok,failed_scenarios,details,run_id "
            "FROM assurance_runs ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [
            {
                "id": row_id,
                "run_id": run_id,
                "ran_at": ran_at,
                "mode": mode,
                "ok": bool(ok),
                "failed_scenarios": failed,
                "details": json.loads(details),
            }
            for row_id, ran_at, mode, ok, failed, details, run_id in rows
        ]

    ACCEPTANCE_STAGES = ("ingestion", "analyst_acknowledgment")

    def record_acceptance(
        self, now: datetime, stage: str, note: str, actor: str
    ) -> int:
        if stage not in self.ACCEPTANCE_STAGES:
            raise ContractError("unsupported acceptance stage")
        text(note, "acceptance note", 512)
        text(actor, "acceptance actor", 200)
        with self._write_guard():
            cursor = self.db.execute(
                "INSERT INTO acceptances(stage,note,actor,recorded_at) VALUES(?,?,?,?)",
                (stage, note, actor, stamp(now)),
            )
        return cursor.lastrowid

    def acceptances(self, limit: int = 100) -> list[dict]:
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise ContractError("acceptance limit must be 1 to 1000")
        rows = self.db.execute(
            "SELECT id,stage,note,actor,recorded_at FROM acceptances "
            "ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [
            {
                "id": row_id,
                "stage": stage,
                "note": note,
                "actor": actor,
                "recorded_at": recorded_at,
            }
            for row_id, stage, note, actor, recorded_at in rows
        ]

    def last_assurance(self):
        history = self.assurance_history(1)
        return history[0] if history else None

    def prune(self, now: datetime, older_than_days: int) -> dict:
        if type(older_than_days) is not int or not 1 <= older_than_days <= 3650:
            raise ContractError("retention days must be 1 to 3650")
        cutoff = stamp(now - timedelta(days=older_than_days))
        counts = {}
        with self._write_guard():
            # Destructive retention on a signed chain requires the matching key
            # and a currently valid chain; nothing is deleted otherwise.
            self._ensure_chain_key()
            signed_alerts = self._signed_alert_count()
            doomed = self.db.execute(
                "SELECT COUNT(*) FROM alerts WHERE received_at < ?", (cutoff,)
            ).fetchone()[0]
            retained = self.db.execute(
                "SELECT id,prev_mac FROM alerts WHERE received_at >= ? "
                "ORDER BY rowid LIMIT 1",
                (cutoff,),
            ).fetchone()
            if self.mac_key is not None and signed_alerts and doomed:
                boundary = (retained[1] if retained else None) or ""
                fields = self._checkpoint_fields(
                    stamp(now),
                    cutoff,
                    doomed,
                    boundary,
                    retained[0] if retained else None,
                )
                mac = hmac.new(
                    self.mac_key, canonical(fields).encode(), hashlib.sha256
                ).hexdigest()
                self.db.execute(
                    "INSERT INTO checkpoints(created_at,pruned_before,deleted_alerts,"
                    "boundary_prev_mac,first_retained_id,mac) VALUES(?,?,?,?,?,?)",
                    (
                        fields["created_at"],
                        cutoff,
                        doomed,
                        boundary,
                        fields["first_retained_id"],
                        mac,
                    ),
                )
            counts["alerts"] = self.db.execute(
                "DELETE FROM alerts WHERE received_at < ?", (cutoff,)
            ).rowcount
            counts["outbox"] = self.db.execute(
                "DELETE FROM outbox WHERE updated_at < ?", (cutoff,)
            ).rowcount
            # Alerts removed above must not leave outbox rows that can never
            # be delivered or drained.
            counts["outbox"] += self.db.execute(
                "DELETE FROM outbox WHERE alert_id NOT IN (SELECT id FROM alerts)"
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
        # VACUUM cannot run inside a transaction; take the writer lock only.
        handle = None
        if self._db_path is not None:
            handle = acquire_database_lock(self._db_path, timeout=60.0)
        try:
            if self.db.in_transaction:
                self.db.commit()
            self.db.execute("VACUUM INTO ?", (str(path),))
        finally:
            if handle is not None:
                release_database_lock(handle)
        return str(path)


RESTORE_TABLES = {
    "decisions": {"event_key", "fingerprint", "result", "created_at"},
    "alerts": {
        "id",
        "decoy",
        "actor",
        "opened_at",
        "received_at",
        "evidence",
        "acknowledged_at",
        "acknowledged_by",
        "evidence_mac",
        "prev_mac",
        "route",
    },
    "outbox": {
        "alert_id",
        "payload_format",
        "state",
        "attempts",
        "last_error",
        "updated_at",
    },
    "trail_files": {"digest", "processed_at"},
    "assurance_runs": {"id", "ran_at", "mode", "ok", "failed_scenarios", "details"},
    "checkpoints": {
        "id",
        "created_at",
        "pruned_before",
        "deleted_alerts",
        "boundary_prev_mac",
        "first_retained_id",
        "mac",
    },
}

RESTORE_SCHEMA_SQL = {
    table: f"PRAGMA table_info({table})" for table in RESTORE_TABLES
}


def _validate_restore_source(src: Path):
    """Reject anything that is not a complete, healthy Fool's Gold database.

    Validation runs before the destination is touched; a failure leaves it
    untouched.
    """
    try:
        check = sqlite3.connect(f"file:{src}?mode=ro", uri=True)
        try:
            integrity = check.execute("PRAGMA integrity_check").fetchone()
            if not integrity or integrity[0] != "ok":
                raise ContractError(
                    "restore source failed SQLite integrity_check"
                )
            tables = {
                row[0]
                for row in check.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
            missing = set(RESTORE_TABLES) - tables
            if missing:
                raise ContractError(
                    "restore source is missing required tables: "
                    + ", ".join(sorted(missing))
                )
            for table, columns in RESTORE_TABLES.items():
                actual = {
                    row[1] for row in check.execute(RESTORE_SCHEMA_SQL[table])
                }
                absent = columns - actual
                if absent:
                    raise ContractError(
                        f"restore source table {table} is missing columns: "
                        + ", ".join(sorted(absent))
                    )
        finally:
            check.close()
    except sqlite3.Error as exc:
        raise ContractError(
            "restore source is not a readable Fool's Gold database"
        ) from exc


def restore_database(source, destination) -> str:
    """Exclusively replace a closed database with a validated backup.

    Procedure: validate the source, take the writer lock (fails for an active
    destination), checkpoint/recover the destination, copy the source to a
    temp file in the destination directory, remove the destination's stale
    sidecars while the writer lock is held, then atomically replace the main
    file. Any failure leaves the destination untouched.
    """
    src = Path(source)
    dst = Path(destination)
    if src.is_symlink() or not src.is_file():
        raise ContractError("restore source must be a regular file")
    wal = Path(str(src) + "-wal")
    if wal.exists() and wal.stat().st_size > 0:
        raise ContractError(
            "restore source has uncommitted WAL data; use a file written by `backup`"
        )
    if dst.is_symlink() or not dst.parent.is_dir():
        raise ContractError(
            "restore requires an existing trusted directory and a nonsymlink leaf"
        )
    _validate_restore_source(src)
    # Restore requires exclusive access: no other Fool's Gold session and no
    # in-flight writer may touch the destination while it is replaced.
    session = SessionLock(dst)
    session.acquire(exclusive=True, timeout=0)
    lock = None
    try:
        lock = acquire_database_lock(dst, timeout=0)
        if dst.exists():
            # Recover any crash-created destination WAL under the writer lock.
            try:
                check = sqlite3.connect(str(dst), timeout=1)
                try:
                    check.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                finally:
                    check.close()
            except sqlite3.Error as exc:
                raise ContractError(
                    "restore destination is not recoverable; close all connections"
                ) from exc
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
            # The destination has no active writer (we hold the lock) and its
            # WAL was checkpointed above, so remaining sidecars are stale and
            # must not survive the replacement.
            for suffix in ("-wal", "-shm"):
                sidecar = Path(str(dst) + suffix)
                if sidecar.exists():
                    sidecar.unlink()
            os.replace(temporary, dst)
        except OSError as exc:
            try:
                temporary.unlink()
            except OSError:
                pass
            raise ContractError(
                "restore could not replace the destination"
            ) from exc
    finally:
        if lock is not None:
            release_database_lock(lock)
        session.release()
    return str(dst)
