"""Incident timelines and tamper-evident evidence bundles. Local files only."""

import hashlib
import hmac
import json
import re
import zipfile
from datetime import UTC, datetime
from pathlib import Path

from .core import ContractError, canonical, instant, parse_json, stamp

MAX_ENTRY_BYTES = 32 * 1024 * 1024
MAX_BUNDLE_BYTES = 128 * 1024 * 1024
BUNDLE_PAYLOADS = {
    "alerts.jsonl",
    "report.json",
    "checkpoints.jsonl",
    "annotations.jsonl",
    "delivery.jsonl",
    "assurance.jsonl",
    "acceptances.jsonl",
}
BUNDLE_FILES = BUNDLE_PAYLOADS | {"manifest.json", "manifest.sig"}
SUPPLEMENTAL_FILES = (
    "annotations.jsonl",
    "delivery.jsonl",
    "assurance.jsonl",
    "acceptances.jsonl",
)
MAX_GAP_SECONDS = 86400


def incidents(engine, gap_seconds: int = 300) -> dict:
    """Cluster alerts per actor into incidents without dropping any evidence."""
    if type(gap_seconds) is not int or not 1 <= gap_seconds <= MAX_GAP_SECONDS:
        raise ContractError("gap seconds must be an integer from 1 to 86400")
    rows = engine.db.execute(
        "SELECT id,actor,received_at,acknowledged_at,evidence FROM alerts "
        "ORDER BY actor,received_at,id"
    ).fetchall()
    clusters = []
    current = None
    for alert_id, actor, received_at, acknowledged, evidence in rows:
        alert = json.loads(evidence)
        received = instant(received_at)
        same_run = (
            current is not None
            and current["actor"] == actor
            and (received - instant(current["last_seen"])).total_seconds()
            <= gap_seconds
        )
        if same_run:
            current["last_seen"] = stamp(received)
            current["alert_count"] += 1
            current["alert_ids"].append(alert_id)
            current["decoys"] = sorted({*current["decoys"], alert["decoy_id"]})
            current["actions"] = sorted(
                {*current["actions"], *alert["event"]["actions"]}
            )
            current["mitre_techniques"] = sorted(
                {*current["mitre_techniques"], *(alert.get("mitre_techniques") or [])}
            )
            current["acknowledged"] += 1 if acknowledged else 0
            current["max_telemetry_delay_seconds"] = max(
                current["max_telemetry_delay_seconds"],
                alert["telemetry_delay_seconds"],
            )
        else:
            current = {
                "actor": actor,
                "first_seen": stamp(received),
                "last_seen": stamp(received),
                "alert_count": 1,
                "acknowledged": 1 if acknowledged else 0,
                "alert_ids": [alert_id],
                "decoys": [alert["decoy_id"]],
                "actions": sorted(set(alert["event"]["actions"])),
                "mitre_techniques": sorted(set(alert.get("mitre_techniques") or [])),
                "max_telemetry_delay_seconds": alert["telemetry_delay_seconds"],
            }
            clusters.append(current)
    return {"schema_version": 1, "incidents": clusters}


def build_bundle(engine, target, now: datetime | None = None) -> str:
    """Write alerts, report and manifest (plus HMAC signature when keyed)."""
    now = now or datetime.now(UTC)
    path = Path(target)
    if path.is_symlink() or not path.parent.is_dir():
        raise ContractError(
            "bundle requires an existing trusted directory and a nonsymlink leaf"
        )
    if path.exists():
        raise ContractError("bundle target already exists")
    with engine.read_snapshot():
        files = _capture_bundle(engine, now)
    # Filesystem work happens after the read snapshot has been released.
    with zipfile.ZipFile(path, "x") as archive:
        for name, data in files.items():
            archive.writestr(name, data)
    return str(path)


def _capture_bundle(engine, now):
    """Capture all bundle components from the caller's read snapshot."""
    alerts = list(engine.export_alerts())
    integrity = engine.verify_integrity() if engine.mac_key is not None else None
    checkpoints = [
        {
            "id": row[0],
            "created_at": row[1],
            "pruned_before": row[2],
            "deleted_alerts": row[3],
            "boundary_prev_mac": row[4],
            "first_retained_id": row[5],
            "mac": row[6],
        }
        for row in engine.db.execute(
            "SELECT id,created_at,pruned_before,deleted_alerts,"
            "boundary_prev_mac,first_retained_id,mac FROM checkpoints ORDER BY id"
        )
    ]
    annotations = [
        {
            "alert_id": alert_id,
            "acknowledged_at": acknowledged_at,
            "acknowledged_by": acknowledged_by,
        }
        for alert_id, acknowledged_at, acknowledged_by in engine.db.execute(
            "SELECT id,acknowledged_at,acknowledged_by FROM alerts "
            "WHERE acknowledged_at IS NOT NULL ORDER BY id"
        )
    ]
    delivery_rows = [
        {
            "alert_id": alert_id,
            "destination": destination,
            "payload_format": payload_format,
            "state": state,
            "attempts": attempts,
            "last_error": last_error,
            "updated_at": updated_at,
        }
        for (
            alert_id,
            destination,
            payload_format,
            state,
            attempts,
            last_error,
            updated_at,
        ) in engine.db.execute(
            "SELECT alert_id,destination,payload_format,state,attempts,"
            "last_error,updated_at FROM outbox ORDER BY alert_id,destination"
        )
    ]
    assurance_runs = list(reversed(engine.assurance_history(1000)))
    acceptances = list(reversed(engine.acceptances(1000)))
    supplemental = {
        "checkpoints": len(checkpoints),
        "annotations": len(annotations),
        "delivery": len(delivery_rows),
        "assurance_runs": len(assurance_runs),
        "acceptances": len(acceptances),
    }
    files = {
        "alerts.jsonl": "".join(canonical(alert) + "\n" for alert in alerts).encode(),
        "checkpoints.jsonl": "".join(
            canonical(checkpoint) + "\n" for checkpoint in checkpoints
        ).encode(),
        "annotations.jsonl": "".join(
            canonical(annotation) + "\n" for annotation in annotations
        ).encode(),
        "delivery.jsonl": "".join(
            canonical(row) + "\n" for row in delivery_rows
        ).encode(),
        "assurance.jsonl": "".join(
            canonical(run) + "\n" for run in assurance_runs
        ).encode(),
        "acceptances.jsonl": "".join(
            canonical(item) + "\n" for item in acceptances
        ).encode(),
        "report.json": canonical(
            {
                "schema_version": 1,
                "report": engine.report(),
                "outbox": engine.outbox_report(),
                "integrity": integrity,
                "supplemental": supplemental,
            }
        ).encode(),
    }
    manifest = {
        "schema_version": 1,
        "created_at": stamp(now),
        "alerts": len(alerts),
        "integrity_ok": None if integrity is None else integrity["ok"],
        "file_sha256": {
            name: hashlib.sha256(data).hexdigest() for name, data in files.items()
        },
    }
    manifest_bytes = canonical(manifest).encode()
    if engine.mac_key is not None:
        files["manifest.sig"] = hmac.new(
            engine.mac_key, manifest_bytes, hashlib.sha256
        ).hexdigest().encode()
    files["manifest.json"] = manifest_bytes
    return files


def verify_bundle(path, mac_key: bytes | None = None) -> dict:
    """Validate entry hashes and, when keyed, the manifest signature."""
    bundle = Path(path)
    if bundle.is_symlink() or not bundle.is_file():
        raise ContractError("bundle must be a regular file")
    try:
        with zipfile.ZipFile(bundle) as archive:
            entries = archive.namelist()
            names = set(entries)
            if len(entries) != len(names):
                raise ContractError("bundle contains duplicate entries")
            if not names <= BUNDLE_FILES:
                raise ContractError("bundle contains unexpected entries")
            if not BUNDLE_PAYLOADS <= names:
                raise ContractError(
                    "bundle requires alerts.jsonl and report.json entries"
                )
            data = {}
            total = 0
            for name in names:
                info = archive.getinfo(name)
                if info.file_size > MAX_ENTRY_BYTES:
                    raise ContractError("bundle entry exceeds the size limit")
                total += info.file_size
                if total > MAX_BUNDLE_BYTES:
                    raise ContractError("bundle exceeds the total size limit")
                data[name] = archive.read(name)
    except (zipfile.BadZipFile, OSError) as exc:
        raise ContractError("bundle is not a readable zip archive") from exc
    manifest = parse_json(data["manifest.json"])
    if not isinstance(manifest, dict) or set(manifest) != {
        "schema_version",
        "created_at",
        "alerts",
        "integrity_ok",
        "file_sha256",
    }:
        raise ContractError("bundle manifest has an unexpected shape")
    if (
        type(manifest["schema_version"]) is not int
        or manifest["schema_version"] != 1
    ):
        raise ContractError("unsupported bundle manifest schema")
    if manifest["integrity_ok"] not in (True, False, None):
        raise ContractError("bundle manifest has an invalid integrity flag")
    if type(manifest["alerts"]) is not int or manifest["alerts"] < 0:
        raise ContractError("bundle manifest has an invalid alert count")
    instant(manifest["created_at"])
    hashes = manifest["file_sha256"]
    if not isinstance(hashes, dict) or set(hashes) != BUNDLE_PAYLOADS:
        raise ContractError("bundle manifest does not cover the entry set")
    failures = []
    for name, expected in hashes.items():
        if not isinstance(expected, str) or not re.fullmatch(
            r"[0-9a-f]{64}", expected
        ):
            raise ContractError("bundle manifest contains an invalid digest")
        if hashlib.sha256(data[name]).hexdigest() != expected:
            failures.append(name)
    try:
        alert_lines = [
            line for line in data["alerts.jsonl"].splitlines() if line.strip()
        ]
        alerts = [parse_json(line) for line in alert_lines]
    except (ContractError, UnicodeError) as exc:
        raise ContractError("bundle alerts are not valid JSONL") from exc
    if any(not isinstance(alert, dict) for alert in alerts):
        raise ContractError("bundle alerts must be JSON objects")
    if manifest["alerts"] != len(alerts):
        raise ContractError("manifest alert count does not match the payload")
    report = parse_json(data["report.json"])
    if not isinstance(report, dict) or set(report) != {
        "schema_version",
        "report",
        "outbox",
        "integrity",
        "supplemental",
    }:
        raise ContractError("bundle report has an unexpected shape")
    parsed = {}
    for name in ("checkpoints.jsonl",) + SUPPLEMENTAL_FILES:
        try:
            lines = [line for line in data[name].splitlines() if line.strip()]
            items = [parse_json(line) for line in lines]
        except (ContractError, UnicodeError) as exc:
            raise ContractError(f"bundle {name} is invalid") from exc
        if any(not isinstance(item, dict) for item in items):
            raise ContractError(f"bundle {name} entries must be objects")
        parsed[name] = items
    supplemental = report["supplemental"]
    expected_counts = {
        "checkpoints": len(parsed["checkpoints.jsonl"]),
        "annotations": len(parsed["annotations.jsonl"]),
        "delivery": len(parsed["delivery.jsonl"]),
        "assurance_runs": len(parsed["assurance.jsonl"]),
        "acceptances": len(parsed["acceptances.jsonl"]),
    }
    if not isinstance(supplemental, dict) or supplemental != expected_counts:
        raise ContractError(
            "bundle report supplemental counts do not match payloads"
        )
    signature = None
    if "manifest.sig" in data:
        if mac_key is None:
            signature = "unverified"
        else:
            expected = hmac.new(
                mac_key, data["manifest.json"], hashlib.sha256
            ).hexdigest()
            try:
                provided = data["manifest.sig"].decode("ascii")
            except UnicodeError:
                provided = ""
            signature = (
                "verified"
                if hmac.compare_digest(expected, provided)
                else "invalid"
            )
    elif mac_key is not None:
        # A keyed verification must not accept a bundle whose signature was
        # stripped; otherwise an attacker can downgrade to an unsigned bundle.
        signature = "missing"
    authenticated = signature == "verified"
    source_integrity_ok = manifest["integrity_ok"]
    archive_ok = not failures
    return {
        "schema_version": 1,
        "alerts": manifest["alerts"],
        "created_at": manifest["created_at"],
        "integrity_ok": source_integrity_ok,
        "source_integrity_ok": source_integrity_ok,
        "files_ok": archive_ok,
        "archive_ok": archive_ok,
        "failures": failures,
        "signature": signature,
        "authenticated": authenticated,
        "ok": (
            archive_ok
            and signature not in ("missing", "invalid")
            and source_integrity_ok is not False
        ),
    }
