"""Operator onboarding: registry bootstrap, synthetic decoy files and a demo.

Every generated artifact is synthetic and local. Decoy content is watermarked
and never resembles a working credential or key.
"""

import html
import json
import os
import secrets
from datetime import UTC, datetime, timedelta
from pathlib import Path

from .assurance import assurance_report, canary_events, canary_registry
from .core import ContractError, Engine, Registry, stamp
from .reporting import incidents

MAX_DECOY_BYTES = 4096
DEFAULT_LIFETIME_DAYS = 30
DECOY_KINDS = ("aws-credentials", "ssh-key", "config-export")

DECOY_TEMPLATES = {
    "aws-credentials": (
        "# SYNTHETIC DECOY - NOT REAL CREDENTIALS\n"
        "# Touching this file is the tripwire.\n"
        "[default]\n"
        "aws_access_key_id = SYNTHETIC-ACCESS-KEY-NOT-REAL\n"
        "aws_secret_access_key = SYNTHETIC/NOT/A/REAL/SECRET/KEY/EXAMPLE\n"
        "region = us-gov-west-1\n"
    ),
    "ssh-key": (
        "-----BEGIN SYNTHETIC DECOY KEY-----\n"
        "SYNTHETIC DECOY KEY - NOT A REAL OPENSSH PRIVATE KEY\n"
        "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAAB\n"
        "-----END SYNTHETIC DECOY KEY-----\n"
    ),
    "config-export": (
        "# SYNTHETIC DECOY - CONFIGURATION EXPORT\n"
        "environment = synthetic\n"
        "api_endpoint = https://example.invalid/\n"
        "database_password = SYNTHETIC-NOT-A-REAL-PASSWORD\n"
        "backup_window = 02:00-03:00\n"
    ),
}


def _protected_write(target: Path, data: bytes, *, force: bool = False):
    if target.is_symlink() or not target.parent.is_dir():
        raise ContractError(
            "output requires an existing trusted directory and a nonsymlink leaf"
        )
    if target.exists() and not force:
        raise ContractError(f"{target.name} already exists; use --force to replace")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0)
    descriptor = (
        os.open(target, flags, 0o600) if os.name != "nt" else os.open(target, flags)
    )
    try:
        os.write(descriptor, data)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write_registry(folder, *, owner, s3=None, windows=None, linux=None, now=None) -> str:
    now = now or datetime.now(UTC)
    decoys = []
    if s3:
        decoys.append(
            {
                "id": "decoy-s3-1",
                "owner": owner,
                "source": "aws.cloudtrail.s3",
                "locator": {
                    "account": s3["account"],
                    "region": s3.get("region", "us-gov-west-1"),
                    "arn": f"arn:aws-us-gov:s3:::{s3['bucket']}/{s3['key']}",
                },
                "created_at": stamp(now),
                "expires_at": stamp(now + timedelta(days=DEFAULT_LIFETIME_DAYS)),
                "expected_actions": ["read", "write", "append", "delete", "recon"],
                "response_procedure": "Triage: verify actor and contact the owner",
            }
        )
    if windows:
        decoys.append(
            {
                "id": "decoy-windows-1",
                "owner": owner,
                "source": "windows.security",
                "locator": {"host": windows["host"], "path": windows["path"]},
                "created_at": stamp(now),
                "expires_at": stamp(now + timedelta(days=DEFAULT_LIFETIME_DAYS)),
                "expected_actions": ["read", "write", "append", "delete"],
                "response_procedure": "Triage: inspect process and confirm authorized testing",
            }
        )
    if linux:
        decoys.append(
            {
                "id": "decoy-linux-1",
                "owner": owner,
                "source": "linux.audit",
                "locator": {"host": linux["host"], "path": linux["path"]},
                "created_at": stamp(now),
                "expires_at": stamp(now + timedelta(days=DEFAULT_LIFETIME_DAYS)),
                "expected_actions": ["read", "write", "append", "delete", "recon"],
                "response_procedure": "Triage: inspect uid, process and path",
            }
        )
    if not decoys:
        raise ContractError("init requires at least one decoy location")
    document = {"schema_version": 1, "decoys": decoys}
    Registry(document)  # fail closed before writing
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    target = folder / "registry.json"
    if target.exists():
        raise ContractError("registry.json already exists")
    target.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    return str(target)


def write_key(folder, name="evidence.key") -> str:
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    target = folder / name
    if target.exists():
        raise ContractError(f"{name} already exists")
    _protected_write(target, (secrets.token_hex(32) + "\n").encode("ascii"))
    return str(target)


def write_decoy(kind: str, out, *, force: bool = False) -> str:
    if kind not in DECOY_KINDS:
        raise ContractError("unsupported decoy kind")
    data = DECOY_TEMPLATES[kind].encode("utf-8")
    if len(data) > MAX_DECOY_BYTES:
        raise ContractError("decoy content exceeds bounds")
    _protected_write(Path(out), data, force=force)
    return str(out)


def _render_report(alerts, summary, incident_data, outbox, now) -> str:
    rows = []
    for alert in alerts[:200]:
        rows.append(
            "<tr>"
            f"<td>{html.escape(alert['alert_id'])}</td>"
            f"<td>{html.escape(alert['decoy_id'])}</td>"
            f"<td>{html.escape(alert['event']['actor'])}</td>"
            f"<td>{html.escape(', '.join(alert['event']['actions']))}</td>"
            f"<td>{html.escape(alert['event']['outcome'])}</td>"
            f"<td>{alert['telemetry_delay_seconds']}</td>"
            f"<td>{html.escape(', '.join(alert.get('mitre_techniques') or []))}</td>"
            "</tr>"
        )
    return (
        "<!doctype html><html><head><meta charset='utf-8'>"
        "<title>Fool's Gold demo report</title><style>"
        "body{font-family:system-ui,sans-serif;margin:2rem;color:#1b1b1b}"
        "table{border-collapse:collapse;width:100%}th,td{border:1px solid #ccc;"
        "padding:.35rem .5rem;font-size:.85rem;text-align:left}"
        "th{background:#f2f2f2}.note{color:#555;font-size:.85rem}"
        "</style></head><body>"
        f"<h1>Fool's Gold demo report</h1>"
        f"<p class='note'>Generated {html.escape(stamp(now))}. Synthetic canary "
        "data only; not a deployed result.</p>"
        f"<p>Alerts: <strong>{len(alerts)}</strong> &middot; Assurance runs: "
        f"<strong>{summary['runs']}</strong> &middot; MTTD p50: "
        f"<strong>{summary['mttd_seconds']['p50']}</strong>s &middot; MTTA p50: "
        f"<strong>{summary['mtta_seconds']['p50']}</strong>s &middot; "
        f"Incidents: <strong>{len(incident_data['incidents'])}</strong> &middot; "
        f"Outbox: {html.escape(json.dumps(outbox['outbox'], sort_keys=True))}</p>"
        "<table><thead><tr><th>Alert</th><th>Decoy</th><th>Actor</th>"
        "<th>Actions</th><th>Outcome</th><th>Delay (s)</th><th>ATT&amp;CK</th>"
        "</tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table></body></html>\n"
    )


def create_demo(folder, now=None) -> dict:
    now = now or datetime.now(UTC)
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    registry_path = folder / "registry.json"
    database_path = folder / "evidence.sqlite"
    report_path = folder / "report.html"
    for target in (registry_path, database_path, report_path):
        if target.exists():
            raise ContractError(f"demo target already exists: {target.name}")
    registry_document = canary_registry(now)
    registry_path.write_text(
        json.dumps(registry_document, indent=2) + "\n", encoding="utf-8"
    )
    engine = Engine(Registry(registry_document), database_path)
    try:
        alerts = []
        for _name, event in canary_events(now):
            result = engine.process(event, now)
            if result["decision"] != "alert":
                raise ContractError("demo canary failed to alert")
            engine.acknowledge(
                result["alert"]["alert_id"],
                "demo-analyst",
                now + timedelta(seconds=30),
            )
            alerts.append(result["alert"])
        summary = assurance_report(engine, now=now)
        incident_data = incidents(engine)
        outbox = engine.outbox_report()
    finally:
        engine.close()
    report_path.write_text(
        _render_report(alerts, summary, incident_data, outbox, now), encoding="utf-8"
    )
    return {
        "registry": str(registry_path),
        "database": str(database_path),
        "report": str(report_path),
        "alerts": len(alerts),
    }
