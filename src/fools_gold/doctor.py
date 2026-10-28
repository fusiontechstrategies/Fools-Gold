"""Local deployment readiness checks. Read-only and bounded."""

import platform
import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path

from .core import ContractError, instant

EXPIRY_WARNING_DAYS = 14
PENDING_WARNING_HOURS = 24


def run_doctor(
    engine,
    *,
    inbox=None,
    max_assurance_hours=None,
    assurance_mode=None,
    max_collection_hours=None,
    now=None,
) -> dict:
    now = now or datetime.now(UTC)
    if max_assurance_hours is not None and (
        type(max_assurance_hours) is not int
        or not 0 <= max_assurance_hours <= 24 * 3650
    ):
        raise ContractError("max assurance hours must be a nonnegative integer")
    if assurance_mode not in (None, "canary", "live"):
        raise ContractError("assurance mode must be canary or live")
    if max_collection_hours is not None and (
        type(max_collection_hours) is not int
        or not 0 <= max_collection_hours <= 24 * 365
    ):
        raise ContractError("max collection hours must be a nonnegative integer")
    checks = []

    def record(name, status, detail=""):
        checks.append({"name": name, "status": status, "detail": detail})

    decoys = engine.registry.decoys
    expired = [d["id"] for d in decoys if instant(d["expires_at"]) <= now]
    record(
        "registry",
        "warn" if expired else "pass",
        f"{len(decoys)} decoys" + (f"; expired: {expired}" if expired else ""),
    )
    expiring = [
        d["id"]
        for d in decoys
        if now < instant(d["expires_at"]) <= now + timedelta(days=EXPIRY_WARNING_DAYS)
    ]
    if expiring:
        record(
            "registry_expiry",
            "warn",
            f"expiring within {EXPIRY_WARNING_DAYS} days: {expiring}",
        )

    mode = engine.db.execute("PRAGMA journal_mode").fetchone()[0]
    record("database_journal", "pass" if mode.lower() in ("wal", "memory") else "warn", mode)

    if engine.mac_key is None:
        record("evidence_integrity", "warn", "no evidence key configured")
    else:
        outcome = engine.verify_integrity()
        record(
            "evidence_integrity",
            "pass" if outcome["ok"] else "fail",
            f"alerts={outcome['alerts']} failures={len(outcome['failures'])}",
        )

    outbox = engine.outbox_report()["outbox"]
    failed = sum(counts.get("failed", 0) for counts in outbox.values())
    pending = sum(counts.get("pending", 0) for counts in outbox.values())
    record(
        "delivery_outbox",
        "warn" if failed else "pass",
        f"pending={pending} failed={failed}",
    )
    oldest = engine.db.execute(
        "SELECT MIN(updated_at) FROM outbox WHERE state='pending'"
    ).fetchone()[0]
    if oldest:
        age_hours = (now - instant(oldest)).total_seconds() / 3600
        record(
            "delivery_backlog_age",
            "warn" if age_hours > PENDING_WARNING_HOURS else "pass",
            f"oldest pending {round(age_hours, 2)}h",
        )

    last = engine.last_assurance()
    history = engine.assurance_history(1000)
    if assurance_mode is not None:
        history = [run for run in history if run["mode"] == assurance_mode]
    last_ok = next((run for run in history if run["ok"]), None)
    if max_assurance_hours is None:
        if last is None:
            record("assurance", "warn", "no assurance run recorded")
        else:
            record(
                "assurance",
                "pass" if last["ok"] else "warn",
                f"last mode={last['mode']} ok={last['ok']}",
            )
    else:
        scope = f"{assurance_mode} " if assurance_mode else ""
        if last_ok is None:
            record("assurance", "fail", f"no successful {scope}assurance run")
        else:
            age_hours = (now - instant(last_ok["ran_at"])).total_seconds() / 3600
            record(
                "assurance",
                "pass" if age_hours <= max_assurance_hours else "fail",
                f"last successful {scope}run {round(age_hours, 2)}h ago",
            )

    if inbox is not None:
        path = Path(inbox)
        if not path.is_dir():
            record("trail_inbox", "fail", "missing directory")
        else:
            staged = [
                entry
                for entry in path.iterdir()
                if entry.is_file()
                and (
                    entry.name.endswith(".json") or entry.name.endswith(".json.gz")
                )
            ]
            record("trail_inbox", "pass", f"{len(staged)} file(s) staged")
            if max_collection_hours is not None:
                if not staged:
                    record(
                        "collection_freshness",
                        "warn",
                        "no staged files; collection may be stalled",
                    )
                else:
                    newest = max(entry.stat().st_mtime for entry in staged)
                    age_hours = (
                        now - datetime.fromtimestamp(newest, UTC)
                    ).total_seconds() / 3600
                    record(
                        "collection_freshness",
                        (
                            "pass"
                            if age_hours <= max_collection_hours
                            else "warn"
                        ),
                        f"newest staged file {round(age_hours, 2)}h old",
                    )

    host = (platform.node() or "").casefold()
    expected = [
        d
        for d in decoys
        if d["source"] in ("windows.security", "linux.audit")
        and d["locator"]["host"] == host
    ]
    if expected:
        missing = [
            d["id"] for d in expected if not Path(d["locator"]["path"]).exists()
        ]
        record(
            "decoy_files",
            "fail" if missing else "pass",
            f"missing: {missing}" if missing else f"{len(expected)} present",
        )
    elif any(
        d["source"] in ("windows.security", "linux.audit") for d in decoys
    ):
        record(
            "decoy_files",
            "warn",
            f"no file decoys registered for host {host or '(unknown)'}",
        )

    if platform.system() == "Windows":
        record(
            "windows_collector",
            "pass" if shutil.which("wevtutil") else "fail",
            "wevtutil availability",
        )
    else:
        record(
            "linux_audit_sensor",
            "unverified",
            "collector contract only; stage auditd exports for ingest",
        )
    record(
        "audit_policy",
        "unverified",
        "file SACL/audit policy (and SMB access auditing) require manual verification",
    )

    return {
        "schema_version": 1,
        "ok": all(check["status"] != "fail" for check in checks),
        "checks": checks,
    }
