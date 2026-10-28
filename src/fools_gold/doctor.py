"""Local deployment readiness checks. Read-only and bounded."""

import platform
import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path

from .core import instant

EXPIRY_WARNING_DAYS = 14


def run_doctor(engine, *, inbox=None, max_assurance_hours=None, now=None) -> dict:
    now = now or datetime.now(UTC)
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

    last = engine.last_assurance()
    if last is None:
        record(
            "assurance",
            "fail" if max_assurance_hours is not None else "warn",
            "no assurance run recorded",
        )
    else:
        age_hours = (now - instant(last["ran_at"])).total_seconds() / 3600
        if max_assurance_hours is None:
            record("assurance", "pass" if last["ok"] else "warn", f"last ok={last['ok']}")
        else:
            status = (
                "pass" if last["ok"] and age_hours <= max_assurance_hours else "fail"
            )
            record(
                "assurance",
                status,
                f"last ok={last['ok']} age_hours={round(age_hours, 2)}",
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

    if platform.system() == "Windows":
        record(
            "windows_collector",
            "pass" if shutil.which("wevtutil") else "fail",
            "wevtutil availability",
        )
    else:
        record(
            "linux_audit_sensor",
            "warn",
            "collector contract only; stage auditd exports for ingest",
        )

    return {
        "schema_version": 1,
        "ok": all(check["status"] != "fail" for check in checks),
        "checks": checks,
    }
