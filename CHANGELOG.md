# Changelog

All notable changes to Fool's Gold are documented here. The project follows the honesty discipline of the README: a listed capability means it is implemented and covered by the test suite, not that it has been verified against production infrastructure.

## 0.3.0 — 2026-10-28

### Added

- **Detection depth:** S3 `HeadObject` and bucket listings (`ListObjects`/`ListObjectsV2`) map to a new `recon` action and match registered bucket prefixes; `GetObjectVersion` reads and `CopyObject` destination writes are supported. Windows Security event **4656** (denied handle attempts) is a first-class denied contract, including the XML adapter. A documented **`linux.audit`** sensor contract covers POSIX file access.
- **Triage context:** every alert carries coarse ATT&CK tags (`T1530`, `T1005`, `T1526`) and an optional per-decoy `route`; the new `incidents` command clusters alerts per actor without dropping evidence.
- **Assurance as a product:** `assure` records each canary run (optionally with `--live` probing real registered decoy files and waiting for the alert), and `assure-report` publishes MTTD/MTTA percentiles plus a `--max-age-hours` staleness gate for cron/dead-man's-switch use.
- **Evidence handling:** `bundle` writes a tamper-evident zip (entry hashes + manifest, HMAC-signed when an evidence key is configured) and `verify-bundle` validates it; `prune`, `backup` and `restore` cover retention and recovery; SQLite now runs in WAL mode with a busy timeout.
- **Operator UX:** `doctor` checks registry, expiry, integrity, outbox, assurance, inbox and collector readiness; `init` writes a validated starter registry and key; `plant` writes watermarked synthetic decoy files; `demo` builds a self-contained demo database and HTML report; `serve` runs a loopback-only, bearer-token dashboard with `/api/*` endpoints, `/healthz` and Prometheus `/metrics`.
- **Delivery:** route-filtered enqueueing (`deliver --route`).
- **Artifacts:** Dockerfile, Compose file, systemd inbox service/timer, Terraform skeleton, and Splunk/Elastic/Sentinel starter content.
- **Tests:** 202 tests including adversarial, hardening and maintenance coverage.

### Enhanced

- The dashboard is browser-usable: login form with short-lived HttpOnly session cookies, CSRF-protected acknowledgment, alert filters (search/source/decoy/route/ack), stable pagination, alert detail with event/receipt/delivery/acknowledgment times, incidents view and summary cards, while the bearer API and metrics endpoint remain available.

### Hardened

- Wazuh file delivery now routes open/write/fsync/zero-progress failures through the durable outbox failure path, completes short writes, closes descriptors reliably, and documents at-least-once duplicate ambiguity instead of claiming exactly-once delivery.
- S3 listings are accepted as documented bucket-level data events (Management retained for older trails), versioned reads carry `context.version_id`, and the Terraform selector now uses a valid bucket-level data-event selector instead of unsupported management-event filtering.
- Windows collection now aligns with real wevtutil output (empty, concatenated Event roots, wrapped/unwrapped, UTF-16), skips unsupported individual records without aborting a batch, pages oldest-first from a durable cursor with bounded catch-up, and reports log rollover/coverage gaps. State loading validates stored timestamps.
- Restore validates source SQLite integrity and the complete application schema, checkpoints the destination under an exclusive writer lock, removes stale destination sidecars, and refuses an active database; the single-writer lock is now enforced for file databases.
- Bundle verification requires signatures whenever a key is supplied, rejects downgraded, manifest-only or count-mismatched bundles, and reports `authenticated`, `archive_ok` and `source_integrity_ok` separately.
- Retention writes signed checkpoints so pruning old alerts no longer breaks chain verification; unauthorized deletions and tampered checkpoints still fail. Bundles and backups carry the retention boundary.
- Route filtering applies to delivery batches, not just enqueueing, so one run cannot send another route's pending alerts.
- Delivery accept Lists Linux audit events and `recon` actions (previously rejected at render time), and flat Wazuh records carry `fg_route` and `fg_mitre`.
- Dashboard API responses are bounded (`/api/alerts?limit=`, 5000 max) with `nosniff`/`no-store` headers.
- `prune` removes orphaned outbox rows; `restore` rejects sources with uncommitted WAL data and never leaves a partial file.
- Bundle verification pins the manifest schema, rejects duplicate zip entries, and validates manifest field types.
- `doctor` validates its age bound and warns when file decoys are registered for a different host.

### Changed

- `--registry`/`--database` are required only by commands that use them; `check`, `init`, `plant`, `demo`, `restore` and `verify-bundle` run standalone.

## 0.2.0 — 2026-10-28

### Added

- **Windows Security log collector** (`collect` via `fools_gold.winlog`): one fixed `wevtutil` XPath query for event 4663, hardened XML envelope parsing shared with the export adapter, and emission filtered to registered decoy locations. Contract failures are skipped with a visible count.
- **CloudTrail trail inbox** (`trail-inbox` command): processes CloudTrail log files from a watched local directory, gzip-aware with bounded decompression, 16 MiB/10,000-record/64 KiB bounds, and idempotent processing by SHA-256 file digest. Files with malformed records stay unmarked for retry.
- **Durable delivery** (`deliver` command): persistent SQLite outbox per format; Splunk HEC over verified HTTPS (default trust, fixed path, no redirects, token from `FG_SPLUNK_HEC_TOKEN` only) and Wazuh JSONL localfile append with fsync and POSIX 0600 creation; at most three attempts per packet with 1/2-second backoff, 0.25-second send pacing, 4 KiB response bound, durable per-attempt failure recording and `--retry-failed` requeueing.
- **Evidence integrity**: optional HMAC-SHA256 chaining of every stored alert via `--evidence-key-file` (32 bytes), with a `verify-integrity` command that recomputes the chain and reports tampering. Legacy databases are migrated in place.
- **Assurance check** (`check` command): self-contained canary registry, events and scenario suite in a temporary database, with an optional transport stage when the operator passes delivery arguments. `python -m scripts.run_synthetic_pilot` now delegates to it.
- Open-source release packaging: Apache-2.0 license, contribution guide, security policy, CI and security badges.

### Changed

- `--registry`/`--database` are now validated per command; `check` runs standalone.
- The strict JSON contract parser (`parse_json`, `no_duplicate_keys`) moved to `fools_gold.core`; the `fools_gold.cli` re-export is preserved.

## 0.1.0 — 2026-10-02

Initial offline pilot: registry, strict GovCloud CloudTrail S3 and Windows 4663 contracts, decision engine with persistent deduplication and correlation, scoped expiring exceptions, analyst acknowledgment, synthetic assurance exercise, bounded export converters, offline Wazuh/Splunk payload rendering, and a loopback-only mock transport helper.
