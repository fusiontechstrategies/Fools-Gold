# Changelog

All notable changes to Fool's Gold are documented here. The project follows the honesty discipline of the README: a listed capability means it is implemented and covered by the test suite, not that it has been verified against production infrastructure.

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
