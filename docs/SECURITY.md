# Security boundaries and limits

## Defenses in the offline pilot

- Exact resource matching scoped by GovCloud account/region or Windows host/path.
- Expiring actor/action exceptions checked at event and receipt time; denied S3 attempts never take those exceptions.
- Parameterized SQL. No evaluation, subprocess launch, remote callbacks or telemetry-driven file access.
- JSON object duplicate keys/nonfinite numbers rejected by CLI; 1 MiB registry, 64 KiB event records and 100,000 records per ingestion run.
- JSON nesting is limited to 32 levels/100,000 value nodes. The offline Windows XML adapter forbids DTD/entities and enforces input/tree/field bounds.
- Persistent replay detection and rejection of changed evidence under an existing source ID.
- Separate original decisions for correlated activity.

## Limits an operator must understand

**Collection authenticity:** source fields are input, not cryptographic proof. A forged source export can make a false alert or consume an event ID. Deploy authenticated collection and independently retained logs before making evidentiary claims.

**Local privilege:** anyone who can edit the registry, database or process can affect decisions and acknowledgments. Database hashes are not an HMAC, signed chain or tamper-proof ledger. Production evidence needs external integrity/access controls.

**Permissions:** new POSIX CLI runtime files use restrictive umask. Windows ACLs are not configured automatically. Choose a trusted protected directory, do not allow other principals to replace parent directories/DB files, and protect SQLite sidecar files. The CLI leaf-symlink check is not a race-resistant privilege boundary.

**Storage/availability:** SQLite decisions grow until an operator archives them. This release has no retention scheduler, database quota, HA, authenticated service API, queue, outbox, delivery retry or durable invalid-record ledger. Invalid results are stdout/stderr plus nonzero exit status; capture those explicitly. Existing source evidence must remain available for review. Disk full and SQLite corruption can stop ingestion.

**Concurrency:** use one local ingestion/acknowledgment writer. Multiwriter duplicate races and clock ordering are not a supported deployment mode. Monitor failure exit codes and do not retry blindly into a different database.

**Clock and coverage:** future source timestamps are rejected, so collectors need time synchronization. Supported adapters intentionally reject unsupported source operations rather than inventing semantics. No coverage claim applies to an unsupported or missing event.

**Resource aliases:** Windows case folding does not resolve hard links, junctions, device paths, SMB aliases or 8.3 paths. S3 versions, batch operations and alternate ARN forms need separate contracts/tests. Review real exported events during pilot acceptance.

**Response:** unexpected access does not establish malicious intent. No automated disablement, deletion, quarantine or account blocking is present. Human triage remains required.

**Offline adapters:** packet rendering is not production delivery. The only HTTP helper uses a fixed loopback address and synthetic token for mock tests. Planned production TLS/auth/rate/outbox controls and their acceptance evidence are documented in [ADAPTERS.md](ADAPTERS.md).

Report suspected security issues privately as described in [SECURITY.md](../SECURITY.md). Use synthetic reproduction data only. Do not upload operational placements or private telemetry.
