# Security boundaries and limits

## Defenses in the offline pilot

- Exact resource matching scoped by GovCloud account/region or Windows host/path.
- Expiring actor/action exceptions checked at event and receipt time; denied S3 attempts never take those exceptions.
- Parameterized SQL. No evaluation, subprocess launch, remote callbacks or telemetry-driven file access.
- JSON object duplicate keys/nonfinite numbers rejected by CLI; 1 MiB registry, 64 KiB event records and 100,000 records per ingestion run.
- JSON nesting is limited to 32 levels/100,000 value nodes. The offline Windows XML adapter forbids DTD/entities and enforces input/tree/field bounds.
- Persistent replay detection and rejection of changed evidence under an existing source ID.
- Separate original decisions for correlated activity.
- Optional HMAC-SHA256 evidence chain (`--evidence-key-file`) with `verify-integrity` tamper detection.
- Durable delivery outbox with bounded attempts, verified TLS, no redirect following and fixed HEC path.
- Bounded Windows Security query envelope parsing and gzip-bomb-resistant CloudTrail inbox processing.

## Limits an operator must understand

**Collection authenticity:** source fields are input, not cryptographic proof. A forged source export can make a false alert or consume an event ID. Deploy authenticated collection and independently retained logs before making evidentiary claims.

**Local privilege:** anyone who can edit the registry, database or process can affect decisions and acknowledgments. Database hashes are not an HMAC, signed chain or tamper-proof ledger. Production evidence needs external integrity/access controls.

**Permissions:** new POSIX CLI runtime files use restrictive umask. Windows ACLs are not configured automatically. Choose a trusted protected directory, do not allow other principals to replace parent directories/DB files, and protect SQLite sidecar files. The CLI leaf-symlink check is not a race-resistant privilege boundary.

**Evidence integrity:** with `--evidence-key-file` the engine chains an HMAC-SHA256 over each stored alert and `verify-integrity` recomputes the chain. `prune` writes a signed retention checkpoint before deleting old alerts; verification accepts a missing predecessor only when a valid checkpoint authorizes that exact boundary. Deleting an alert inside the retained chain shows as a break. Deleting a trailing suffix, deleting *every* alert, or holding both the database and the key is not locally detectable — anchor the latest chain head outside the host for deletion-completeness claims. Without a key, hashes remain comparison aids only.

**Delivery:** `deliver` transmits only when the operator runs it with explicit endpoint arguments and, for Splunk, a token in `FG_SPLUNK_HEC_TOKEN`. TLS uses the default verified context with no bypass selectable; the path is fixed; responses are bounded; attempts are durably recorded and never appear as acknowledgment. The operator selects the endpoint; protect command history and process listing accordingly. Wazuh file delivery does not prove manager ingestion.

**Collection:** the Windows collector queries only the local Security log through a fixed `wevtutil` XPath and never sends data anywhere; the trail inbox reads only operator-staged files. Collector output still requires an authenticated, protected channel to the evidence store.

**Assurance:** `assure --live` reads up to 64 bytes from decoy files registered to this machine name only, then waits for the resulting alert. It never reads non-decoy paths and never writes to decoys.

**Dashboard:** `serve` binds only `127.0.0.1`, serves no files from disk, bounds request bodies to 4 KiB, caps pages at 100 rows and sets a 10-second socket timeout. The login form exchanges the 16+ character token (constant-time comparison) for a server-side session that expires after 8 hours; the cookie is HttpOnly, SameSite=Strict and session-scoped, the token never appears in URLs or logs, and form posts require a per-session CSRF token. `/api/*` and `/metrics` accept only the bearer token. Acknowledgment is still an unauthenticated-identity operator action; put the dashboard behind your own access control if identity matters.

**Bundles:** `bundle` hashes every entry and signs the manifest with HMAC-SHA256 when an evidence key is configured; `verify-bundle` reports `signature: unverified` when no key is supplied. Holding the key allows re-signing, so keep it outside the monitored host.

Bundle capture uses one SQLite read snapshot for alerts, integrity, acknowledgments, delivery, assurance and acceptance history. Concurrent ingestion or retention cannot mix states from different moments into the same archive. Filesystem archive writing happens after the read snapshot is released.

Signed retention checkpoints preserve the evidence-key requirement even after every signed alert has expired. Keyless or wrongly keyed chain writes remain refused, and verification checks every checkpoint signature, including checkpoints that do not currently explain a retained boundary.

**Recovery:** `restore` rejects a source with uncommitted WAL sidecar data; restore only files written by `backup` (a self-contained `VACUUM INTO` copy). `prune` also removes outbox rows whose alerts were deleted so delivery state cannot silently accumulate.

**Concurrency:** every file-backed process holds a lifetime session marker; writes take a short-lived exclusive writer lock per transaction, so the dashboard, ingestion and delivery can run concurrently while evidence-chain predecessor selection stays serialized. Restore requires an exclusive session lock and fails while any session has the database open.

**Storage/availability:** SQLite decisions grow until an operator archives them. This release has no retention scheduler, database quota, HA, authenticated service API, queue or durable invalid-record ledger. Invalid results are stdout/stderr plus nonzero exit status; capture those explicitly. Existing source evidence must remain available for review. Disk full and SQLite corruption can stop ingestion.

**Concurrency:** use one local ingestion/acknowledgment writer. Multiwriter duplicate races and clock ordering are not a supported deployment mode. Monitor failure exit codes and do not retry blindly into a different database.

**Clock and coverage:** future source timestamps are rejected, so collectors need time synchronization. Supported adapters intentionally reject unsupported source operations rather than inventing semantics. No coverage claim applies to an unsupported or missing event.

**Resource aliases:** Windows case folding does not resolve hard links, junctions, device paths, SMB aliases or 8.3 paths. S3 versions, batch operations and alternate ARN forms need separate contracts/tests. Review real exported events during pilot acceptance.

**Response:** unexpected access does not establish malicious intent. No automated disablement, deletion, quarantine or account blocking is present. Human triage remains required.

**Offline adapters:** packet rendering is not delivery; the `deliver` command performs real transport only when the operator explicitly configures it, as described above. The loopback mock helper stays fixed to `127.0.0.1` with a synthetic token.

Report suspected security issues privately as described in [SECURITY.md](../SECURITY.md). Use synthetic reproduction data only. Do not upload operational placements or private telemetry.
