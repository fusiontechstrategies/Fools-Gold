# Verification record

Initial local verification: October 2, 2026, Windows, Python 3.12.

The test suite covers exact GovCloud S3 matching, Windows host/path boundaries and content masks, scoped/expired exceptions, denied access, expired decoys, malformed input, timestamp ordering, persistence/replay collisions, correlation and local acknowledgment. Run the suite to obtain the current count rather than relying on a stale number here.

The adapter increment also tests native XML metadata/outcome, namespace and duplicate-field rejection, DTD/entity/encoding bounds, CloudTrail batch failure, registry snapshot isolation, JSON depth/exponent overflow, local-file Wazuh packet round trips, and loopback mock HEC acceptance/errors/redirects. Deployment artifacts are checked for disabled delivery and exact synthetic scope. This does not substitute for actual Wazuh/Splunk parsing or indexing.

The 0.2.0 increment adds coverage for the wevtutil XML envelope and registry-filtered collection (malformed events are skipped with a count), gzip-bomb and digest-idempotent trail-inbox processing, outbox enqueue/batch/mark/reset semantics, Wazuh file delivery idempotency, Splunk HEC delivery attempts and failure recording over a loopback receiver (production always uses verified HTTPS; the injected plain-HTTP factory is test-only), HMAC chain verification and tamper detection including legacy schema migration, and the self-contained canary `check` with and without transport. Run the suite for current counts.

The 0.3.0 increment adds coverage for recon/version/copy S3 operations and prefix listings, Windows 4656 denied contracts (JSON and XML), the Linux audit contract, MITRE tagging, route-filtered enqueueing, WAL and legacy-schema migration, retention/backup/restore, assurance runs with injected live probes and staleness gates, incident clustering, bundle hashing/signature verification (including forged manifests), doctor checks, onboarding (`init`/`plant`/`demo`) and the loopback dashboard including token enforcement, acknowledgment and metrics.

The deterministic synthetic exercise produces:

| Metric | Offline result |
|---|---|
| Canary trigger scenarios | 2 |
| Failed canary scenarios | 0 |
| Original alerts | 2 |
| Retained authorized-access decisions | 1 |
| Synthetic S3 event-to-local-receipt delay | 5 seconds |
| Synthetic Windows event-to-local-receipt delay | 2 seconds |
| Simulated acknowledgment delay | 30 seconds for each alert |

These delays are constructed from fixture timestamps. They are not measured service performance. CI repeats the tests and exercise on Windows/Linux with Python 3.12/3.13.

Not verified: live AWS deployment, actual CloudTrail selectors or collection, real Windows policy/SACL/collector configuration, real Linux audit sensor mapping, Wazuh/Splunk ingestion through a real installation, real analyst acknowledgment, Suricata correlation, authenticated collection channels, evidentiary integrity against a privileged local attacker, live assurance probes against configured SACLs, dashboard exposure behind a reverse proxy, HA or production retention.

The next acceptance evidence must come from the governed pilot described in [PILOT.md](PILOT.md).

## Release acceptance — October 28, 2026

The final integrated Windows checkout passed 356 tests (two platform-specific skips). Hosted Windows/Linux results are available in the repository's CI runs. Ruff and whitespace checks passed locally. Focused regression coverage includes signed checkpoints after complete pruning, unused checkpoint tampering, concurrent bundle snapshots, durable page spooling/replay, native Windows PowerShell stderr/exit handling, fixed public branding cache headers, and incident-to-actor navigation.

The local Semgrep scan ran 480 rules from `p/default`, `p/python`, `p/security-audit` and `p/secrets` with zero findings. Its strict invocation still returned a nonzero exit because one rule emitted a Windows-side lexical warning; that invocation is not recorded as a clean strict pass. Narrow suppressions cover fixed loopback test URLs and the Python-3.7 compatibility rule on a package requiring Python 3.12+. Full-history Gitleaks reported no leaks. Hosted security checks provide the independent Linux scanner run.

An actual Windows PowerShell worker exercise used a synthetic native-query substitute with real collection, page publication, cursor persistence and CLI ingestion: a later-page failure retained and ingested the first 128 records; restarting ingested record 129; an idle rerun created no duplicate. A failed ingestion kept the completed page for retry, which succeeded after restart. No scheduled task was registered and no audit policy was changed.

The real browser walkthrough used a separate synthetic database: login, source/status filtering, investigation and CSRF-protected acknowledgment, assurance stage distinctions, incidents, evidence integrity and local-file delivery were inspected. Desktop screenshots are retained in `docs/images`; the overview was also inspected at a narrow viewport and a tablet breakpoint. The incident-to-alert link regression found during this walkthrough is fixed and covered by an HTTP regression test. Browser screenshots are actual renders, not product mockups; all actors and events are synthetic.

Wheel and source distributions are independently installed into clean Windows environments outside the checkout and exercised through their console entry point, metadata, `check` and `demo`. The mascot is package data and must be available from the installed wheel. CI repeats the package smoke checks on Windows and Linux. CodeQL default setup was enabled and its initial Actions/Python validation passed; later pushes are scanned by GitHub.

Local Linux container execution was unavailable because this machine's Docker container starts hung. This record does not claim a local Linux run. GitHub CI is the independent Linux verification path. Live GovCloud, SACL/audit policy, real SIEM indexing and real operator acceptance remain outside this synthetic release acceptance.
