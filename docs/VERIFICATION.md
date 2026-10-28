# Verification record

Initial local verification: October 2, 2026, Windows, Python 3.12.

The test suite covers exact GovCloud S3 matching, Windows host/path boundaries and content masks, scoped/expired exceptions, denied access, expired decoys, malformed input, timestamp ordering, persistence/replay collisions, correlation and local acknowledgment. Run the suite to obtain the current count rather than relying on a stale number here.

The adapter increment also tests native XML metadata/outcome, namespace and duplicate-field rejection, DTD/entity/encoding bounds, CloudTrail batch failure, registry snapshot isolation, JSON depth/exponent overflow, local-file Wazuh packet round trips, and loopback mock HEC acceptance/errors/redirects. Deployment artifacts are checked for disabled delivery and exact synthetic scope. This does not substitute for actual Wazuh/Splunk parsing or indexing.

The 0.2.0 increment adds coverage for the wevtutil XML envelope and registry-filtered collection (malformed events are skipped with a count), gzip-bomb and digest-idempotent trail-inbox processing, outbox enqueue/batch/mark/reset semantics, Wazuh file delivery idempotency, Splunk HEC delivery attempts and failure recording over a loopback receiver (production always uses verified HTTPS; the injected plain-HTTP factory is test-only), HMAC chain verification and tamper detection including legacy schema migration, and the self-contained canary `check` with and without transport. Run the suite for current counts.

The deterministic synthetic exercise produces:

| Metric | Offline result |
|---|---|
| Synthetic trigger scenarios | 2 |
| Missed synthetic triggers | 0 |
| Original alerts | 2 |
| Retained authorized-access decisions | 1 |
| Synthetic S3 event-to-local-receipt delay | 5 seconds |
| Synthetic Windows event-to-local-receipt delay | 2 seconds |
| Simulated acknowledgment delay | 30 seconds for each alert |

These delays are constructed from fixture timestamps. They are not measured service performance. CI repeats the tests and exercise on Windows/Linux with Python 3.12/3.13.

Not verified: live AWS deployment, actual CloudTrail selectors or collection, real Windows policy/SACL/collector configuration, Wazuh/Splunk ingestion through a real installation, real analyst acknowledgment, Suricata correlation, authenticated collection channels, evidentiary integrity against a privileged local attacker, HA or production retention.

The next acceptance evidence must come from the governed pilot described in [PILOT.md](PILOT.md).
