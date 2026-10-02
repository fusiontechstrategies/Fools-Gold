# Verification record

Initial local verification: October 2, 2026, Windows, Python 3.12.

The test suite covers exact GovCloud S3 matching, Windows host/path boundaries and content masks, scoped/expired exceptions, denied access, expired decoys, malformed input, timestamp ordering, persistence/replay collisions, correlation and local acknowledgment. Run the suite to obtain the current count rather than relying on a stale number here.

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

Not verified: live AWS deployment, actual CloudTrail selectors or collection, real Windows policy/SACL/collector configuration, Wazuh/Splunk delivery, real analyst acknowledgment, Suricata correlation, authenticated transport, evidentiary integrity, HA or production retention.

The next acceptance evidence must come from the governed pilot described in [PILOT.md](PILOT.md).
