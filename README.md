# Fool's Gold

*Looks valuable. Leaves evidence.*

[![CI](https://github.com/fusiontechstrategies/Fools-Gold/actions/workflows/ci.yml/badge.svg)](https://github.com/fusiontechstrategies/Fools-Gold/actions/workflows/ci.yml)
[![Security](https://github.com/fusiontechstrategies/Fools-Gold/actions/workflows/security.yml/badge.svg)](https://github.com/fusiontechstrategies/Fools-Gold/actions/workflows/security.yml)

Put harmless bait where an intruder might look. Know when someone touches it. Regularly prove that the resulting alert can reach a person.

Fool's Gold is an open-source toolkit from Fusion Technology Strategies for internal cyber decoys and detection assurance in AWS GovCloud and Windows environments. Its starting point is CISA's September 16, 2026 paper, **Using Cyber Decoys to Strengthen Detection and Response**.

## What works today

The first release is an **offline pilot**, with no AWS or SIEM connection required:

- Register exact S3 object locations and Windows file locations with an owner, expiration and response procedure.
- Normalize supported GovCloud CloudTrail S3 data events and a documented Windows Security 4663 collector contract.
- Detect unexpected reads, writes, appends and deletes without relying on a filename prefix.
- Recognize explicitly scoped, expiring authorized access. Keep a decision record instead of silently discarding it.
- Retain individual alert evidence, link nearby activity, and deduplicate exact replay across restarts.
- Record a local analyst acknowledgment and its elapsed time.
- Collect Windows Security 4663 events live through a fixed `wevtutil` query, filtered to registered decoy locations.
- Process CloudTrail log files, including gzip, from a watched local inbox, idempotently by content digest.
- Deliver retained alerts durably to Splunk HEC over verified TLS or append Wazuh JSONL locally, with bounded retries and a persistent outbox, only when the operator configures it.
- Chain alert evidence with HMAC-SHA256 under an operator-held 32-byte key and re-verify the chain later.
- Run a self-contained canary exercise (`check`) that can exercise configured delivery end to end.
- Run repeatable synthetic scenarios that prove the core detection path.
- Convert bounded Windows Event XML and CloudTrail Records exports, and render Wazuh JSONL or Splunk HEC packets offline.

**No production deployment, real SIEM ingestion, or analyst workflow has been verified.** Live collection is read-only local tooling; delivery is implemented but untested against a real Wazuh/Splunk installation. Demo timing and analyst actions are simulated, not customer results.

## Try the synthetic pilot

Python 3.12 or newer. No third-party runtime dependencies.

From the repository directory, in PowerShell:

```powershell
$env:PYTHONPATH = 'src'
python -m pip install --require-hashes -r requirements-dev.txt
python -m unittest discover -s tests -v
python -m scripts.run_synthetic_pilot
```

On Linux:

```sh
python -m pip install --require-hashes -r requirements-dev.txt
PYTHONPATH=src python -m unittest discover -s tests -v
PYTHONPATH=src python -m scripts.run_synthetic_pilot
```

The exercise uses an isolated temporary database, a fixed synthetic clock, two synthetic read events, an authorized backup read and a replay. It prints an assurance report and removes its temporary runtime data. The same exercise is available as a command:

```powershell
python -m fools_gold check
```

`check` uses its own canary registry and a temporary database. Add `--wazuh-output` or `--splunk-host`/`--splunk-port` (plus `FG_SPLUNK_HEC_TOKEN` in the environment) to exercise configured delivery as well.

On a Windows host with the file SACL configured, emit registered-decoy events as contract JSONL and ingest them:

```powershell
python -m fools_gold --registry examples/registry.synthetic.json collect-windows --log-epoch <collector-generation-id> > runtime/windows-events.jsonl
python -m fools_gold --registry examples/registry.synthetic.json --database runtime/pilot.sqlite ingest runtime/windows-events.jsonl
```

The query is fixed to event 4663 and only registered locations are emitted; `--follow --interval-seconds N` repeats it until interrupted, and non-contract events are counted on stderr.

For persisted synthetic evidence:

```powershell
New-Item -ItemType Directory -Path runtime
python -m fools_gold --registry examples/registry.synthetic.json --database runtime/pilot.sqlite ingest examples/events.synthetic.jsonl
python -m fools_gold --registry examples/registry.synthetic.json --database runtime/pilot.sqlite report
```

Use the printed `alert_id` to acknowledge an alert:

```powershell
python -m fools_gold --registry examples/registry.synthetic.json --database runtime/pilot.sqlite acknowledge fg-REPLACE_WITH_PRINTED_ID --analyst synthetic-analyst
```

CLI receipt and acknowledgment timestamps use the actual clock. The standalone exercise uses a fixed clock so its expected results remain repeatable. Fixtures dated October 2, 2026 must not be ingested before their event time.

## What the evidence means

Unexpected decoy access is a reason to investigate. It does not prove that the actor is malicious. Antivirus, backup jobs and authorized testing can touch decoys too. Exceptions identify the exact actor and actions, carry a reason and owner, and expire. A denied S3 attempt still alerts, including when the actor has a successful-read exception.

Decoy expiration does **not** switch off detection. It raises a maintenance flag while preserving alerts. SHA-256 values help compare evidence; they do not authenticate its source or protect against an administrator rewriting the database.

## Read next

- [Architecture and trust boundaries](docs/ARCHITECTURE.md)
- [Registry, event and alert contracts](docs/CONTRACTS.md)
- [Pilot deployment and acceptance plan](docs/PILOT.md)
- [Threat model and operational limits](docs/SECURITY.md)
- [Synthetic verification results](docs/VERIFICATION.md)
- [Offline collection and delivery adapters](docs/ADAPTERS.md)
- [Deployment review packet](docs/DEPLOYMENT-REVIEW.md)
- [Focused security review](docs/SECURITY-REVIEW-2026-10-02.md)

Placement details, operational telemetry, client information and credentials belong in protected deployment storage. Only synthetic examples belong in this repository. Public source code is not a substitute for access control on your own deployment data.

## Contributing and support

- Report defects and propose changes through [CONTRIBUTING.md](CONTRIBUTING.md).
- Report suspected security issues privately as described in [SECURITY.md](SECURITY.md).

## License

Copyright 2026 Fusion Technology Strategies. Released under the [Apache License 2.0](LICENSE).
