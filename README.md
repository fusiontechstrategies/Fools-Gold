# Fool's Gold

*Looks valuable. Leaves evidence.*

Put harmless bait where an intruder might look. Know when someone touches it. Regularly prove that the resulting alert can reach a person.

Fool's Gold is a private Fusion Technology Strategies project for internal cyber decoys and detection assurance in AWS GovCloud and Windows environments. Its starting point is CISA's September 16, 2026 paper, **Using Cyber Decoys to Strengthen Detection and Response**.

## What works today

The first release is an **offline pilot**, with no AWS or SIEM connection required:

- Register exact S3 object locations and Windows file locations with an owner, expiration and response procedure.
- Normalize supported GovCloud CloudTrail S3 data events and a documented Windows Security 4663 collector contract.
- Detect unexpected reads, writes, appends and deletes without relying on a filename prefix.
- Recognize explicitly scoped, expiring authorized access. Keep a decision record instead of silently discarding it.
- Retain individual alert evidence, link nearby activity, and deduplicate exact replay across restarts.
- Record a local analyst acknowledgment and its elapsed time.
- Run repeatable synthetic scenarios that prove the core detection path.
- Convert bounded Windows Event XML and CloudTrail Records exports, and render Wazuh JSONL or Splunk HEC packets offline.

**No live deployment, Wazuh/Splunk delivery, Suricata integration or automatic response has been verified.** Demo timing and analyst actions are simulated, not customer results.

## Try the synthetic pilot

Python 3.12 or newer. No third-party runtime dependencies.

From the repository directory, in PowerShell:

```powershell
$env:PYTHONPATH = 'src'
python -m unittest discover -s tests -v
python -m scripts.run_synthetic_pilot
```

On Linux:

```sh
PYTHONPATH=src python -m unittest discover -s tests -v
PYTHONPATH=src python -m scripts.run_synthetic_pilot
```

The exercise uses an isolated temporary database, a fixed synthetic clock, two synthetic read events, an authorized backup read and a replay. It prints an assurance report and removes its temporary runtime data.

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

Placement details, operational telemetry, client information and credentials belong in protected deployment storage. Only synthetic examples belong in this repository. Private visibility is not a substitute for access control.

Copyright 2026 Fusion Technology Strategies. All rights reserved. No open-source license is granted in this private pilot.
