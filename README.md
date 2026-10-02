# Fool's Gold

*Looks valuable. Leaves evidence.*

A Fusion Technology Strategies project for internal cyber decoys, honeytokens, and verified detection workflows in AWS GovCloud and Windows environments.

## Project status

Private repository. Design stage. No deployable implementation yet.

## The idea

Place believable, harmless decoys along likely intrusion paths. Record unexpected interactions, deliver useful alerts to the existing security stack, and regularly prove that those alerts reach an analyst.

The initial design draws on CISA's **Using Cyber Decoys to Strengthen Detection and Response**, published September 16, 2026, and the MITRE Engage lifecycle.

## Planned first pilot

- Synthetic documents on selected Windows shares, with targeted access auditing.
- Synthetic S3 objects, with explicitly configured CloudTrail data events.
- Isolated internal service endpoints for observing discovery and connection attempts.
- Planned Wazuh, Splunk, and Suricata integrations.
- A protected decoy registry recording owner, placement, expected triggers, response procedure, expiry, and the last successful test.
- Repeatable synthetic tests measuring missed triggers, alert delivery time, and analyst acknowledgment.

## Design boundaries

Use synthetic content and no production credentials. Keep deployment changes explicit, environments isolated, and response actions subject to human approval. Treat unexpected interactions as evidence to investigate, with context for authorized scanners, backups, and testing.

Detailed placement records, client configuration, credentials, and operational telemetry belong in protected deployment systems, not source control. GitHub visibility alone is not a secret-management control.

## Next milestone

Define the pilot architecture, event contracts, deployment boundaries, and acceptance tests. Existing Fusion projects are candidates for reuse; integrations must be verified before they are described as working capabilities.
