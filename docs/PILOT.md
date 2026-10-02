# A pilot worth running

## Scope

One approved GovCloud account, one exact synthetic S3 object, one Windows host with one synthetic local file, one SOC owner and one analyst workflow. No exposed services or automatic containment. Two trustworthy paths are more useful than a large untested decoy inventory.

## Prepare

1. Agree on a plausible threat scenario, such as unexpected access to a configuration export or backup inventory. Use synthetic content, not copied production material.
2. Record exact placement, operational owner, response procedure and retirement date outside source control. Identify antivirus, backups and testing that might touch the bait.
3. Verify a separate, controlled telemetry path. An intruder reading the bait must not be able to disable logging or rewrite registry/evidence.
4. Approve the test identity/window and document narrow exceptions. Never make a wildcard exception just to quiet the dashboard.

## Governed deployment steps, not implemented commands

**S3:** choose a dedicated private GovCloud bucket/prefix, least-privilege access, encryption and protected audit storage. Configure CloudTrail object data events including reads and writes for the exact decoy resources. Preserve existing trail selectors when changing them. Avoid writing logs into the monitored bait prefix. Verify actual `GetObject` records and adapter fields, including exact key/ARN representation.

**Windows:** place the synthetic file where the approved scenario can find it. Configure Audit File System and a targeted SACL for the required content access. Verify real provider, channel, SID, object path and access mask. SMB aliases must resolve to the server's exact audited local path; client-visible UNC strings are not interchangeable with that path.

**Wazuh/Splunk:** build an authenticated collector/export mapping, ingest the normalized alert without losing IDs, and route it to the designated analyst. Do not call an adapter operational until a source event is visible in the actual tool and acknowledged through the real case workflow.

**Suricata:** add context only after core paths pass. A network alert cannot establish that a local file was read. Keep independent evidence sources and time synchronization.

## Acceptance checklist

| Exercise | Required evidence |
|---|---|
| Authorized synthetic S3 read | CloudTrail source record, normalized identity/location, alert, analyst acknowledgment |
| Authorized synthetic Windows read | Security 4663 source record, normalized fields, alert, acknowledgment |
| Benign authorized backup | Scoped exception decision retained, unrelated actor still alerts |
| Expired exception | Same access alerts after expiry |
| Delayed source event | No stale exception bypass; telemetry delay recorded |
| Replay and restart | One original decision survives restart; replay is identified |
| Identifier collision | Changed record is rejected visibly, original evidence preserved |
| Expired decoy | Alert remains active with maintenance flag |
| Lost collection/transport | Missing-source/delivery check fails the pilot instead of claiming coverage |
| Retirement | Owner removes bait and scoped audit settings, preserves required evidence |

Define a delivery/acknowledgment target with the SOC before testing. This offline pilot sets no universal production latency promise. Report missed triggers, source-to-receipt delay, SIEM delivery and analyst acknowledgment separately.

## Operate and learn

Run the same approved scenario after configuration changes and on an agreed schedule. Store each real assurance result with decoy ID, test time, source record, alert/case ID, outcome and owner. The current offline exercise produces `last_successful_offline_test`; it must not be presented as the last successful deployed test. Review expired placements and exceptions, unexpected benign interactions and missed-trigger failures.
