# Exact deployment review packet

Nothing in `deployment/` is applied automatically. The JSON plan has deployment and production delivery set to false, and the runtime does not read it to enable a sender. Replace placeholders only in protected operator storage.

## Proposed footprint

- One approved private GovCloud bucket and exact synthetic object.
- One approved Windows host/local synthetic file.
- One protected registry/evidence directory and collection identity.
- One Wazuh JSONL/manager-rule path and one optional Splunk HEC destination.
- One accountable SOC owner and one authenticated analyst acknowledgment workflow.

## Reviewable artifacts

| Artifact | Operator review needed |
|---|---|
| `pilot-plan.template.json` | Exact account/region/host, protected paths, owners, secret/CA references and acceptance evidence |
| `cloudtrail-data-selector.synthetic.json` | Replace synthetic ARN; merge with existing selectors without losing management/data coverage |
| `wazuh-localfile.example.xml` | Confirm path/ACL, agent and manager versions, rotation/retention and agent-to-manager trust |
| `wazuh-rules.example.xml` | Confirm rule ID is unused; test decoder/rule on the actual manager before applying |

CloudTrail selector APIs can replace existing selector configuration. Capture the original configuration, prepare a reviewed merged configuration and rollback record, and verify retained coverage. The artifact is a proposed selector, not a command to overwrite a trail. [AWS data-event selector documentation](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-data-events-with-cloudtrail.html).

The Wazuh XML examples are syntactically tested offline only. On the actual manager, use the documented log-test procedure to confirm `fg_product`, alert ID, actor and action extraction and the selected rule. Then prove an agent-collected source record appears in manager alert storage. [Wazuh custom decoder verification](https://documentation.wazuh.com/current/user-manual/ruleset/decoders/custom.html).

## Inputs needed before live work

1. Approved account/region, bucket/key, Windows host/local path, owner and test window.
2. Current CloudTrail selectors/log destination and Windows audit policy/SACL, exported without credentials or client payloads.
3. Wazuh agent/manager versions, trusted collection route, selected manager rule ID and protected JSONL path.
4. If Splunk is used, approved HEC destination/index/sourcetype, CA trust, secret-store reference and indexer-ack capability. Actual tokens belong only in the secret store.
5. Evidence classification, retention, filesystem ACLs, encryption, failure alarms and retirement/rollback owners.

## Required evidence before enabling delivery

Record source export digest and provenance, decoy registry digest, exact normalized event, local alert, decoder/HEC result, indexed/manager alert ID, authenticated analyst acknowledgment and elapsed times. Record each failed stage instead of assuming receipt at a later stage.

Governed tests must cover an authorized read, another actor, an expired exception, replay/restart, malformed input, collection outage, rejected transport response and retirement. The synthetic suite verifies local contracts; it cannot establish the permissions, TLS trust, SIEM parsing or operational availability of the deployment.

No real AWS configuration, audit policy/SACL, agent rule, firewall, exposed honeypot or containment action has been changed by this increment.
