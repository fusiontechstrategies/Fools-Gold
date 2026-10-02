# Contracts, version 1

## Registry

See [the complete synthetic registry](../examples/registry.synthetic.json).

| Required field | Meaning |
|---|---|
| `id` | Unique registry identifier |
| `owner` | Accountable operating owner |
| `source` | `aws.cloudtrail.s3` or `windows.security` |
| `locator` | Exact GovCloud account/region/object ARN or Windows host/local path |
| `created_at`, `expires_at` | Zoned timestamps, expiration after creation |
| `expected_actions` | Supported content actions the deployment should test |
| `response_procedure` | Triage instruction or internal runbook reference |

Optional exceptions identify exact actor/actions, owner, reason, ID and bounded start/expiry. At most 1,000 decoys and 100 exceptions per decoy. Duplicate IDs/locations fail validation. Windows host/path matching ignores case; S3 keys are case sensitive. Windows paths must be absolute without parent traversal. UNC aliases, junctions and short-name aliases are not inferred.

`expected_actions` is desired tested coverage, not a suppression filter. An unexpected supported interaction still alerts. Allowed sets in this pilot: `["read"]`, `["write"]`, `["delete"]` or `["read","write","append","delete"]`.

Exceptions match the exact reported principal, never a username substring or ARN wildcard. STS sessions need session-specific review. A future canonical-role adapter must validate account/role boundaries before relaxing matching.

## S3 input

One complete exported CloudTrail event per JSONL line, not an AWS `Records` envelope. Supported operations: `GetObject`, `PutObject`, `DeleteObject` in `us-gov-east-1` or `us-gov-west-1`, with `eventCategory=Data` and `eventSource=s3.amazonaws.com`.

Required fields: recipient account, region, request bucket/key, exactly matching object resource ARN, principal ARN, event ID/time and source address. Object and principal ARNs use `aws-us-gov`. The pilot does not percent-decode keys or invent missing ARNs. Review collector transformations against actual exports.

An `errorCode` yields outcome `denied`, which still alerts for a matched decoy. Enumeration, version-specific objects, anonymous identities, batch deletes, access-point ARN variants, IAM honeycredentials and Object Lambda are outside this adapter. Rejections are visible and must not be counted as covered.

## Windows input

See [the flattened synthetic collector event](../examples/events.synthetic.jsonl). This is a documented collector contract, not arbitrary Windows XML, Wazuh alerts or Splunk exports.

| Input | Required value/source |
|---|---|
| `source` | `windows.security` |
| `provider`, `channel` | `Microsoft-Windows-Security-Auditing`, `Security` |
| `event_id`, `audit_outcome`, `object_type` | Integer `4663`, `success`, `File` |
| `computer`, `log_epoch`, `record_id` | Host, stable log-generation identity, decimal record ID |
| `time`, `subject_sid` | TimeCreated and exact subject SID |
| `object_name`, `process_name` | ObjectName and ProcessName |
| `access_mask` | Hexadecimal AccessMask |

Mask bits: `0x1` read data, `0x2` write data, `0x4` append data, `0x10000` delete access. Multiple bits yield multiple actions. Metadata-only access is rejected. Delete access is not proof of final deletion. Event 4663 is a successful access audit; fabricated failure variants are rejected.

The collector must enable the correct audit policy/file SACL and map genuine provider/channel/outcome fields. Event 4656 and denied-access monitoring need a separate future adapter.

The offline XML and CloudTrail export converters are documented in [ADAPTERS.md](ADAPTERS.md). Windows computer names must be bounded ASCII names without replay-key delimiters. A supplied S3 `errorCode` must be a nonempty string.

## Decisions and evidence

Each accepted source event yields `alert`, `expected_access`, `unmatched` or `duplicate`. Malformed/unsupported records print `rejected` and make ingestion exit with status 2. Oversized records stop ingestion, preserving earlier committed decisions.

Alert evidence includes actor/location/actions/outcome, source identity, owner/runbook, receipt time, telemetry delay, expiry flag, registry/raw-event hashes and optional related alert. Original raw records remain in source storage; this tool retains their digest and normalized fields.

Output is JSONL. A future Wazuh/Splunk transport must preserve `decision=alert` and the nested alert, while routing rejections and expected access separately. Printing a record is not proof of SIEM delivery.

Acknowledgment is an operator-supplied name and time, not authenticated identity. Protect command access/database and use an authenticated case workflow in production.
