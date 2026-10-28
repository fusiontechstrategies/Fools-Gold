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
| `route` | Optional delivery routing label (64 characters) carried into evidence |

Optional exceptions identify exact actor/actions, owner, reason, ID and bounded start/expiry. At most 1,000 decoys and 100 exceptions per decoy. Duplicate IDs/locations fail validation. Windows and Linux host matching ignores case; Windows paths ignore case, Linux paths stay case sensitive. S3 keys are case sensitive. File paths must be absolute without parent traversal. UNC aliases, junctions and short-name aliases are not inferred.

Sources: `aws.cloudtrail.s3`, `windows.security`, `linux.audit` (`{"host","path"}` locator).

`expected_actions` is desired tested coverage, not a suppression filter. An unexpected supported interaction still alerts. Allowed sets: `["read"]`, `["write"]`, `["delete"]`, `["recon"]`, `["read","recon"]`, `["read","write","append","delete"]`, `["read","write","append","delete","recon"]`.

Exceptions match the exact reported principal, never a username substring or ARN wildcard. STS sessions need session-specific review. A future canonical-role adapter must validate account/role boundaries before relaxing matching.

## S3 input

One complete exported CloudTrail event per JSONL line, not an AWS `Records` envelope. Object operations require `eventCategory=Data`: `GetObject`, `GetObjectVersion`, `HeadObject` (recon), `PutObject`, `CopyObject` (destination write), `DeleteObject`. Bucket listings `ListObjects`/`ListObjectsV2` require `eventCategory=Management` and match registered decoys by bucket/prefix (`arn:aws-us-gov:s3:::bucket/prefix`). All in `us-gov-east-1` or `us-gov-west-1`, with `eventSource=s3.amazonaws.com`.

Required fields: recipient account, region, request bucket/key (or bucket/prefix for listings), exactly matching object resource ARN for object operations, principal ARN, event ID/time and source address. Object and principal ARNs use `aws-us-gov`. Keys are not percent-decoded and missing ARNs are not invented. `CopyObject` reports the destination write only; copies *from* a decoy to another location are not independently represented. Review collector transformations against actual exports.

An `errorCode` yields outcome `denied`, which still alerts for a matched decoy. Anonymous identities, batch deletes (`DeleteObjects`), access-point ARN variants, IAM honeycredentials and Object Lambda are outside this adapter. Rejections are visible and must not be counted as covered.

Two known limitations to confirm against real exports: `GetObjectVersion` events whose resource ARN embeds a version identifier are rejected (the contract expects the plain object ARN), and `CopyObject` is represented only for its destination write — a copy *from* a decoy to another location is not independently reported. A bucket listing that spans several registered decoys produces one alert for the first matching decoy in registry order.

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

Mask bits: `0x1` read data, `0x2` write data, `0x4` append data, `0x10000` delete access. Multiple bits yield multiple actions. Metadata-only access is rejected. Delete access is not proof of final deletion. Event 4663 requires Audit Success; event 4656 requires Audit Failure and yields `outcome="denied"` (the denied-access tripwire). Success-keyword 4656 and failure-keyword 4663 are rejected.

The collector must enable the correct audit policy/file SACL and map genuine provider/channel/outcome fields. SMB share-access events (5145) are not supported.

## Linux input

A documented sensor contract, not raw auditd lines: `source=linux.audit`, `host`, `sensor_epoch`, decimal `record_id`, `time`, `uid`, absolute `path`, `action` in `read|write|append|delete|recon`, and `audit_outcome` in `success|denied`. Actor is `uid:<uid>`. Replay identity is `linux:host:epoch:record`. Paths are case sensitive, absolute, and reject parent traversal.

The offline XML and CloudTrail export converters are documented in [ADAPTERS.md](ADAPTERS.md). Windows computer names must be bounded ASCII names without replay-key delimiters. A supplied S3 `errorCode` must be a nonempty string.

## Decisions and evidence

Each accepted source event yields `alert`, `expected_access`, `unmatched` or `duplicate`. Malformed/unsupported records print `rejected` and make ingestion exit with status 2. Oversized records stop ingestion, preserving earlier committed decisions. `trail-inbox` applies the same rule per file and skips files whose SHA-256 digest was already processed.

Alert evidence includes actor/location/actions/outcome, source identity, owner/runbook, receipt time, telemetry delay, expiry flag, registry/raw-event hashes, optional related alert, route and coarse ATT&CK technique tags. Original raw records remain in source storage; this tool retains their digest and normalized fields.

`incidents` clusters alerts per actor whose receipt times are within a configurable gap (default 300 seconds) without merging stored evidence. `bundle` writes alerts and a report into a zip with per-entry SHA-256 values and an HMAC-signed manifest when an evidence key is configured; `verify-bundle` re-checks both.

With `--evidence-key-file` (64 hexadecimal characters = 32 bytes), each stored alert receives an HMAC-SHA256 chained to its predecessor; `verify-integrity` recomputes the chain and reports any tampering. The key must be protected independently of the database.

## Delivery

`deliver --format splunk --splunk-host H --splunk-port P` sends rendered HEC packets over verified HTTPS using `FG_SPLUNK_HEC_TOKEN` from the environment; `deliver --format wazuh --wazuh-output PATH` appends rendered records to a local protected file. Every retained alert is enqueued per format exactly once, optionally filtered with `--route`; the outbox records state and per-attempt errors, `--retry-failed` requeues failures. Delivery success is transport-level only and never touches acknowledgment.

Output is JSONL. A Wazuh/Splunk transport must preserve `decision=alert` and the nested alert, while routing rejections and expected access separately. Printing a record is not proof of SIEM delivery.

Acknowledgment is an operator-supplied name and time, not authenticated identity. Protect command access/database and use an authenticated case workflow in production.
