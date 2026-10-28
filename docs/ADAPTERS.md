# Offline collection and delivery adapters

These adapters make the pilot's boundaries testable before real infrastructure is connected. Collection reads only operator-managed local sources (exported files, staged CloudTrail logs, the local Windows Security log); delivery transmits only when the operator explicitly runs it with configured endpoints. Nothing fetches from AWS or applies deployment templates.

## Collection

### Windows Event XML

`windows_event_xml()` converts one UTF-8 exported event into the existing collector contract. It verifies the event namespace, provider, Security channel, event ID 4663, Audit Success keyword without Audit Failure, record ID, event time and required EventData. Duplicate fields/elements, DTD/entity declarations, wrong source metadata and unsupported events are rejected.

Bounds: 64 KiB input, 128 XML elements, depth 6, 2,048 characters per EventData value. Consumed fields cannot contain control characters. Unused native fields such as multiline AccessList remain bounded but are not included in the normalized contract. The collector's log-generation epoch is supplied separately, never taken from an arbitrary event field.

```powershell
$env:PYTHONPATH = 'src'
New-Item -ItemType Directory -Path runtime -Force
python -m fools_gold.adapters windows-export examples/windows-4663.synthetic.xml --log-epoch synthetic-installation-1 > runtime/windows.jsonl
```

### CloudTrail Records export

`cloudtrail_export()` unwraps an exact `Records` JSON envelope. It validates every record against the existing S3 adapter before returning the batch. An unsupported record fails the whole batch, so a partial result cannot accidentally be described as complete coverage.

Bounds: 1 MiB export, 1 to 1,000 records, 64 KiB serialized record. No gzip decompression, S3 fetch, key percent-decoding or source attribution is inferred.

All JSON adapters reject duplicate keys, nonfinite numbers (including exponent overflow), nesting beyond 32 and more than 100,000 value nodes; the trail inbox raises its explicit node bound to 1,000,000 for whole CloudTrail log files. These limits also apply to registry/decision JSON inputs.

```powershell
python -m fools_gold.adapters cloudtrail-export examples/cloudtrail-export.synthetic.json > runtime/cloudtrail.jsonl
```

Source authentication, original export retention and collection audit policy are still deployment requirements. A correctly shaped XML or JSON file can be forged.

### Live Windows Security query

`fools_gold.winlog.collect` runs one fixed `wevtutil` XPath query for event 4663 against the local Security log and maps the returned XML envelope through the same hardened parsing as exports. Only events whose normalized host/path match a registered decoy are emitted; contract failures are skipped with a visible count and never silently accepted. Requires Windows; the query is collector configuration, never event-driven.

```powershell
python -m fools_gold --registry examples/registry.synthetic.json collect-windows --log-epoch synthetic-installation-1 > runtime/windows-events.jsonl
python -m fools_gold --registry examples/registry.synthetic.json --database runtime/pilot.sqlite ingest runtime/windows-events.jsonl
```

`--follow --interval-seconds N` (1–3600) repeats the query until interrupted; `--max-events` caps each query at 128. The command needs only `--registry`.

### CloudTrail log inbox

`fools_gold.trail_inbox.cloudtrail_records_file` processes one CloudTrail log file that already landed in an operator-managed directory (fetching from S3 stays a credential-scoped deployment concern, such as a sync job). Bounds: 16 MiB per file, 10,000 records, 64 KiB per record, bounded gzip decompression. The `trail-inbox` command skips files already processed by SHA-256 digest; a file with malformed records stays unmarked so it can be corrected and retried, while deduplication keeps earlier decisions safe.

## Offline payload rendering

The Wazuh adapter renders a flat JSONL record using `fg_` fields. The Splunk adapter wraps the original alert as a HEC event with fixed source/sourcetype and the original event timestamp. Both preserve the alert identity. Payloads are bounded to 64 KiB; Wazuh adds a newline delimiter after the bounded JSON record.

```powershell
python -m fools_gold --registry examples/registry.synthetic.json --database runtime/pilot.sqlite ingest examples/events.synthetic.jsonl
python -m fools_gold --registry examples/registry.synthetic.json --database runtime/pilot.sqlite export-alerts > runtime/alert-decisions.jsonl
python -m fools_gold.adapters render-alerts runtime/alert-decisions.jsonl --format wazuh > runtime/wazuh-alerts.jsonl
python -m fools_gold.adapters render-alerts runtime/alert-decisions.jsonl --format splunk > runtime/splunk-hec.jsonl
```

`export-alerts` reads retained evidence, including after a prior stdout delivery failure. It does not mark records sent or acknowledged. Repeated exports require downstream deduplication by `alert_id`. There is no production outbox or exactly-once delivery claim. Rendering rejects a stream containing rejection/unknown records and can leave previously printed packets; treat a nonzero exit as incomplete output.

The adapter CLI accepts at most 100,000 decision records per run and a 64 KiB decision line. Original evidence remains in the SQLite database. Protect exported files as operational telemetry and do not commit them.

## What the mock test proves

The test suite posts synthetic Splunk HEC packets to a locally created receiver. The helper fixes host to `127.0.0.1`, uses a synthetic token, sends one request and permits neither URL selection nor redirects/retries. Socket operations have a one-second timeout; responses are limited to 4 KiB and must contain an unambiguous integer `code=0` with HTTP 200.

This is **mock transport receipt**, not Splunk indexing or analyst acknowledgment. The Wazuh test writes a synthetic record to a temporary local file and checks its JSON fields. It does not run Wazuh's decoder or alerting engine.

## Production delivery, implemented with limits

The `deliver` command now sends retained alerts from a persistent SQLite outbox. It runs only when the operator explicitly configures an endpoint:

```powershell
python -m fools_gold --registry examples/registry.synthetic.json --database runtime/pilot.sqlite deliver --format wazuh --wazuh-output runtime/wazuh-feed.jsonl
$env:FG_SPLUNK_HEC_TOKEN = '<token from protected secret storage>'
python -m fools_gold --registry examples/registry.synthetic.json --database runtime/pilot.sqlite deliver --format splunk --splunk-host hec.internal.example --splunk-port 8088
```

Implemented controls: verified HTTPS with the default certificate trust (no bypass selectable), fixed HEC path with no redirect following, token from `FG_SPLUNK_HEC_TOKEN` only, 64 KiB packets, 4 KiB response bound, 5-second transport timeout, at most three attempts per packet with 1/2-second backoff, 0.25-second send pacing, durable per-attempt failure recording and `--retry-failed` requeueing. Wazuh delivery appends rendered records to an operator-selected local file with POSIX 0600 protection on creation and fsync. Every packet is keyed by `alert_id`, so repeated runs cannot duplicate delivery.

Still true: transport receipt is not Splunk indexing, not Wazuh manager ingestion and not analyst acknowledgment; `send_splunk_mock` remains a loopback-only test helper; the mock test suite does not exercise Wazuh's decoder or Splunk's indexer; Windows ACL hardening and endpoint acceptance evidence are deployment tasks.

Remaining acceptance requirements for a real deployment:

| Control | Required evidence before trusting delivery |
|---|---|
| TLS trust | Approved CA chain against the real endpoint; hostname verified |
| Auth | Dedicated least-privilege HEC token from protected secret storage; rotation/expiry owned and verified |
| Endpoint | Operator-approved host/port; no telemetry-selected destination |
| Indexing | HEC ack plus indexer acknowledgment where supported; alert visible in the product |
| Wazuh | Trusted agent-to-manager channel, verified decoder/rule, manager alert evidence |
| Analyst | Separate authenticated case acknowledgment; transport receipt must never populate it |

Primary references: [Wazuh JSON decoder](https://documentation.wazuh.com/current/user-manual/ruleset/decoders/json-decoder.html), [Wazuh localfile](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/localfile.html), [Splunk HEC event format](https://help.splunk.com/splunk-enterprise/get-data-in/get-started-with-getting-data-in/9.0/get-data-with-http-event-collector/format-events-for-http-event-collector), [Splunk HEC input endpoints](https://help.splunk.com/splunk-enterprise/rest-api-reference/9.4/input-endpoints/input-endpoint-descriptions).
