# Offline collection and delivery adapters

These adapters make the pilot's boundaries testable before real infrastructure is connected. They do not fetch from AWS, read the Windows Security log, transmit to Wazuh/Splunk, or apply deployment templates.

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

All JSON adapters reject duplicate keys, nonfinite numbers (including exponent overflow), nesting beyond 32 and more than 100,000 value nodes. These limits also apply to registry/decision JSON inputs.

```powershell
python -m fools_gold.adapters cloudtrail-export examples/cloudtrail-export.synthetic.json > runtime/cloudtrail.jsonl
```

Source authentication, original export retention and collection audit policy are still deployment requirements. A correctly shaped XML or JSON file can be forged.

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

## Production delivery requirements, not implemented

| Control | Planned acceptance requirement |
|---|---|
| TLS | HTTPS with hostname/chain validation and approved CA trust; no insecure bypass |
| Auth | Dedicated least-privilege HEC token from protected secret storage; no token in logs/source/control files |
| Expiry | Token issuance/expiration/rotation owned and verified; expired or unknown credentials fail closed |
| Endpoint | Operator-approved fixed endpoint; no telemetry-selected destination or redirect following |
| Rate | Initially no more than 5 events/second, explicit bounded queue/backpressure and failure alarms |
| Size/time | 64 KiB event packet, 4 KiB response, total request deadline 5 seconds |
| Retry | Bounded retry with durable outbox, attempt evidence and alert-ID deduplication; no silent success |
| HEC acceptance | Validate HEC response and use indexer acknowledgment where supported/configured |
| Wazuh | Protected JSONL file, trusted agent-to-manager channel, verified decoder/rule and manager alert evidence |
| Analyst | Separate authenticated case acknowledgment; transport receipt must not populate analyst acknowledgment |

The planned rate/deadline/token controls are recorded in the review template, not enforced by a nonexistent production sender. HTTP is used only for the synthetic loopback mock. Real delivery remains disabled by absence of production transport code.

Primary references: [Wazuh JSON decoder](https://documentation.wazuh.com/current/user-manual/ruleset/decoders/json-decoder.html), [Wazuh localfile](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/localfile.html), [Splunk HEC event format](https://help.splunk.com/splunk-enterprise/get-data-in/get-started-with-getting-data-in/9.0/get-data-with-http-event-collector/format-events-for-http-event-collector), [Splunk HEC input endpoints](https://help.splunk.com/splunk-enterprise/rest-api-reference/9.4/input-endpoints/input-endpoint-descriptions).
