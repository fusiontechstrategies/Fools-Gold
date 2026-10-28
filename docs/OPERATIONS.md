# Operator acceptance walkthrough

This is the reviewed end-to-end workflow. Every step is explicit; nothing
installs services, changes auditing or applies infrastructure automatically.
Use synthetic data for every step until the pilot is approved.

## 1. Install

```powershell
python -m pip install .            # or pipx install .
fools-gold --help
```

## 2. Initialize

```powershell
python -m fools_gold init --out runtime/live --owner soc-team `
  --windows-host fs01 --windows-path 'C:\Decoys\config-export.txt' --write-key
```

`init` validates the registry before writing it. Keep `evidence.key` outside
the monitored host where possible; the CLI takes `--evidence-key-file`.

## 3. Plant decoys

```powershell
python -m fools_gold plant --type config-export --out 'C:\Decoys\config-export.txt'
```

Decoy content is watermarked synthetic data; never place working credentials.

## 4. Configure collection

- Windows: enable file auditing and a SACL on the decoy path, then register the
  scheduled collector (`deployment/windows/register-collector.ps1`) or run
  `collect-windows --follow --state-file ...` under your supervisor.
- CloudTrail: stage log files into a protected inbox directory (for example a
  credential-scoped sync job) and schedule
  `python -m fools_gold ... trail-inbox <inbox>` (see
  `deployment/systemd/fools-gold-inbox.service`).
- Profiles: copy `examples/profile.example.json` and use `--profile` to avoid
  repeating paths; CLI arguments always override profile values.

## 5. Readiness

```powershell
python -m fools_gold --profile runtime/live/profile.json doctor `
  --inbox runtime/live/inbox --max-assurance-hours 24 --assurance-mode live
```

`doctor` separates executable availability from actual readiness. Checks that
cannot be verified locally are reported as `unverified` — file SACL/audit
policy always requires manual confirmation.

## 6. Ingest and verify

```powershell
python -m fools_gold --profile runtime/live/profile.json doctor --max-collection-hours 2
python -m fools_gold --profile runtime/live/profile.json report
python -m fools_gold --profile runtime/live/profile.json --evidence-key-file runtime/live/evidence.key verify-integrity
```

## 7. Deliver

```powershell
$env:FG_SPLUNK_HEC_TOKEN = '<from protected secret storage>'
python -m fools_gold --profile runtime/live/profile.json deliver --format splunk
python -m fools_gold --profile runtime/live/profile.json deliver --format wazuh --wazuh-output runtime/live/wazuh-feed.jsonl
```

Delivery is at-least-once. Confirm indexing/decoding in the actual SIEM before
trusting it; transport acceptance is not analyst acknowledgment.

## 8. Assure

```powershell
python -m fools_gold --profile runtime/live/profile.json assure --live --wait-seconds 30
python -m fools_gold --profile runtime/live/profile.json assure-report --max-age-hours 24
```

`assure` records every run. Synthetic canary success does not prove live
collection; use `--live` and require the appropriate mode in `doctor` and
`assure-report`. A failing `--max-age-hours` gate exits 2 for cron/dead-man's
switch use.

## 9. Investigate and acknowledge

- Browse `http://127.0.0.1:8080/` after `serve --port 8080` and sign in with
  `FG_UI_TOKEN` (or a token file).
- Filter/search alerts, open an alert to see event, receipt, delivery and
  acknowledgment times, then acknowledge with the analyst name.
- `incidents` / the dashboard incidents view groups per-actor activity.

## 10. Export

```powershell
python -m fools_gold --profile runtime/live/profile.json --evidence-key-file runtime/live/evidence.key bundle --out runtime/live/case.zip
python -m fools_gold --evidence-key-file runtime/live/evidence.key verify-bundle --file runtime/live/case.zip
```

A keyed verification fails closed on a missing or invalid signature; verifying
without the key is the documented inspection mode and reports `unverified`.
A recorded source-integrity failure is never reported as success.

## 11. Recover

```powershell
python -m fools_gold --profile runtime/live/profile.json prune --older-than-days 90
python -m fools_gold --profile runtime/live/profile.json backup --out runtime/live/backup.sqlite
python -m fools_gold --database runtime/live/evidence.sqlite restore --source runtime/live/backup.sqlite
```

`restore` refuses an active database and sources with uncommitted WAL data,
validates integrity and the full schema before touching the destination, and
removes stale destination sidecars under the writer lock. Retention writes
signed checkpoints so pruning does not break chain verification.

## Recovery and logging notes

- Collector: durable cursor in `--state-file`; stderr reports skipped records
  and coverage gaps (log clear/rollover). On gap, investigate and let it resume.
- Delivery: inspect `report`/dashboard outbox counts; failed packets require
  `deliver --retry-failed`. Check the sink for duplicates after a crash.
- Database: one writer at a time; a second writer fails fast with a clear
  message. Use `backup` rather than copying a live SQLite file.
- Evidence: keep the HMAC key outside the host and anchor chain heads
  externally if deletion-resistant proof is required.
