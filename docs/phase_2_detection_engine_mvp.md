# Phase 2 Detection Engine MVP Runbook

## Purpose

This runbook validates the first Phase 2 detection path: native PowerShell detection for MITRE ATT&CK `T1059.001` using normalized Sysmon Event ID 1 ECS documents.

The MVP proves a narrow detection-layer path:

```text
normalized Sysmon Event ID 1 ECS document
  -> native PowerShell detection rule
  -> native evaluator
  -> alert document builder
  -> JSON or summary output
  -> optional Elasticsearch alert indexing
```

Alerts are printed by default. They are written to Elasticsearch only when `--write-alerts` is explicitly provided. Alerts are never sent to TheHive, SOAR, Kafka, or any other response system in this MVP.

## What The MVP Proves

- The project can load the first native `T1059.001` PowerShell rule.
- The native evaluator can match normalized Sysmon Event ID 1 process creation events.
- A matched event can produce a simple alert document in memory.
- The alert preserves rule metadata, ATT&CK metadata, investigation evidence, and Atomic Red Team metadata when present.
- Elasticsearch can be used as a read-only candidate source when matching normalized events already exist.
- Alert documents can optionally be indexed into a local native alert index for inspection.

## Scope Boundaries

In scope:

- Only `T1059.001` PowerShell execution.
- Only normalized Sysmon Event ID 1 ECS documents.
- Rule matching on current process fields only:
  - `process.name`
  - `process.executable`
  - `process.command_line`
- Fixture/offline detection smoke path.
- Optional read-only Elasticsearch detection smoke path.
- Optional alert indexing with `--write-alerts`.

Important boundary:

- Parent-only PowerShell does not match this rule. For example, `cmd.exe` with `process.parent.name = powershell.exe` is not an alert for this issue.

Out of scope:

- ML detection.
- Kafka streaming.
- TheHive case creation.
- SOAR or containment.
- SigmaHQ import.
- Full ATT&CK coverage.
- New Sysmon Event IDs.
- Alert writes to Elasticsearch.
- Kibana dashboards.
- Windows VM requirement for MVP acceptance.

## Components

- Native rule: `detection/rules/native/t1059_001_powershell_process_start.yml`
- Rule loader: `detection/rules/native/loader.py`
- Native evaluator: `detection/rules/native/evaluator.py`
- Alert builder: `detection/rules/native/alerts.py`
- Elasticsearch candidate query: `detection/rules/native/elasticsearch.py`
- Alert indexer: `detection/rules/native/alert_indexer.py`
- Native detection runner: `scripts/detection/run_native_detection.py`
- Detection smoke command: `scripts/smoke/phase_2_detection_smoke.py` remains available for smoke-only validation, but the native detection runner is the primary Phase 2 operator command.
- Phase 1 fixture: `collection/sysmon/fixtures/sysmon_event_1_process_create.xml`
- Phase 1 smoke payload builder: `scripts/smoke/end_to_end_art_telemetry_smoke.py`

## Fixture / Offline Detection Workflow

This is the primary deterministic acceptance path.

Run:

```powershell
python scripts\detection\run_native_detection.py
```

This mode:

- Does not require Docker.
- Does not require Elasticsearch, Logstash, Kibana, or Kafka.
- Does not require a Windows VM.
- Reuses the existing Phase 1 Sysmon Event ID 1 fixture path.
- Builds the normalized payload.
- Copies the normalized payload and adapts current process fields to `powershell.exe`.
- Loads the native `T1059.001` PowerShell rule.
- Evaluates the event with the native evaluator.
- Builds alert documents in memory.
- Prints JSON by default.
- Does not write alerts unless `--write-alerts` is provided.

Summary output:

```powershell
python scripts\detection\run_native_detection.py --output summary
```

No-alert check:

```powershell
python scripts\detection\run_native_detection.py --fixture-no-match
```

The no-alert check uses the original fixture shape, where current process is `cmd.exe` and PowerShell is only the parent. It should print `alert_count = 0` and exit with code `1`.

## Optional Elasticsearch Detection Workflow

Elasticsearch mode is optional. It validates the live read-only query path when matching normalized events already exist in Elasticsearch.

Start the local lab and post Phase 1 smoke payloads:

```powershell
docker compose up -d
python scripts\smoke\end_to_end_art_telemetry_smoke.py --post-logstash
```

Run the Phase 2 Elasticsearch detection smoke:

```powershell
python scripts\detection\run_native_detection.py --input elasticsearch
```

Custom connection options:

```powershell
python scripts\detection\run_native_detection.py `
  --input elasticsearch `
  --elasticsearch-url http://localhost:9200 `
  --index-pattern edr-raw-events-* `
  --size 100 `
  --timeout-seconds 10
```

Elasticsearch mode:

- Uses the Issue 03 read-only Elasticsearch candidate query.
- Filters normalized events with `event.dataset = windows.sysmon_operational` and `event.code = 1`.
- Searches current process PowerShell fields only.
- Evaluates returned candidates with the same native evaluator.
- Builds alerts in memory with the same alert builder.
- Preserves Elasticsearch `_index` and `_id` as `source.index` and `source.document_id`.
- Does not write alerts unless `--write-alerts` is provided.

Important caveat:

The current Phase 1 smoke fixture has `cmd.exe` as the current process and PowerShell as the parent process. Because this Phase 2 MVP rule matches current process fields only, Elasticsearch mode may produce zero alerts unless Elasticsearch contains a normalized Sysmon Event ID 1 document where the current process is `powershell.exe`.

Use fixture/offline mode as the deterministic acceptance path.

## Optional Alert Indexing

By default, the native detection runner only prints alerts. To write alert documents to Elasticsearch, opt in with `--write-alerts`:

```powershell
python scripts\detection\run_native_detection.py --input fixture --write-alerts
```

Elasticsearch input with alert indexing:

```powershell
python scripts\detection\run_native_detection.py --input elasticsearch --write-alerts
```

Alert index format:

```text
edr-alerts-native-YYYY.MM.DD
```

Example:

```text
edr-alerts-native-2026.06.17
```

The runner uses `alert.alert.id` as the Elasticsearch document ID:

```text
PUT /edr-alerts-native-YYYY.MM.DD/_doc/<alert.alert.id>
```

Use an explicit alert index date for deterministic local replay:

```powershell
python scripts\detection\run_native_detection.py `
  --input fixture `
  --write-alerts `
  --alert-index-date 2026-06-17
```

Verify indexed alerts:

```powershell
curl.exe -s "http://localhost:9200/edr-alerts-native-*/_search?q=rule.id:det.t1059_001.powershell_process_start&size=5&pretty"
```

## Expected JSON Output

Successful fixture mode output is shaped like this:

```json
{
  "mode": "fixture",
  "rule_id": "det.t1059_001.powershell_process_start",
  "candidate_count": 1,
  "alert_count": 1,
  "indexed_count": 0,
  "alerts": [
    {
      "alert": {
        "id": "det-t1059-001-powershell-process-start-...",
        "kind": "signal",
        "status": "open",
        "created": "2026-06-16T15:35:14Z",
        "severity": "medium",
        "confidence": "high"
      },
      "rule": {
        "id": "det.t1059_001.powershell_process_start",
        "name": "PowerShell Process Execution",
        "version": 1
      },
      "attack": {
        "technique": {
          "id": "T1059.001",
          "name": "PowerShell"
        },
        "tactic": ["Execution"]
      }
    }
  ],
  "indexed_alerts": []
}
```

Important alert sections:

- `alert.*`: alert ID, kind, status, created time, severity, confidence.
- `rule.*`: native rule metadata.
- `attack.*`: MITRE ATT&CK technique and tactic metadata.
- `event.*`: normalized Sysmon event metadata.
- `host`, `user`, `process`, `process.parent`: investigation context.
- `art.*`: Atomic Red Team metadata when present.
- `source.*`: Elasticsearch `_index` and `_id` when running Elasticsearch mode.

No-alert output:

```json
{
  "mode": "fixture",
  "rule_id": "det.t1059_001.powershell_process_start",
  "candidate_count": 1,
  "alert_count": 0,
  "indexed_count": 0,
  "alerts": [],
  "indexed_alerts": [],
  "message": "No matching PowerShell alerts produced."
}
```

## Summary Output

Run:

```powershell
python scripts\detection\run_native_detection.py --output summary
```

Expected shape:

```text
Phase 2 detection smoke
Mode: fixture
Rule: det.t1059_001.powershell_process_start
Candidates: 1
Alerts: 1
Indexed: 0
- det-t1059-001-powershell-process-start-... medium high WIN11-EDR-LAB powershell.exe
```

## Exit Codes

| Exit code | Meaning |
| --- | --- |
| `0` | Command ran successfully and produced one or more alerts. |
| `1` | Command ran successfully but produced zero alerts. |
| `2` | Operational failure, such as Elasticsearch unavailable, malformed Elasticsearch response, or alert indexing failure. |
| `3` | Unexpected detection or alert generation error. |

Notes:

- Exit `1` is a no-alert condition, not a Python crash.
- Exit `2` usually means Elasticsearch mode cannot reach or parse Elasticsearch, or `--write-alerts` failed.
- Fixture/offline mode should normally exit `0`.

## Troubleshooting

| Symptom | Likely cause | Check / fix |
| --- | --- | --- |
| Fixture mode returns `alert_count = 0` | Running `--fixture-no-match`, or fixture adaptation failed | Run without `--fixture-no-match`; run `python -m pytest tests`. |
| Elasticsearch mode exits `2` | Elasticsearch unavailable or malformed response | Run `docker compose up -d`, then `docker compose ps`. |
| Elasticsearch mode returns zero alerts | No current `powershell.exe` normalized Event ID 1 document exists | Use fixture mode for deterministic acceptance, or ingest a current PowerShell process event. |
| Elasticsearch contains raw events but no alerts | Raw payloads have `event.dataset = edr.raw` | Confirm normalized docs have `event.dataset = windows.sysmon_operational` and `event.code = 1`. |
| `--write-alerts` exits `2` | Alert indexing failed | Confirm Elasticsearch is running and reachable at `--elasticsearch-url`. |
| Indexed alert is not found | Wrong date/index pattern or write was not enabled | Confirm `--write-alerts` was used and query `edr-alerts-native-*`. |
| Parent PowerShell does not alert | The rule intentionally matches current process fields only | This is expected for the Phase 2 MVP boundary. |
| JSON output is too verbose | Need a compact operator view | Use `--output summary`. |
| Alert IDs changed in tests | Stable ID material changed | Check rule ID, event timestamp, process identity, command line, and source metadata. |

Useful checks:

```powershell
python -m pytest tests
python scripts\detection\run_native_detection.py
python scripts\detection\run_native_detection.py --output summary
python scripts\detection\run_native_detection.py --fixture-no-match
```

Optional Elasticsearch query:

```powershell
curl.exe -s "http://localhost:9200/edr-raw-events-*/_search?q=event.dataset:windows.sysmon_operational&size=5&pretty"
```

Optional alert index check:

```powershell
curl.exe -s "http://localhost:9200/edr-alerts-native-*/_search?q=rule.id:det.t1059_001.powershell_process_start&size=5&pretty"
```

## Acceptance Checklist

- [ ] Fixture/offline workflow runs without Docker, Elasticsearch, Logstash, Kibana, Kafka, or Windows VM.
- [ ] Fixture/offline workflow emits at least one alert.
- [ ] Optional Elasticsearch workflow is documented as read-only.
- [ ] Elasticsearch mode preserves `_index` and `_id` in alert `source`.
- [ ] Alert indexing is documented as opt-in with `--write-alerts`.
- [ ] Alert index format `edr-alerts-native-YYYY.MM.DD` is documented.
- [ ] Expected JSON output is documented.
- [ ] Summary output is documented.
- [ ] Exit codes are documented.
- [ ] No-alert troubleshooting is documented.
- [ ] Elasticsearch unavailable troubleshooting is documented.
- [ ] Scope boundaries are explicit.
- [ ] Out-of-scope systems are not described as implemented.

## Commands Reference

Fixture/offline success path:

```powershell
python scripts\detection\run_native_detection.py
```

Fixture/offline summary:

```powershell
python scripts\detection\run_native_detection.py --output summary
```

Fixture/offline no-alert check:

```powershell
python scripts\detection\run_native_detection.py --fixture-no-match
```

Optional Elasticsearch path:

```powershell
docker compose up -d
python scripts\smoke\end_to_end_art_telemetry_smoke.py --post-logstash
python scripts\detection\run_native_detection.py --input elasticsearch
```

Optional Elasticsearch path with explicit settings:

```powershell
python scripts\detection\run_native_detection.py `
  --input elasticsearch `
  --elasticsearch-url http://localhost:9200 `
  --index-pattern edr-raw-events-* `
  --size 100 `
  --timeout-seconds 10
```

Fixture input with alert indexing:

```powershell
python scripts\detection\run_native_detection.py --input fixture --write-alerts
```

Elasticsearch input with alert indexing:

```powershell
python scripts\detection\run_native_detection.py --input elasticsearch --write-alerts
```

Regression tests:

```powershell
python -m pytest tests
```
