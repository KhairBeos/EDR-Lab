# Live Telemetry Pipeline MVP Runbook

## Purpose

This runbook documents the production-shaped local live telemetry pipeline MVP.

The pipeline connects:

```text
Sysmon Event ID 1 XML
  -> ECS normalization
  -> optional normalized event indexing
  -> native T1059.001 PowerShell detection
  -> alert document building
  -> optional alert indexing
  -> JSON or summary output
```

This is not a smoke-only script. Fixture mode is a deterministic input mode of the real pipeline.

For the Sigma-like detection engine MVP and `--engine sigma-like|all`, see `docs/sigma_detection_mvp.md`.

For the Phase 3 detection coverage validation report, see `docs/detection_coverage_report_mvp.md`.

For the optional Phase 4 Kafka transport between normalization and detection, see `docs/kafka_pipeline_mvp.md`.

## Scope Boundaries

In scope:

- Sysmon Event ID 1 Process Create XML.
- Existing Phase 1 fixture input.
- XML file input exported from Windows Event Viewer.
- Existing ECS normalizer for Sysmon Event ID 1.
- Existing native `T1059.001` PowerShell rule.
- Optional normalized event indexing.
- Optional native alert indexing.

Out of scope:

- Kafka.
- ML.
- SOAR.
- TheHive.
- SigmaHQ import.
- Dashboards.
- New Sysmon Event IDs.
- Windows Event Log subscription or daemon mode.

## Command Interface

Fixture input:

```powershell
python scripts\pipeline\run_live_telemetry_pipeline.py --input fixture
```

XML input:

```powershell
python scripts\pipeline\run_live_telemetry_pipeline.py --input xml --xml-path .\event.xml
```

Deterministic PowerShell detection from the existing fixture:

```powershell
python scripts\pipeline\run_live_telemetry_pipeline.py --input fixture --fixture-detectable-powershell
```

The existing fixture has `cmd.exe` as the current process and PowerShell as the parent process. The native PowerShell rule matches current process fields only, so plain fixture mode produces zero alerts. `--fixture-detectable-powershell` copies the normalized fixture event and adapts current process fields to `powershell.exe` for deterministic detection validation.

## Event Indexing

By default, normalized events are not written to Elasticsearch.

Write normalized events explicitly:

```powershell
python scripts\pipeline\run_live_telemetry_pipeline.py --input fixture --write-events
```

Event index format:

```text
edr-normalized-events-YYYY.MM.DD
```

Use a deterministic event index date:

```powershell
python scripts\pipeline\run_live_telemetry_pipeline.py `
  --input fixture `
  --write-events `
  --event-index-date 2026-06-17
```

Event document ID strategy:

1. `event.id` if present.
2. `sysmon.event_data.ProcessGuid` if present.
3. Stable SHA-256 hash from event dataset, code, timestamp, host, and process fields.

## Alert Indexing

By default, alerts are not written to Elasticsearch.

Write alerts explicitly:

```powershell
python scripts\pipeline\run_live_telemetry_pipeline.py --input fixture --fixture-detectable-powershell --write-alerts
```

Alert index format:

```text
edr-alerts-native-YYYY.MM.DD
```

Write both normalized event and alert:

```powershell
python scripts\pipeline\run_live_telemetry_pipeline.py `
  --input fixture `
  --fixture-detectable-powershell `
  --write-events `
  --write-alerts
```

When `--write-events` is set and an alert is built, the alert receives event source metadata:

```json
{
  "source": {
    "index": "edr-normalized-events-2026.06.17",
    "document_id": "{9f7f5c20-1c5d-6666-0100-000000000400}"
  }
}
```

## Expected Output

Plain fixture mode normalizes one event and usually produces zero alerts:

```json
{
  "mode": "fixture",
  "normalized_event_count": 1,
  "event_indexed_count": 0,
  "alert_count": 0,
  "alert_indexed_count": 0,
  "message": "No matching PowerShell alerts produced."
}
```

Detectable fixture mode produces one alert:

```json
{
  "mode": "fixture",
  "normalized_event_count": 1,
  "event_indexed_count": 0,
  "alert_count": 1,
  "alert_indexed_count": 0,
  "alerts": [
    {
      "rule": {
        "id": "det.t1059_001.powershell_process_start"
      },
      "attack": {
        "technique": {
          "id": "T1059.001",
          "name": "PowerShell"
        }
      }
    }
  ]
}
```

Summary output:

```powershell
python scripts\pipeline\run_live_telemetry_pipeline.py --input fixture --fixture-detectable-powershell --output summary
```

Expected shape:

```text
Live telemetry pipeline
Mode: fixture
Normalized events: 1
Events indexed: 0
Alerts: 1
Alerts indexed: 0
- det-t1059-001-powershell-process-start-... medium high WIN11-EDR-LAB powershell.exe
```

## Verification Queries

Normalized events:

```powershell
curl.exe -s "http://localhost:9200/edr-normalized-events-*/_search?q=event.dataset:windows.sysmon_operational&size=5&pretty"
```

Native alerts:

```powershell
curl.exe -s "http://localhost:9200/edr-alerts-native-*/_search?q=rule.id:det.t1059_001.powershell_process_start&size=5&pretty"
```

## Exit Codes

| Exit code | Meaning |
| --- | --- |
| `0` | Pipeline ran successfully and produced one normalized event. |
| `1` | `--fixture-detectable-powershell` was selected but zero alerts were produced. |
| `2` | Operational failure: unreadable XML, malformed XML, unsupported Event ID, event indexing failure, alert indexing failure, or Elasticsearch unavailable. |
| `3` | Unexpected detection or alert generation failure. |

## Troubleshooting

| Symptom | Likely cause | Check / fix |
| --- | --- | --- |
| Fixture mode produces zero alerts | Existing fixture current process is `cmd.exe` | Add `--fixture-detectable-powershell` for deterministic detection. |
| XML mode exits `2` | Missing/unreadable XML path or malformed XML | Confirm `--xml-path` points to exported Sysmon Event ID 1 XML. |
| Unsupported Event ID exits `2` | Normalizer only supports Sysmon Event ID 1 | Export a Sysmon Event ID 1 Process Create record. |
| `--write-events` exits `2` | Elasticsearch unavailable or indexing failed | Start Elastic and confirm `--elasticsearch-url`. |
| `--write-alerts` exits `2` | Elasticsearch unavailable or alert indexing failed | Start Elastic and confirm `--elasticsearch-url`. |
| Indexed event not found | Wrong date/prefix or write flag omitted | Query `edr-normalized-events-*` and confirm `--write-events`. |
| Indexed alert not found | No alert was produced or write flag omitted | Use `--fixture-detectable-powershell --write-alerts`. |

## Commands Reference

Fixture normalization:

```powershell
python scripts\pipeline\run_live_telemetry_pipeline.py --input fixture
```

Fixture deterministic detection:

```powershell
python scripts\pipeline\run_live_telemetry_pipeline.py --input fixture --fixture-detectable-powershell
```

Sigma-like deterministic detection:

```powershell
python scripts\pipeline\run_live_telemetry_pipeline.py --input fixture --fixture-detectable-powershell --engine sigma-like
```

Run all detection engines:

```powershell
python scripts\pipeline\run_live_telemetry_pipeline.py --input fixture --fixture-detectable-powershell --engine all
```

Fixture event and alert indexing:

```powershell
python scripts\pipeline\run_live_telemetry_pipeline.py --input fixture --fixture-detectable-powershell --write-events --write-alerts
```

XML input:

```powershell
python scripts\pipeline\run_live_telemetry_pipeline.py --input xml --xml-path .\event.xml
```

Regression tests:

```powershell
python -m pytest tests\test_event_indexer.py
python -m pytest tests\test_live_telemetry_pipeline.py
python -m pytest tests
```

## Related Final Docs

- [Architecture](architecture.md)
- [Final demo script](final_demo_script.md)
- [Final demo report MVP](final_demo_report_mvp.md)
