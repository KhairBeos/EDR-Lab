# Detection Coverage Report MVP

## Purpose

This runbook documents the Phase 3 detection coverage validation report MVP.

The report proves the current local EDR pipeline has deterministic coverage for one technique:

```text
MITRE ATT&CK T1059.001 PowerShell
```

It is production-shaped, not smoke-only. The report command reads local rule metadata, validates the real live telemetry pipeline with deterministic fixture input, and writes operator artifacts.

## What The Report Validates

The report validates:

- The native detection engine has one `T1059.001` PowerShell rule.
- The Sigma-like detection engine has one `T1059.001` PowerShell rule.
- Both engines support normalized Sysmon Event ID 1 ECS documents.
- Deterministic fixture validation produces the expected alert count.
- Optional Elasticsearch alert counts can be included when requested.

It does not write events or alerts.

## Scope Boundaries

In scope:

- `T1059.001` PowerShell execution.
- Normalized Sysmon Event ID 1 ECS documents.
- Native detection engine.
- Sigma-like detection engine.
- Fixture validation through the live telemetry pipeline.
- Optional read-only Elasticsearch alert count query.

Out of scope:

- Kafka.
- ML.
- SOAR.
- TheHive.
- Dashboards.
- Full SigmaHQ import.
- New Sysmon Event IDs.
- Event writes.
- Alert writes.
- Detection semantic changes.

## Command Interface

Default command:

```powershell
python scripts\reporting\generate_detection_coverage_report.py
```

This writes:

```text
reports/detection_coverage_report.json
reports/detection_coverage_report.md
```

Generate JSON only:

```powershell
python scripts\reporting\generate_detection_coverage_report.py --format json
```

Generate Markdown only:

```powershell
python scripts\reporting\generate_detection_coverage_report.py --format markdown
```

Validate only native coverage:

```powershell
python scripts\reporting\generate_detection_coverage_report.py --engine native
```

Validate only Sigma-like coverage:

```powershell
python scripts\reporting\generate_detection_coverage_report.py --engine sigma-like
```

Include optional Elasticsearch alert counts:

```powershell
python scripts\reporting\generate_detection_coverage_report.py --include-elasticsearch
```

## Rule Inventory

The report reads the local rule files through the existing loaders.

Native rule:

```text
detection/rules/native/t1059_001_powershell_process_start.yml
```

Sigma-like rule:

```text
detection/rules/sigma_like/t1059_001_powershell_process_start.yml
```

Each rule inventory entry includes:

- Rule ID.
- Detection engine.
- Name.
- Severity or level.
- Confidence.
- ATT&CK technique ID/name/tactic.
- Supported datasource.

## Covered Technique

Current MVP coverage:

| Technique | Name | Tactic | Dataset | Event ID | Event Type | Engines |
| --- | --- | --- | --- | --- | --- | --- |
| `T1059.001` | PowerShell | Execution | `windows.sysmon_operational` | `1` | `process_creation` | native, sigma-like |

## Engine Coverage Summary

The MVP should report:

| Engine | Rule Count |
| --- | --- |
| native | 1 |
| sigma-like | 1 |
| total | 2 |

## Deterministic Fixture Validation

Validation uses the real live telemetry pipeline:

```text
fixture Sysmon Event ID 1 XML
  -> normalize to ECS-like event
  -> adapt current process fields to powershell.exe
  -> run selected engine(s)
  -> build alerts in memory
  -> compare actual and expected alert counts
```

Expected alert counts:

| Engine | Expected Alerts |
| --- | --- |
| native | 1 |
| sigma-like | 1 |
| all | 2 |

The validation path calls the pipeline with:

```text
input_mode = fixture
fixture_detectable_powershell = true
write_events = false
write_alerts = false
```

## Optional Elasticsearch Alert Counts

Elasticsearch is not required by default.

When `--include-elasticsearch` is provided, the report queries:

```text
edr-alerts-native-*
```

The optional section includes:

- Alert index pattern.
- Total matching alerts for `T1059.001`.
- Native alert count.
- Sigma-like alert count.

Native alert note:

- Native alerts may not include `detection.engine`.
- For this MVP, missing `detection.engine` is counted as native.

## Expected Output

JSON report shape:

```json
{
  "generated_at": "2026-06-17T10:30:00Z",
  "project_phase": "Phase 3 Live Telemetry Pipeline MVP",
  "covered_techniques": [
    {
      "technique_id": "T1059.001",
      "technique_name": "PowerShell"
    }
  ],
  "rule_inventory": [],
  "validation_results": [
    {
      "fixture_name": "sysmon_event_1_process_create.xml",
      "engine": "all",
      "normalized_event_count": 1,
      "expected_alert_count": 2,
      "actual_alert_count": 2,
      "passed": true
    }
  ],
  "engine_coverage_summary": {
    "native_rule_count": 1,
    "sigma_like_rule_count": 1,
    "total_rule_count": 2
  }
}
```

Markdown report includes:

- Generated timestamp.
- Project phase.
- Coverage summary.
- Covered techniques table.
- Rule inventory table.
- Deterministic fixture validation table.
- Optional Elasticsearch alert counts table.
- Acceptance result.
- Scope boundaries.

The report does not include raw event payloads or `event.original`.

## Exit Codes

| Exit Code | Meaning |
| --- | --- |
| `0` | Report generated and deterministic validation passed. |
| `1` | Report generated but deterministic validation failed. |
| `2` | Operational/reporting failure. |
| `3` | Unexpected failure. |

## Troubleshooting

| Symptom | Likely Cause | Fix |
| --- | --- | --- |
| Report exits `1` | Deterministic validation did not produce expected alerts | Run `python scripts\pipeline\run_live_telemetry_pipeline.py --input fixture --fixture-detectable-powershell --engine all`. |
| Report exits `2` with rule loading error | Local rule metadata is invalid | Run detection rule tests and inspect native/Sigma-like YAML. |
| `--include-elasticsearch` exits `2` | Elasticsearch is unavailable or response shape changed | Start Elasticsearch or run without `--include-elasticsearch`. |
| Elasticsearch counts are zero | No alerts have been indexed yet | Run the live telemetry pipeline with `--write-alerts`, then rerun the report. |

## Verification

Focused tests:

```powershell
python -m pytest tests\test_detection_coverage_report.py
```

Full regression:

```powershell
python -m pytest tests
```
