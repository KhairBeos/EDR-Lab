# Sigma-Like Detection MVP

## Purpose

This document describes the Phase 3 Sigma-like detection MVP. It adds a second production-shaped detection engine that can run alongside the existing native engine in the live telemetry pipeline.

This is not a full Sigma implementation and not a SigmaHQ import. It is a small, local, Sigma-like rule format for the first PowerShell detection path.

For the Phase 3 detection coverage validation report that checks native and Sigma-like coverage together, see `docs/detection_coverage_report_mvp.md`.

## Scope

In scope:

- One Sigma-like rule for MITRE ATT&CK `T1059.001` PowerShell execution.
- Normalized Sysmon Event ID 1 ECS documents.
- In-memory rule evaluation.
- Alert documents compatible with the existing alert shape.
- Optional alert indexing through the existing alert indexer.
- Engine selection in the live telemetry pipeline.

Out of scope:

- Full SigmaHQ import.
- pySigma.
- Kafka.
- ML.
- SOAR.
- TheHive.
- Dashboards.
- New Sysmon Event IDs.

## Supported YAML Subset

Rule file:

```text
detection/rules/sigma_like/t1059_001_powershell_process_start.yml
```

Supported metadata:

- `id`
- `title`
- `status`
- `description`
- `author`
- `logsource.product`
- `logsource.service`
- `logsource.category`
- `detection.selection`
- `detection.condition`
- `level`
- `confidence`
- `attack.technique_id`
- `attack.technique_name`
- `attack.tactic`

Supported condition:

```yaml
condition: selection
```

Supported selection operators:

- plain equality
- `|equals`
- `|endswith`
- `|contains`

The first rule gates on:

```yaml
event.dataset: windows.sysmon_operational
event.code: 1
```

Then matches current process fields:

```yaml
process.name|equals:
  - powershell.exe
process.executable|endswith:
  - \powershell.exe
process.command_line|contains:
  - powershell.exe
```

Parent-only PowerShell does not match this MVP rule.

## Engine Selection

The live telemetry pipeline supports:

```text
--engine native
--engine sigma-like
--engine all
```

Default:

```text
native
```

Behavior:

- `native`: current native detection engine only.
- `sigma-like`: Sigma-like rules only.
- `all`: native and Sigma-like engines both run.

## Commands

Run Sigma-like detection against deterministic fixture input:

```powershell
python scripts\pipeline\run_live_telemetry_pipeline.py --input fixture --fixture-detectable-powershell --engine sigma-like
```

Run both native and Sigma-like engines:

```powershell
python scripts\pipeline\run_live_telemetry_pipeline.py --input fixture --fixture-detectable-powershell --engine all
```

Run Sigma-like detection and index produced alerts:

```powershell
python scripts\pipeline\run_live_telemetry_pipeline.py --input fixture --fixture-detectable-powershell --engine sigma-like --write-alerts
```

## Alert Shape

Sigma-like alerts use the same top-level alert document shape as native alerts:

- `alert.*`
- `rule.*`
- `attack.*`
- `event.*`
- `host`
- `user`
- `process`
- `source`
- `art`
- `detection.*`

Sigma-like alerts include:

```json
{
  "detection": {
    "engine": "sigma-like",
    "matched_fields": [
      "process.name",
      "process.executable",
      "process.command_line"
    ]
  }
}
```

Alert IDs are deterministic and include the engine and rule ID in the stable material, so Sigma-like alerts do not collide with native alerts for the same event.

## Alert Indexing

Sigma-like alerts reuse the existing alert indexer.

Index format:

```text
edr-alerts-native-YYYY.MM.DD
```

Verify indexed Sigma-like alerts:

```powershell
curl.exe -s "http://localhost:9200/edr-alerts-native-*/_search?q=detection.engine:sigma-like&size=5&pretty"
```

## Tests

```powershell
python -m pytest tests\test_sigma_like_detection.py
python -m pytest tests\test_live_pipeline_sigma_integration.py
python -m pytest tests
```
