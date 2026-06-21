Status: done

# Technical Design: Sigma-Like Detection MVP

## Scope

This design covers:

`.scratch/phase-3-live-telemetry-pipeline/issues/02-sigma-like-detection-mvp.md`

Goal: implement a production-shaped Sigma-like detection MVP that can run alongside the existing native detection engine in the live telemetry pipeline.

This is not smoke-only. It extends the live telemetry pipeline with a second detection engine.

In scope:

- Minimal Sigma-like YAML rule format for `T1059.001` PowerShell process execution.
- Load Sigma-like rules from `detection/rules/sigma_like/`.
- Evaluate normalized ECS Sysmon Event ID 1 events in memory.
- Build alert documents compatible with the existing alert shape.
- Integrate Sigma-like evaluation into `scripts/pipeline/run_live_telemetry_pipeline.py`.
- Optional alert indexing using existing native alert indexer.
- CLI flag `--engine native|sigma-like|all`.

Out of scope:

- Full SigmaHQ import.
- pySigma dependency.
- Kafka.
- ML.
- SOAR.
- TheHive.
- Dashboards.
- New Sysmon Event IDs.

## Architecture

Current Phase 3 pipeline:

```text
Sysmon XML / fixture
  -> normalize Sysmon Event ID 1
  -> optional index normalized event
  -> native detection
  -> optional index alert
```

New pipeline:

```text
Sysmon XML / fixture
  -> normalize Sysmon Event ID 1
  -> optional index normalized event
  -> selected detection engines:
       native
       sigma-like
       all
  -> build alerts
  -> optional index alerts
```

New package:

```text
detection/rules/sigma_like/
```

Responsibilities:

- `loader.py`: parse and validate the minimal Sigma-like YAML subset.
- `evaluator.py`: evaluate normalized ECS event dictionaries.
- `alerts.py`: build alert documents compatible with existing alert shape, adding `detection.engine = sigma-like` and deterministic engine-aware alert IDs.
- Rule YAML: first Sigma-like rule for `T1059.001`.

Important design point:

- Existing native `build_alert_document()` validates the native rule schema and its alert ID helper uses a native-oriented prefix. Sigma-like alerts should use a Sigma-like-specific builder adapter rather than forcing Sigma-like metadata through native validation.
- The Sigma-like alert builder should preserve the same top-level alert shape:
  - `alert.*`
  - `rule.*`
  - `attack.*`
  - `event.*`
  - `host`
  - `user`
  - `process`
  - `detection.*`
  - `source`
  - `art`

## Rule File Format

Create:

```text
detection/rules/sigma_like/t1059_001_powershell_process_start.yml
```

Minimal YAML shape:

```yaml
id: sigma_like.t1059_001.powershell_process_start
title: PowerShell Process Execution
status: experimental
description: Detects Windows PowerShell process creation from normalized Sysmon Event ID 1 ECS documents.
author: edr-project
logsource:
  product: windows
  service: sysmon
  category: process_creation
detection:
  selection:
    event.dataset: windows.sysmon_operational
    event.code: 1
    process.name|equals:
      - powershell.exe
    process.executable|endswith:
      - \powershell.exe
    process.command_line|contains:
      - powershell.exe
  condition: selection
level: medium
confidence: high
attack:
  technique_id: T1059.001
  technique_name: PowerShell
  tactic:
    - Execution
```

Interpretation:

- Hard gates are `event.dataset` and `event.code`.
- Process field operators are OR conditions within `selection`.
- `condition: selection` is the only supported condition in this MVP.
- Matching is case-insensitive.
- Parent fields are intentionally not supported by this first rule.

## Required Rule Fields

Required metadata:

- `id`
- `title` or `name`
- `status`
- `description`
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

Allowed operators in `detection.selection`:

- plain equality for hard gates, e.g. `event.dataset: windows.sysmon_operational`
- `|equals`
- `|endswith`
- `|contains`

Unsupported:

- Boolean expression language beyond `condition: selection`.
- Filters.
- Multiple selections.
- Aggregations.
- Time windows.
- Sigma modifiers beyond the three listed operators.

## Matching Logic

Hard gate:

```text
event.dataset == windows.sysmon_operational
event.code == 1
```

Match OR conditions:

```text
process.name equals powershell.exe
OR process.executable ends with \powershell.exe
OR process.command_line contains powershell.exe
```

Rules:

- Case-insensitive matching.
- Missing optional fields are non-matches, not crashes.
- Raw payloads with `event.dataset = edr.raw` do not match.
- Non Event ID 1 does not match.
- `cmd.exe` with `process.parent.name = powershell.exe` does not match.

Evaluator result shape:

```python
@dataclass(frozen=True)
class SigmaLikeMatchResult:
    matched: bool
    rule_id: str
    matched_fields: tuple[str, ...]
    engine: str = "sigma-like"
```

## Alert Documents

Sigma-like alert requirements:

- Include `alert.*`.
- Include `rule.*`.
- Include `attack.*`.
- Include `event.*`.
- Include `process.*`.
- Include `host` and `user` if present.
- Include `detection.engine = sigma-like`.
- Include `detection.matched_fields`.
- Preserve `source` metadata if event was indexed.
- Preserve `art` metadata if present.

Alert ID strategy:

- Deterministic.
- Include engine and rule ID in stable material.
- Must not collide with native alerts for the same event.

Suggested prefix:

```text
det-sigma-like-t1059-001-powershell-process-start-<digest>
```

Stable material:

- `engine = sigma-like`
- `rule.id`
- `event.dataset`
- `event.code`
- `event.created` or `@timestamp`
- `host.name`
- `process.entity_id`
- `process.pid`
- `process.executable`
- `process.command_line`
- `source.document_id`

## CLI Integration

Edit:

```text
scripts/pipeline/run_live_telemetry_pipeline.py
```

Add:

```text
--engine native|sigma-like|all
```

Default:

```text
native
```

Behavior:

- `--engine native`: current behavior unchanged.
- `--engine sigma-like`: run only Sigma-like engine.
- `--engine all`: run native engine and Sigma-like engine, append alerts from both.

Output:

- Existing JSON shape remains.
- `alerts` may include native and Sigma-like alerts.
- `alert_count` is total alert count.
- `alert_index_results` includes all indexed alerts when `--write-alerts` is set.

Summary:

- Include enough fields to distinguish engines.
- Recommended alert line includes detection engine:

```text
- <alert-id> sigma-like medium high WIN11-EDR-LAB powershell.exe
```

## Tests

Tests must not require live Elasticsearch.

`tests/test_sigma_like_detection.py`:

- Loader validates required metadata.
- Loader rejects missing rule ID.
- Loader rejects unsupported `condition`.
- Evaluator matches `process.name = powershell.exe`.
- Evaluator matches `process.executable` ending with `\powershell.exe`.
- Evaluator matches `process.command_line` containing `powershell.exe`.
- Matching is case-insensitive.
- Raw payload with `event.dataset = edr.raw` does not match.
- Non Event ID 1 does not match.
- `cmd.exe` with parent PowerShell does not match.
- Missing optional process fields do not crash.
- Alert builder creates alert with `detection.engine = sigma-like`.
- Sigma-like alert ID differs from native alert ID for the same event.

`tests/test_live_pipeline_sigma_integration.py`:

- `--engine native` keeps current fixture detectable behavior.
- `--engine sigma-like --fixture-detectable-powershell` produces one Sigma-like alert.
- `--engine all --fixture-detectable-powershell` produces two alerts.
- One alert has native/default detection metadata, one has `detection.engine = sigma-like`.
- `--write-alerts` indexes Sigma-like alerts with existing alert indexer.
- Without `--write-alerts`, alert indexer is not called.

Commands:

```powershell
python -m pytest tests\test_sigma_like_detection.py
python -m pytest tests\test_live_pipeline_sigma_integration.py
python -m pytest tests
```

## Acceptance Criteria

- [ ] Existing native behavior remains unchanged by default.
- [ ] Sigma-like rule file exists for `T1059.001` PowerShell process execution.
- [ ] Sigma-like loader validates minimal YAML metadata.
- [ ] Sigma-like evaluator matches current process PowerShell fields only.
- [ ] Sigma-like evaluator does not match raw payloads.
- [ ] Sigma-like evaluator does not match non Event ID 1 events.
- [ ] Sigma-like evaluator does not match parent-only PowerShell.
- [ ] Sigma-like alert includes `detection.engine = sigma-like`.
- [ ] Sigma-like alert ID is deterministic and does not collide with native alert ID.
- [ ] `--engine native` keeps existing pipeline behavior.
- [ ] `--engine sigma-like --fixture-detectable-powershell` produces one Sigma-like alert.
- [ ] `--engine all --fixture-detectable-powershell` produces two alerts: one native and one Sigma-like.
- [ ] `--write-alerts` indexes Sigma-like alerts using existing alert indexer.
- [ ] Tests pass without live Elasticsearch.
- [ ] Docs explain Sigma-like MVP and pipeline engine selection.

## Files To Create/Edit

Create:

- `detection/rules/sigma_like/t1059_001_powershell_process_start.yml`
- `detection/rules/sigma_like/__init__.py`
- `detection/rules/sigma_like/loader.py`
- `detection/rules/sigma_like/evaluator.py`
- `detection/rules/sigma_like/alerts.py`
- `tests/test_sigma_like_detection.py`
- `tests/test_live_pipeline_sigma_integration.py`
- `docs/sigma_detection_mvp.md`

Edit:

- `scripts/pipeline/run_live_telemetry_pipeline.py`
- `docs/live_telemetry_pipeline_mvp.md`

Do not add:

- Full SigmaHQ import.
- pySigma dependency.
- Kafka.
- ML.
- SOAR.
- TheHive.
- Dashboards.
- New Sysmon Event IDs.
