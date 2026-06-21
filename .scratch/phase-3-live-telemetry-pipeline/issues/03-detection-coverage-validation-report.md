Status: done

# Detection coverage validation report

## Parent

`.scratch/phase-3-live-telemetry-pipeline/issues/01-live-telemetry-to-detection-pipeline.md`

## Goal

Implement a production-shaped detection coverage and validation report MVP for the current EDR pipeline.

This must not be smoke-only. The report command should validate the implemented detection coverage by reading local rule metadata and running the real live telemetry pipeline in deterministic fixture mode.

## Scope

In scope:

- Read local rule metadata from the native rule directory.
- Read local rule metadata from the Sigma-like rule directory.
- Run deterministic fixture validation through `scripts/pipeline/run_live_telemetry_pipeline.py` behavior with `--fixture-detectable-powershell`.
- Validate expected coverage for:
  - MITRE ATT&CK `T1059.001` PowerShell.
  - Sysmon Event ID `1`.
  - Native detection engine.
  - Sigma-like detection engine.
- Produce report artifacts:
  - `reports/detection_coverage_report.json`
  - `reports/detection_coverage_report.md`
- Optionally query Elasticsearch alert indexes only when `--include-elasticsearch` is provided.
- Do not require Elasticsearch by default.

Out of scope:

- No Kafka.
- No ML.
- No SOAR.
- No TheHive.
- No dashboards.
- No full SigmaHQ import.
- No new Sysmon Event IDs.
- No change to detection behavior.
- No writing events or alerts from the report command.

## Architecture

Add a small reporting module and a CLI wrapper:

```text
local rule files
  -> rule inventory collector
  -> deterministic pipeline validation
  -> optional Elasticsearch alert count query
  -> JSON/Markdown report renderer
  -> report files under reports/
```

The reporting module should own pure report assembly and rendering behavior. The CLI should own argument parsing, output directory creation, file writing, and exit code mapping.

The validation path should call the existing live telemetry pipeline function directly instead of duplicating fixture normalization or detection logic. This keeps the report tied to the production-shaped runner:

```python
run_live_telemetry_pipeline(
    input_mode="fixture",
    fixture_detectable_powershell=True,
    engine=args.engine,
    write_events=False,
    write_alerts=False,
)
```

The default `--engine all` validation should expect two alerts:

- One native alert.
- One Sigma-like alert.

For `--engine native`, expect one native alert. For `--engine sigma-like`, expect one Sigma-like alert.

## CLI Interface

Create:

```powershell
python scripts\reporting\generate_detection_coverage_report.py
```

Options:

- `--output-dir reports`
- `--format json|markdown|all`, default `all`
- `--include-elasticsearch`
- `--elasticsearch-url`, default `http://localhost:9200`
- `--alert-index-pattern`, default `edr-alerts-native-*`
- `--engine native|sigma-like|all`, default `all`

Default behavior must generate both JSON and Markdown reports without contacting Elasticsearch:

```powershell
python scripts\reporting\generate_detection_coverage_report.py
```

Generate only JSON:

```powershell
python scripts\reporting\generate_detection_coverage_report.py --format json
```

Include live Elasticsearch alert counts:

```powershell
python scripts\reporting\generate_detection_coverage_report.py --include-elasticsearch
```

## Report Data Model

The JSON report should be a stable, JSON-compatible Python dictionary with this shape:

```json
{
  "generated_at": "2026-06-17T00:00:00Z",
  "project_phase": "Phase 3 Live Telemetry Pipeline MVP",
  "covered_techniques": [
    {
      "technique_id": "T1059.001",
      "technique_name": "PowerShell",
      "tactic": ["Execution"],
      "datasource": {
        "event_dataset": "windows.sysmon_operational",
        "event_code": 1,
        "event_type": "process_creation"
      },
      "engines": ["native", "sigma-like"]
    }
  ],
  "rule_inventory": [
    {
      "rule_id": "det.t1059_001.powershell_process_start",
      "engine": "native",
      "name": "PowerShell Process Execution",
      "severity": "medium",
      "confidence": "high",
      "attack": {
        "technique_id": "T1059.001",
        "technique_name": "PowerShell",
        "tactic": ["Execution"]
      },
      "supported_datasource": {
        "event_dataset": "windows.sysmon_operational",
        "event_code": 1
      }
    }
  ],
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

When `--include-elasticsearch` is set, include:

```json
{
  "elasticsearch": {
    "alert_index_pattern": "edr-alerts-native-*",
    "total_matching_alerts": 0,
    "native_alert_count": 0,
    "sigma_like_alert_count": 0
  }
}
```

Omit the `elasticsearch` section entirely unless `--include-elasticsearch` is provided.

## Rule Inventory

Native rule inventory should use the existing native loader:

- `detection/rules/native/loader.py`
- `detection/rules/native/t1059_001_powershell_process_start.yml`

Map native metadata:

- `id` -> `rule_id`
- `name` -> `name`
- `severity` -> `severity`
- `confidence` -> `confidence`
- `attack.*` -> `attack.*`
- `data_source.event_dataset` and `data_source.event_code` -> `supported_datasource`
- `engine = native`

Sigma-like rule inventory should use the existing Sigma-like loader:

- `detection/rules/sigma_like/loader.py`
- `detection/rules/sigma_like/t1059_001_powershell_process_start.yml`

Map Sigma-like metadata:

- `id` -> `rule_id`
- `title` or `name` -> `name`
- `level` -> `severity`
- `confidence` -> `confidence`
- `attack.*` -> `attack.*`
- `logsource.*` plus hard-gated selection fields -> `supported_datasource`
- `engine = sigma-like`

## Validation Logic

The report should validate deterministic coverage by running the existing live telemetry pipeline in fixture mode:

```text
fixture Sysmon Event ID 1 XML
  -> normalize to ECS-like event
  -> adapt current process fields to powershell.exe
  -> run selected detection engine(s)
  -> count alerts
  -> compare actual alert count against expected alert count
```

Expected alert counts:

| Engine | Expected alert count |
| --- | --- |
| `native` | `1` |
| `sigma-like` | `1` |
| `all` | `2` |

Validation should also assert that:

- The normalized event count is `1`.
- Native alerts cover `T1059.001`.
- Sigma-like alerts cover `T1059.001`.
- `--engine all` returns both native and Sigma-like engine output.
- The validation command does not write events or alerts.

## Elasticsearch Alert Count Query

Use standard library `urllib.request` only.

The optional Elasticsearch query should read only alert indexes matching `--alert-index-pattern`.

Query target:

```text
GET /<alert-index-pattern>/_search
```

The query should count alerts for `T1059.001` and split counts by engine:

```json
{
  "size": 0,
  "query": {
    "bool": {
      "filter": [
        {
          "term": {
            "attack.technique.id": "T1059.001"
          }
        }
      ]
    }
  },
  "aggs": {
    "native": {
      "filter": {
        "bool": {
          "must_not": [
            {
              "exists": {
                "field": "detection.engine"
              }
            }
          ]
        }
      }
    },
    "sigma_like": {
      "filter": {
        "term": {
          "detection.engine": "sigma-like"
        }
      }
    }
  }
}
```

Native alerts currently may not include `detection.engine`, so native counts should treat missing `detection.engine` as native for this MVP.

Raise a predictable report error for:

- Network failures.
- Timeout failures.
- Non-2xx Elasticsearch responses.
- Malformed JSON responses.
- Missing expected aggregation fields.

## Markdown Report

The Markdown report should be readable as an operator artifact. Include:

- Title and generated timestamp.
- Project phase.
- Coverage summary.
- Covered techniques table.
- Rule inventory table.
- Deterministic fixture validation table.
- Optional Elasticsearch alert count table.
- Acceptance result.
- Scope boundaries.

The Markdown report should not include raw event payloads or `event.original`.

## Error Handling

Add a small predictable exception type in the reporting module, for example:

```python
class DetectionCoverageReportError(RuntimeError):
    """Raised for predictable coverage report failures."""
```

CLI exit codes:

- `0`: report generated and validation passed.
- `1`: report generated but deterministic validation failed.
- `2`: operational/reporting failure, including rule loading failure, Elasticsearch query failure, output write failure, or malformed report input.
- `3`: unexpected failure.

The command should still write report artifacts when deterministic validation fails, as long as report assembly succeeds.

## Files to Create or Edit

Create:

- `reporting/detection_coverage.py`
- `scripts/reporting/generate_detection_coverage_report.py`
- `tests/test_detection_coverage_report.py`
- `docs/detection_coverage_report_mvp.md`

Edit if useful:

- `README.md`
- `docs/live_telemetry_pipeline_mvp.md`
- `docs/sigma_detection_mvp.md`

Do not edit unless a blocking bug is found:

- Existing normalizer behavior.
- Existing native detection rule semantics.
- Existing Sigma-like detection rule semantics.
- Existing alert builder behavior.
- Existing alert indexer behavior.
- Existing live telemetry pipeline detection behavior.

## Commands to Run

Focused tests:

```powershell
python -m pytest tests\test_detection_coverage_report.py
```

Full regression:

```powershell
python -m pytest tests
```

Manual report generation:

```powershell
python scripts\reporting\generate_detection_coverage_report.py
```

Manual Markdown-only generation:

```powershell
python scripts\reporting\generate_detection_coverage_report.py --format markdown
```

Manual native-only validation:

```powershell
python scripts\reporting\generate_detection_coverage_report.py --engine native
```

Manual Sigma-like-only validation:

```powershell
python scripts\reporting\generate_detection_coverage_report.py --engine sigma-like
```

Manual report with Elasticsearch alert counts:

```powershell
python scripts\reporting\generate_detection_coverage_report.py --include-elasticsearch
```

## Tests

`tests/test_detection_coverage_report.py` must not require live Elasticsearch.

Cover:

- Rule inventory includes the native PowerShell rule.
- Rule inventory includes the Sigma-like PowerShell rule.
- Engine coverage summary reports:
  - `native_rule_count = 1`
  - `sigma_like_rule_count = 1`
  - `total_rule_count = 2`
- Generated report includes covered technique `T1059.001`.
- Generated report includes Sysmon Event ID `1`.
- Fixture validation with `engine=all` passes and reports `actual_alert_count = 2`.
- Fixture validation with `engine=native` passes and reports `actual_alert_count = 1`.
- Fixture validation with `engine=sigma-like` passes and reports `actual_alert_count = 1`.
- JSON renderer writes valid JSON.
- Markdown renderer writes a readable report containing `T1059.001`, `native`, and `sigma-like`.
- CLI default generates both report files under the output directory.
- `--format json` writes only the JSON report.
- `--format markdown` writes only the Markdown report.
- Elasticsearch section is omitted by default.
- Elasticsearch section appears only with `--include-elasticsearch`.
- Elasticsearch query can be monkeypatched and returns total/native/Sigma-like counts.
- Elasticsearch query failures map to exit code `2`.
- Validation failure maps to exit code `1`.

## Acceptance Criteria

- [ ] Command generates JSON and Markdown reports without Elasticsearch.
- [ ] Report artifact exists at `reports/detection_coverage_report.json` by default.
- [ ] Report artifact exists at `reports/detection_coverage_report.md` by default.
- [ ] Report shows `T1059.001` covered by the native engine.
- [ ] Report shows `T1059.001` covered by the Sigma-like engine.
- [ ] Report shows supported datasource as normalized Sysmon Event ID `1`.
- [ ] Rule inventory includes rule id, engine, severity/level, confidence, ATT&CK technique, and supported datasource.
- [ ] Engine coverage summary includes native, Sigma-like, and total rule counts.
- [ ] Deterministic fixture validation runs through the live telemetry pipeline with detectable PowerShell fixture adaptation.
- [ ] Validation passes with `--engine all`.
- [ ] Validation expects two alerts for `--engine all`.
- [ ] Validation expects one alert for `--engine native`.
- [ ] Validation expects one alert for `--engine sigma-like`.
- [ ] Elasticsearch is not required by default.
- [ ] When `--include-elasticsearch` is provided, the report includes total `T1059.001`, native, and Sigma-like alert counts.
- [ ] Tests pass without live Elasticsearch.
- [ ] Existing detection behavior remains unchanged.

## Blocked By

- `.scratch/phase-3-live-telemetry-pipeline/issues/01-live-telemetry-to-detection-pipeline.md`
- `.scratch/phase-3-live-telemetry-pipeline/issues/02-sigma-like-detection-mvp.md`
- `.scratch/phase-2-detection-engine-mvp/issues/06-native-detection-pipeline-with-alert-indexing.md`

## Out-of-Scope Boundaries

- Do not add Kafka.
- Do not add ML.
- Do not add SOAR.
- Do not add TheHive.
- Do not create dashboards.
- Do not import full SigmaHQ rules.
- Do not add pySigma.
- Do not add new Sysmon Event IDs.
- Do not write normalized events from this report command.
- Do not write alert documents from this report command.
- Do not modify existing detection matching semantics.
