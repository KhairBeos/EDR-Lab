Status: done

# Technical Design: Detection Coverage Validation Report

## Scope

This design covers:

`.scratch/phase-3-live-telemetry-pipeline/issues/03-detection-coverage-validation-report.md`

Goal: implement a production-shaped detection coverage and validation report MVP for the current EDR pipeline.

This is not smoke-only. The report command validates the real local detection pipeline by reading local rule metadata and running deterministic fixture validation through the existing live telemetry pipeline.

In scope:

- Read local native rule metadata.
- Read local Sigma-like rule metadata.
- Validate deterministic coverage with the existing Sysmon Event ID 1 fixture adapted to current-process `powershell.exe`.
- Validate coverage for:
  - MITRE ATT&CK `T1059.001` PowerShell.
  - Normalized Sysmon Event ID `1`.
  - Native detection engine.
  - Sigma-like detection engine.
- Generate JSON and Markdown report artifacts.
- Optionally query Elasticsearch alert indexes when explicitly requested.

Out of scope:

- Kafka.
- ML.
- SOAR.
- TheHive.
- Dashboards.
- Full SigmaHQ import.
- New Sysmon Event IDs.
- Writing normalized events.
- Writing alert documents.
- Changing detection semantics.

## Architecture

Current Phase 3 pipeline:

```text
Sysmon XML / fixture
  -> normalize Sysmon Event ID 1
  -> optional index normalized event
  -> selected detection engine: native | sigma-like | all
  -> build alerts
  -> optional index alerts
```

New reporting path:

```text
local rule files
  -> rule inventory collector
  -> deterministic fixture validation via live telemetry pipeline
  -> optional Elasticsearch alert count query
  -> JSON/Markdown renderers
  -> reports/detection_coverage_report.*
```

New module:

```text
reporting/detection_coverage.py
```

Responsibilities:

- Load native rule metadata using existing native loader.
- Load Sigma-like rule metadata using existing Sigma-like loader.
- Build rule inventory.
- Build covered technique summary.
- Run deterministic fixture validation by calling the existing live telemetry pipeline function.
- Optionally query Elasticsearch alert indexes with `urllib.request`.
- Render JSON and Markdown report content.
- Raise predictable reporting errors.

New CLI:

```text
scripts/reporting/generate_detection_coverage_report.py
```

Responsibilities:

- Parse CLI arguments.
- Call the reporting module.
- Create output directory.
- Write requested report files.
- Print a short operator summary.
- Map predictable failures to exit codes.

Important design point:

- The report command should not duplicate normalization or detection logic. It should call `run_live_telemetry_pipeline()` with fixture input and detection flags so coverage validation follows the same path operators use.

## CLI Interface

Default command:

```powershell
python scripts\reporting\generate_detection_coverage_report.py
```

Options:

```text
--output-dir reports
--format json|markdown|all
--include-elasticsearch
--elasticsearch-url http://localhost:9200
--alert-index-pattern edr-alerts-native-*
--engine native|sigma-like|all
```

Defaults:

```text
--output-dir reports
--format all
--engine all
--elasticsearch-url http://localhost:9200
--alert-index-pattern edr-alerts-native-*
```

Examples:

```powershell
python scripts\reporting\generate_detection_coverage_report.py
python scripts\reporting\generate_detection_coverage_report.py --format json
python scripts\reporting\generate_detection_coverage_report.py --format markdown
python scripts\reporting\generate_detection_coverage_report.py --engine native
python scripts\reporting\generate_detection_coverage_report.py --engine sigma-like
python scripts\reporting\generate_detection_coverage_report.py --include-elasticsearch
```

## Data Flow

Report generation:

```text
1. Load native T1059.001 rule metadata.
2. Load Sigma-like T1059.001 rule metadata.
3. Build rule_inventory.
4. Build covered_techniques.
5. Run deterministic validation:
     run_live_telemetry_pipeline(
       input_mode="fixture",
       fixture_detectable_powershell=True,
       engine=<selected engine>,
       write_events=False,
       write_alerts=False,
     )
6. Compare actual alert count with expected alert count.
7. Optionally query Elasticsearch alert indexes.
8. Render and write JSON/Markdown artifacts.
```

Validation must not write events or alerts, even when Elasticsearch is available.

## Report Schema

JSON report:

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

Optional Elasticsearch section:

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

The `elasticsearch` section must be omitted unless `--include-elasticsearch` is provided.

## Rule Inventory Mapping

Native rule source:

```text
detection/rules/native/t1059_001_powershell_process_start.yml
```

Native mapping:

- `id` -> `rule_id`
- `name` -> `name`
- `severity` -> `severity`
- `confidence` -> `confidence`
- `attack` -> `attack`
- `data_source.event_dataset` -> `supported_datasource.event_dataset`
- `data_source.event_code` -> `supported_datasource.event_code`
- constant `engine = native`

Sigma-like rule source:

```text
detection/rules/sigma_like/t1059_001_powershell_process_start.yml
```

Sigma-like mapping:

- `id` -> `rule_id`
- `title` or `name` -> `name`
- `level` -> `severity`
- `confidence` -> `confidence`
- `attack` -> `attack`
- `logsource` plus hard-gated `detection.selection` -> `supported_datasource`
- constant `engine = sigma-like`

## Validation Logic

The validation path uses the existing pipeline:

```python
run_live_telemetry_pipeline(
    input_mode="fixture",
    fixture_detectable_powershell=True,
    engine=engine,
    write_events=False,
    write_alerts=False,
)
```

Expected alert counts:

| Engine | Expected alert count |
| --- | --- |
| `native` | `1` |
| `sigma-like` | `1` |
| `all` | `2` |

Validation result fields:

- `fixture_name`
- `engine`
- `normalized_event_count`
- `expected_alert_count`
- `actual_alert_count`
- `passed`

Validation passes when:

- `normalized_event_count == 1`
- `actual_alert_count == expected_alert_count`
- Alerts cover `attack.technique.id = T1059.001`
- For `engine=all`, output includes native and Sigma-like alerts

## Elasticsearch Alert Count Query

Elasticsearch is optional.

When `--include-elasticsearch` is provided, query:

```text
GET /<alert-index-pattern>/_search
```

Use standard library only:

```text
urllib.request
```

Query intent:

- Count all alerts for `T1059.001`.
- Count native alerts.
- Count Sigma-like alerts.

Example DSL:

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

Native alert note:

- Native alerts may not include `detection.engine`.
- For this MVP, missing `detection.engine` should be counted as native.

## Markdown Report

Generate:

```text
reports/detection_coverage_report.md
```

Recommended sections:

- Title.
- Generated timestamp.
- Project phase.
- Coverage summary.
- Covered techniques table.
- Rule inventory table.
- Deterministic fixture validation table.
- Optional Elasticsearch alert counts table.
- Acceptance result.
- Scope boundaries.

Do not include raw event payloads or `event.original`.

## Error Handling

Add:

```python
class DetectionCoverageReportError(RuntimeError):
    """Raised for predictable coverage report failures."""
```

Predictable failures:

- Rule loading or validation failure.
- Pipeline validation failure caused by predictable pipeline errors.
- Elasticsearch network failure.
- Elasticsearch timeout.
- Elasticsearch non-2xx response.
- Malformed Elasticsearch JSON response.
- Missing expected Elasticsearch aggregation fields.
- Output directory or file write failure.

Exit codes:

| Exit code | Meaning |
| --- | --- |
| `0` | Report generated and deterministic validation passed. |
| `1` | Report generated but deterministic validation failed. |
| `2` | Operational/reporting failure. |
| `3` | Unexpected failure. |

If validation fails but report assembly succeeds, the command should still write report artifacts and return `1`.

## Tests

Tests must not require live Elasticsearch.

Create:

```text
tests/test_detection_coverage_report.py
```

Cover:

- Rule inventory includes native PowerShell rule.
- Rule inventory includes Sigma-like PowerShell rule.
- Engine coverage summary reports one native rule, one Sigma-like rule, and two total rules.
- Report includes covered technique `T1059.001`.
- Report includes Sysmon Event ID `1`.
- Fixture validation with `engine=all` passes with two alerts.
- Fixture validation with `engine=native` passes with one alert.
- Fixture validation with `engine=sigma-like` passes with one alert.
- JSON report renderer outputs valid JSON.
- Markdown report renderer includes `T1059.001`, `native`, and `sigma-like`.
- CLI default writes both report files.
- `--format json` writes only JSON.
- `--format markdown` writes only Markdown.
- Elasticsearch section is omitted by default.
- Elasticsearch section appears only with `--include-elasticsearch`.
- Elasticsearch query can be monkeypatched.
- Elasticsearch query failure maps to exit code `2`.
- Validation failure maps to exit code `1`.

Commands:

```powershell
python -m pytest tests\test_detection_coverage_report.py
python -m pytest tests
```

## Acceptance Criteria

- [ ] Command generates JSON and Markdown reports without Elasticsearch.
- [ ] Report artifact exists at `reports/detection_coverage_report.json` by default.
- [ ] Report artifact exists at `reports/detection_coverage_report.md` by default.
- [ ] Report shows `T1059.001` covered by native engine.
- [ ] Report shows `T1059.001` covered by Sigma-like engine.
- [ ] Report shows supported datasource as normalized Sysmon Event ID `1`.
- [ ] Rule inventory includes rule ID, engine, severity/level, confidence, ATT&CK technique, and supported datasource.
- [ ] Engine coverage summary includes native, Sigma-like, and total rule counts.
- [ ] Deterministic fixture validation runs through the live telemetry pipeline.
- [ ] Validation passes with `--engine all`.
- [ ] Validation expects two alerts for `--engine all`.
- [ ] Validation expects one alert for `--engine native`.
- [ ] Validation expects one alert for `--engine sigma-like`.
- [ ] Elasticsearch is not required by default.
- [ ] `--include-elasticsearch` adds total, native, and Sigma-like alert counts.
- [ ] Tests pass without live Elasticsearch.
- [ ] Existing detection behavior remains unchanged.

## Files To Create/Edit

Create:

- `reporting/detection_coverage.py`
- `scripts/reporting/generate_detection_coverage_report.py`
- `tests/test_detection_coverage_report.py`
- `docs/detection_coverage_report_mvp.md`

Edit if useful:

- `README.md`
- `docs/live_telemetry_pipeline_mvp.md`
- `docs/sigma_detection_mvp.md`

Do not add:

- Kafka.
- ML.
- SOAR.
- TheHive.
- Dashboards.
- Full SigmaHQ import.
- New Sysmon Event IDs.
