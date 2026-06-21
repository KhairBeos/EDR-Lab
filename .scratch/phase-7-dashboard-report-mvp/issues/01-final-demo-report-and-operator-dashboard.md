Status: done

# Final demo report and operator dashboard MVP

## Parent

`.scratch/phase-7-dashboard-report-mvp/PRD.md`

## Goal

Implement a production-shaped final demo report and operator dashboard MVP that summarizes the current EDR platform capabilities and validates all implemented vertical slices.

This must not be smoke-only. The command should run deterministic validation across real implemented modules, collect report artifacts, summarize capability coverage, optionally query Elasticsearch index counts, and write final local JSON and Markdown reports.

## Context

Phase 1 Foundation is complete.

Phase 2 Native Detection Pipeline MVP is complete.

Phase 3 Live Telemetry Pipeline, Sigma-like Detection, and Coverage Report are complete.

Phase 4 Kafka Normalized Event Detection Pipeline is complete.

Phase 5 SOAR Dry-run Response Pipeline is complete.

Phase 6 ML-style Process Anomaly Detection MVP is complete.

Current capabilities:

- Elastic/Kibana/Logstash local lab.
- Sysmon Event ID 1 normalization.
- Native PowerShell detection.
- Sigma-like PowerShell detection.
- Alert indexing to `edr-alerts-native-*`.
- Normalized event indexing to `edr-normalized-events-*`.
- Kafka normalized event transport MVP.
- SOAR dry-run response records.
- ML-style process anomaly detection.
- Detection coverage report.

## What to build

Add an operator-facing final report/dashboard command that produces local artifacts:

```text
implemented EDR modules
  -> deterministic validation checks
  -> capability matrix
  -> optional Elasticsearch live counts
  -> final JSON + Markdown reports
```

Create:

- `reports/final_demo_report.json`
- `reports/final_demo_report.md`

This is a local operator dashboard/report MVP. No web UI or Kibana dashboard creation is required.

## Technical design

Create:

- `reporting/final_demo_report.py`
- `scripts/reporting/generate_final_demo_report.py`
- `tests/test_final_demo_report.py`
- `docs/final_demo_report_mvp.md`

The report module should own:

- Running deterministic validation checks.
- Building the report document.
- Rendering Markdown.
- Writing JSON and Markdown artifacts.
- Optionally querying Elasticsearch index counts.

The CLI should be thin and call the reporting module.

Use existing modules instead of duplicating pipeline behavior:

- Live telemetry fixture pipeline command/module for native and Sigma-like alert checks.
- Kafka dry-run producer/consumer helpers for dry-run validation.
- SOAR response command/module for fixture response planning.
- ML anomaly command/module for benign fixture scoring.
- Detection coverage report generator or existing report artifact path for coverage availability.

Do not change existing pipeline behavior to make the report pass.

## CLI

Create:

- `scripts/reporting/generate_final_demo_report.py`

Command:

```powershell
python scripts\reporting\generate_final_demo_report.py
```

Options:

- `--output-dir reports`
- `--format json|markdown|all`, default `all`
- `--include-elasticsearch`
- `--elasticsearch-url http://localhost:9200`

Behavior:

- Without Elasticsearch, command must still generate final JSON and Markdown reports.
- With `--include-elasticsearch`, report should include live index counts when Elasticsearch is reachable.
- If `--include-elasticsearch` is not provided, no Elasticsearch call should be made.
- Output directory should be created when missing.
- JSON and Markdown formats should share the same report data model.
- The command should return a non-zero exit code only for predictable operational failures or unexpected implementation errors, not for missing optional Elasticsearch when it was not requested.

Suggested exit codes:

- `0` when requested report artifacts are generated.
- `2` for operational failures such as output write errors or requested Elasticsearch query failure.
- `3` for unexpected implementation failures.

## Report content

The JSON report must include:

- `generated_at`
- `project_status`
- `implemented_phases`
- `capability_matrix`
- `validation_results`
- `elasticsearch_counts` only when `--include-elasticsearch` is used
- `demo_command_checklist`
- `known_limitations`
- `out_of_scope`

### Implemented phases

Include all completed phases:

- Phase 1 Foundation
- Phase 2 Native Detection Pipeline MVP
- Phase 3 Live Telemetry Pipeline, Sigma-like Detection, and Coverage Report
- Phase 4 Kafka Normalized Event Detection Pipeline
- Phase 5 SOAR Dry-run Response Pipeline
- Phase 6 ML-style Process Anomaly Detection MVP
- Phase 7 Final Demo Report and Operator Dashboard MVP

### Capability matrix

The report must summarize:

- `telemetry`
- `normalization`
- `native_detection`
- `sigma_like_detection`
- `kafka_transport`
- `alert_indexing`
- `soar_dry_run`
- `ml_anomaly`
- `reporting`

Each capability should include:

- status such as `implemented`
- short description
- primary command or artifact
- validation state

Example shape:

```json
{
  "capability": "native_detection",
  "status": "implemented",
  "description": "Detects PowerShell process execution using native rule logic.",
  "primary_command": "python scripts\\detection\\run_native_detection.py",
  "validation": "passed"
}
```

### Deterministic validation results

Validate these without live Kafka or Elasticsearch:

- Live telemetry fixture detectable PowerShell produces native alert.
- Live telemetry fixture detectable PowerShell produces Sigma-like alert.
- Kafka dry-run fixture produces native alert.
- Kafka dry-run fixture produces Sigma-like alert.
- SOAR fixture alert produces exactly one dry-run response record.
- ML benign fixture produces a low score/no alert.
- Detection coverage report is available and passes generation or artifact checks.

Each validation result should include:

- `id`
- `name`
- `status`: `passed` or `failed`
- `details`
- optional counts such as `alert_count`, `response_count`, `score`

Do not require live Kafka. Use existing dry-run or in-process helper paths.

### Optional Elasticsearch counts

When `--include-elasticsearch` is used, query counts for:

- `edr-normalized-events-*`
- `edr-alerts-native-*`
- `edr-response-actions-*`

Use standard library HTTP (`urllib.request`) unless an existing project helper is already appropriate.

The report should include:

```json
{
  "elasticsearch_counts": {
    "edr-normalized-events-*": 12,
    "edr-alerts-native-*": 4,
    "edr-response-actions-*": 1
  }
}
```

If Elasticsearch is requested and unavailable, return exit code `2` with a clear operational error.

### Demo command checklist

Include commands that an operator can run during the final demo, such as:

```powershell
python scripts\smoke\end_to_end_art_telemetry_smoke.py
python scripts\detection\run_native_detection.py
python scripts\pipeline\run_live_telemetry_pipeline.py --input fixture --fixture-detectable-powershell --engine all
python scripts\kafka\produce_normalized_event.py --input fixture --fixture-detectable-powershell --dry-run
python scripts\kafka\consume_and_detect.py --dry-run --fixture-detectable-powershell --engine all
python scripts\response\run_soar_response.py --input fixture-alert
python scripts\ml\run_process_anomaly_detection.py --input fixture
python scripts\reporting\generate_detection_coverage_report.py
python scripts\reporting\generate_final_demo_report.py
```

### Known limitations and out-of-scope boundaries

Document that this MVP does not add:

- New detection semantics.
- New Sysmon Event IDs.
- TheHive.
- Real containment.
- Dashboards requiring Kibana API.
- Heavy ML frameworks.

Also mention local-lab assumptions:

- Elasticsearch/Kibana are optional for the final report unless `--include-elasticsearch` is set.
- Kafka validation uses deterministic dry-run/in-process paths, not a required live broker.
- SOAR remains dry-run only.
- ML anomaly remains heuristic and deterministic, not trained production ML.

## Markdown report

The Markdown report should be operator-readable and include:

- Title and generated timestamp.
- Project status summary.
- Implemented phase list.
- Capability matrix table.
- Validation results table.
- Optional Elasticsearch counts table only when requested.
- Demo command checklist.
- Known limitations and out-of-scope boundaries.

Keep the Markdown deterministic enough for tests to assert key sections and values.

## Files to create

- `reporting/final_demo_report.py`
- `scripts/reporting/generate_final_demo_report.py`
- `tests/test_final_demo_report.py`
- `docs/final_demo_report_mvp.md`

## Files to edit only if useful

- `README.md`
- `docs/phase_2_detection_engine_mvp.md`
- `docs/live_telemetry_pipeline_mvp.md`
- `docs/kafka_pipeline_mvp.md`
- `docs/soar_response_mvp.md`
- `docs/ml_anomaly_mvp.md`

Do not edit unless needed:

- Detection rule semantics.
- Sysmon normalization semantics.
- Kafka producer/consumer behavior.
- SOAR response behavior.
- ML scoring behavior.
- Containment modules.

## Tests

Create:

- `tests/test_final_demo_report.py`

Tests must not require live Elasticsearch, Kafka, or Kibana.

Cover:

- Report data includes `generated_at`.
- Report data includes project status.
- Report data includes all completed phases.
- Capability matrix includes telemetry, normalization, native detection, Sigma-like detection, Kafka transport, alert indexing, SOAR dry-run, ML anomaly, and reporting.
- Live telemetry fixture validation passes for native detection.
- Live telemetry fixture validation passes for Sigma-like detection.
- Kafka dry-run fixture validation passes for native detection.
- Kafka dry-run fixture validation passes for Sigma-like detection.
- SOAR fixture validation produces one response record.
- ML fixture validation produces low score/no alert.
- Detection coverage report validation passes.
- Command generates JSON report without Elasticsearch.
- Command generates Markdown report without Elasticsearch.
- `--format json` writes only JSON.
- `--format markdown` writes only Markdown.
- `--format all` writes both.
- Elasticsearch counts are absent unless `--include-elasticsearch` is set.
- Elasticsearch count helper can be monkeypatched in tests.
- Requested Elasticsearch query failure maps to exit code `2`.
- Tests do not require live Elasticsearch.
- Existing pipeline behavior remains unchanged.

## Docs

Create:

- `docs/final_demo_report_mvp.md`

Document:

- Purpose of the final demo report/dashboard MVP.
- Pipeline:

```text
implemented modules -> deterministic validation -> capability matrix -> JSON/Markdown report
```

- CLI usage.
- Report artifact paths.
- Format options.
- Optional Elasticsearch count behavior.
- Validation checks.
- Demo command checklist.
- Known limitations and out-of-scope boundaries.

## Commands to run

Focused tests:

```powershell
python -m pytest tests\test_final_demo_report.py
```

Full regression:

```powershell
python -m pytest tests
```

Manual report generation:

```powershell
python scripts\reporting\generate_final_demo_report.py
```

Manual JSON only:

```powershell
python scripts\reporting\generate_final_demo_report.py --format json
```

Manual Markdown only:

```powershell
python scripts\reporting\generate_final_demo_report.py --format markdown
```

Manual Elasticsearch counts:

```powershell
python scripts\reporting\generate_final_demo_report.py --include-elasticsearch --elasticsearch-url http://localhost:9200
```

## Acceptance criteria

- [ ] Command generates `reports/final_demo_report.json` without Elasticsearch.
- [ ] Command generates `reports/final_demo_report.md` without Elasticsearch.
- [ ] Report shows every completed phase and current Phase 7 reporting capability.
- [ ] Report includes a capability matrix for telemetry, normalization, native detection, Sigma-like detection, Kafka transport, alert indexing, SOAR dry-run, ML anomaly, and reporting.
- [ ] Validation passes without live Kafka or Elasticsearch.
- [ ] Live telemetry fixture validation confirms native detection.
- [ ] Live telemetry fixture validation confirms Sigma-like detection.
- [ ] Kafka dry-run fixture validation confirms native detection.
- [ ] Kafka dry-run fixture validation confirms Sigma-like detection.
- [ ] SOAR fixture validation confirms exactly one response record.
- [ ] ML fixture validation confirms low score/no alert.
- [ ] Detection coverage report validation passes.
- [ ] Optional Elasticsearch section appears only with `--include-elasticsearch`.
- [ ] Optional Elasticsearch counts include `edr-normalized-events-*`, `edr-alerts-native-*`, and `edr-response-actions-*`.
- [ ] Tests do not require live Elasticsearch, Kafka, or Kibana.
- [ ] Existing pipeline behavior remains unchanged.
- [ ] Docs explain operator usage, artifact paths, validations, and limitations.

## Blocked by

- `.scratch/phase-1-foundation/PRD.md`
- `.scratch/phase-2-detection-engine-mvp/issues/06-native-detection-pipeline-with-alert-indexing.md`
- `.scratch/phase-3-live-telemetry-pipeline/issues/01-live-telemetry-to-detection-pipeline.md`
- `.scratch/phase-3-live-telemetry-pipeline/issues/02-sigma-like-detection-mvp.md`
- `.scratch/phase-3-live-telemetry-pipeline/issues/03-detection-coverage-validation-report.md`
- `.scratch/phase-4-kafka-pipeline-mvp/issues/01-kafka-normalized-event-detection-pipeline.md`
- `.scratch/phase-5-soar-response-mvp/issues/01-soar-dry-run-response-pipeline.md`
- `.scratch/phase-6-ml-anomaly-mvp/issues/01-process-anomaly-detection-mvp.md`

## Out-of-scope boundaries

- Do not add new detection semantics.
- Do not add new Sysmon Event IDs.
- Do not add TheHive.
- Do not add real containment.
- Do not create dashboards requiring Kibana API.
- Do not add heavy ML frameworks.
- Do not require live Elasticsearch for tests.
- Do not require live Kafka for tests.
- Do not change existing pipeline behavior.

## Comments
