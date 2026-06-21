Status: done

# Multi-attack case dashboard validation

## Goal

Implement a multi-case EDR demo validation pack with around 10 labeled attack and benign cases, expected vs actual results, TP/TN/FP/FN classification, and Kibana dashboard validation.

This is for a live teacher demo. It must prove the EDR can run multiple scenarios from Windows VM / Atomic Red Team / safe manual commands through Sysmon, detection, response, and dashboard evidence.

This is a demo validation phase, not a new detection semantics phase.

## Context

Current project capabilities:

- Sysmon Event ID 1 normalization.
- Native and Sigma-like `T1059.001` PowerShell detection.
- ML-style process anomaly detection.
- Kafka dry-run transport.
- SOAR dry-run response.
- Elasticsearch indexes:
  - `edr-normalized-events-*`
  - `edr-alerts-native-*`
  - `edr-response-actions-*`
- Phase 8 Atomic Red Team / Sysmon demo validation pack.
- Current demo proves one PowerShell case works.

Phase 9 should turn the single-case demo into a teacher-friendly case matrix that shows both strengths and limitations.

## Problem

The final live demo needs:

- Around 10 demo cases.
- Attack and benign scenarios.
- Expected vs actual results.
- True positive / true negative / false positive / false negative classification.
- Dashboard/operator view.
- Evidence suitable for a teacher demo.

False positives and false negatives must be visible. Do not hide weak cases by changing expectations or modifying existing detection rules.

## What to build

Create a small `detection/demo/` package plus scripts, docs, report artifacts, and tests:

- `docs/demo_case_catalog_10_cases.md`
- `docs/demo_dashboard_design.md`
- `detection/demo/case_catalog.py`
- `detection/demo/case_runner.py`
- `detection/demo/classification.py`
- `scripts/demo/run_demo_case_matrix.py`
- `scripts/demo/generate_demo_dashboard_data.py`
- `tests/test_demo_case_matrix.py`
- `reports/demo_cases/README.md`

Optional if practical:

- `kibana/saved_objects/edr_case_matrix_dashboard.ndjson`
- `samples/demo_cases/*.json`
- `samples/sysmon/demo_cases/*.xml`

The implementation should reuse Phase 8 and earlier modules:

- `scripts/demo/run_art_sysmon_demo_validation.py`
- `normalization/sysmon/process_create_normalizer.py`
- Native and Sigma-like detection loaders/evaluators/alert builders.
- ML anomaly feature/scoring/alert modules.
- Event, alert, and response indexers.
- SOAR dry-run response planning.

Do not duplicate detection semantics.

## Demo case catalog

Implement `detection/demo/case_catalog.py`.

Each case must define:

- `case_id`
- `name`
- `category`: `attack|benign|limitation`
- `technique_id` when relevant
- `input_type`: `fixture|xml|json`
- `input_path` or fixture mode
- `engine`: `native|sigma-like|all|ml-anomaly`
- `expected_alert`: `true|false`
- `expected_engines`
- `expected_rule_ids`
- `expected_response`: `true|false`
- `expected_protection`: `none|dry-run|execute-lab-only`
- `description`
- `teacher_demo_notes`

Use a typed model. A dataclass is enough:

```python
@dataclass(frozen=True)
class DemoCase:
    case_id: str
    name: str
    category: str
    input_type: str
    engine: str
    expected_alert: bool
    expected_engines: tuple[str, ...]
    expected_rule_ids: tuple[str, ...]
    expected_response: bool
    expected_protection: str
    description: str
    teacher_demo_notes: str
    technique_id: str | None = None
    input_path: Path | None = None
```

Validation requirements:

- `case_id` values are unique.
- `category` is one of `attack`, `benign`, or `limitation`.
- `input_type` is one of `fixture`, `xml`, or `json`.
- `engine` is one of `native`, `sigma-like`, `all`, or `ml-anomaly`.
- `expected_protection` is one of `none`, `dry-run`, or `execute-lab-only`.
- Attack cases with `expected_alert = true` should include at least one expected engine or rule ID.
- `execute-lab-only` is documentation-only for now and must not execute real containment.

## Required case mix

Create around 10 labeled cases:

- At least 5 true-positive expected attack/suspicious cases.
- At least 2 true-negative benign cases.
- At least 1 expected false-positive analysis case.
- At least 1 known limitation / false-negative case.

Suggested case set:

1. `attack_t1059_001_art_powershell_xml`
   - Category: `attack`
   - Input: Phase 8 sample Sysmon XML.
   - Expected alert: true.
   - Expected rules: native and Sigma-like PowerShell.
   - Expected response: true.
   - Expected classification: true positive.

2. `attack_t1059_001_fixture_powershell`
   - Category: `attack`
   - Input: fixture detectable PowerShell.
   - Expected alert: true.
   - Expected rules: native and Sigma-like PowerShell.
   - Expected response: true.
   - Expected classification: true positive.

3. `attack_ml_encoded_download_json`
   - Category: `attack`
   - Input: Phase 8 ML suspicious JSON sample.
   - Expected alert: true.
   - Expected engine: `ml-anomaly`.
   - Expected response: false unless SOAR explicitly supports ML anomaly alerts.
   - Expected classification: true positive.

4. `attack_t1059_001_safe_manual_marker_xml`
   - Category: `attack`
   - Input: safe manual PowerShell marker XML sample.
   - Expected alert: true.
   - Expected rules: native and Sigma-like PowerShell.
   - Expected response: true.
   - Expected classification: true positive.

5. `attack_t1059_001_atomic_marker_json`
   - Category: `attack`
   - Input: normalized JSON derived from a safe Atomic Red Team marker.
   - Expected alert: true.
   - Expected rules: native and Sigma-like PowerShell, or ML anomaly if using JSON anomaly route.
   - Expected response: true only when produced alert matches SOAR playbook.
   - Expected classification: true positive.

6. `benign_cmd_whoami_fixture`
   - Category: `benign`
   - Input: existing Sysmon Event ID 1 fixture without PowerShell mutation.
   - Expected alert: false.
   - Expected response: false.
   - Expected classification: true negative.

7. `benign_explorer_cmd_json`
   - Category: `benign`
   - Input: crafted normalized ECS JSON for normal `cmd.exe /c whoami`.
   - Expected alert: false.
   - Expected response: false.
   - Expected classification: true negative.

8. `analysis_fp_admin_powershell_inventory`
   - Category: `benign`
   - Input: safe admin PowerShell inventory command.
   - Expected alert: false.
   - Actual may alert because current rules match PowerShell process creation broadly.
   - Expected classification: false positive.
   - Teacher note should explain why tuning allowlists/context would reduce this later.

9. `limitation_fn_non_powershell_execution`
   - Category: `limitation`
   - Input: safe non-PowerShell execution sample, such as `cmd.exe /c whoami` or `wscript.exe` marker.
   - Expected alert: true for the story being demonstrated, but current MVP may not alert because detection coverage focuses on PowerShell `T1059.001`.
   - Expected classification: false negative.
   - Teacher note should explain current detection coverage limitation.

10. `benign_ml_common_process_json`
    - Category: `benign`
    - Input: normalized ECS JSON that scores below ML threshold.
    - Expected alert: false.
    - Expected classification: true negative.

The exact case names can change, but the final catalog must preserve the mix and teaching intent.

## Classification logic

Implement `detection/demo/classification.py`.

Classification rules:

- `expected_alert = true` and `actual_alert = true` => `true_positive`
- `expected_alert = false` and `actual_alert = false` => `true_negative`
- `expected_alert = false` and `actual_alert = true` => `false_positive`
- `expected_alert = true` and `actual_alert = false` => `false_negative`

Expose a small pure function:

```python
def classify_case(*, expected_alert: bool, actual_alert: bool) -> str:
    ...
```

Also expose a summary helper that counts:

- `true_positive_count`
- `true_negative_count`
- `false_positive_count`
- `false_negative_count`

This module must have no Elasticsearch, Kafka, Kibana, or Windows VM dependency.

## Case runner

Implement `detection/demo/case_runner.py`.

Responsibilities:

- Load the catalog.
- Run each case through existing Phase 8 validation paths or direct existing modules.
- Collect normalized event count, alert count, alerts, response count, indexed counts, and errors.
- Classify each case using `classification.py`.
- Render JSON and Markdown matrix artifacts.
- Never require live infrastructure unless write flags are explicitly passed.

Suggested case result shape:

```json
{
  "case_id": "attack_t1059_001_art_powershell_xml",
  "name": "Atomic Red Team T1059.001 PowerShell",
  "category": "attack",
  "technique_id": "T1059.001",
  "expected_alert": true,
  "actual_alert": true,
  "classification": "true_positive",
  "expected_rule_ids": ["det.t1059_001.powershell_process_start"],
  "actual_rule_ids": ["det.t1059_001.powershell_process_start"],
  "actual_engines": ["native", "sigma-like"],
  "normalized_event_count": 1,
  "alert_count": 2,
  "response_count": 2,
  "indexed_event_count": 0,
  "indexed_alert_count": 0,
  "indexed_response_count": 0,
  "expected_protection": "dry-run",
  "status": "completed",
  "error": null,
  "teacher_demo_notes": "..."
}
```

Error handling:

- Predictable per-case failures should produce a case row with `status = failed` and an `error` string.
- The CLI should return non-zero only for systemic failures like invalid catalog, output write failure, or unexpected implementation error.
- Do not silently drop failed cases.

## Case matrix CLI

Create `scripts/demo/run_demo_case_matrix.py`.

Commands:

```powershell
python scripts\demo\run_demo_case_matrix.py --output reports\demo_cases\case_matrix.json
```

```powershell
python scripts\demo\run_demo_case_matrix.py --output reports\demo_cases\case_matrix.json --write-events --write-alerts --write-response --elasticsearch-url http://localhost:9200
```

Options:

- `--output`, default `reports\demo_cases\case_matrix.json`
- `--markdown-output`, default derived as `reports\demo_cases\case_matrix.md`
- `--write-events`
- `--write-alerts`
- `--write-response`
- `--elasticsearch-url`, default `http://localhost:9200`
- `--case-id` optional repeatable filter for focused demo runs
- `--include-failures`, default true, keeps failed case rows in output

Behavior:

- Create output directory if missing.
- Write `case_matrix.json`.
- Write `case_matrix.md`.
- Without write flags, do not call Elasticsearch.
- With write flags, use existing event, alert, and response indexers.
- Return `0` when the matrix is generated, even when FP/FN cases exist.
- Return `2` for predictable operational failure.
- Return `3` for unexpected implementation failure.

## Dashboard data CLI

Create `scripts/demo/generate_demo_dashboard_data.py`.

Command:

```powershell
python scripts\demo\generate_demo_dashboard_data.py --case-matrix reports\demo_cases\case_matrix.json --output reports\demo_cases\dashboard_data.json
```

Dashboard data should include:

- `total_cases`
- `true_positive_count`
- `true_negative_count`
- `false_positive_count`
- `false_negative_count`
- `alert_count_by_rule`
- `alert_count_by_engine`
- `response_count`
- `protection_count` when available
- `case_rows` for dashboard table

Suggested `case_rows` fields:

- `case_id`
- `name`
- `category`
- `technique_id`
- `classification`
- `expected_alert`
- `actual_alert`
- `alert_count`
- `actual_rule_ids`
- `actual_engines`
- `response_count`
- `expected_protection`
- `teacher_demo_notes`

The dashboard data generator should be pure local file processing and must not call Elasticsearch or Kibana.

## Reports

Create `reports/demo_cases/README.md`.

Document:

- What `case_matrix.json` contains.
- What `case_matrix.md` contains.
- What `dashboard_data.json` contains.
- How to regenerate reports.
- Why FP/FN cases are intentionally visible.
- Which files are suitable for teacher demo evidence.

Generated outputs:

- `reports/demo_cases/case_matrix.json`
- `reports/demo_cases/case_matrix.md`
- `reports/demo_cases/dashboard_data.json`

Generated outputs may be created by tests in a temp directory, but the repo should include the README.

## Docs

Create `docs/demo_case_catalog_10_cases.md`.

Document:

- The around 10 demo cases.
- Case IDs, names, categories, expected alert behavior, expected engines/rules, expected response behavior, and teacher notes.
- Which cases are expected TP, TN, FP, and FN.
- Which cases can be driven by Windows VM / Atomic Red Team.
- Which cases are deterministic local samples.
- Safety boundaries: no malware, no real containment.

Create `docs/demo_dashboard_design.md`.

Document how to create dashboard panels:

- TP/TN/FP/FN count.
- Case result table.
- Alerts by `rule.id`.
- Alerts by `detection.engine`.
- Response actions.
- Protection actions placeholder.

Also document useful index patterns:

- `edr-normalized-events-*`
- `edr-alerts-native-*`
- `edr-response-actions-*`

And useful fields:

- `case.case_id` if case metadata is indexed.
- `rule.id`
- `detection.engine`
- `response.status`
- `playbook.id`
- `event.dataset`
- `event.code`
- `process.name`

If case metadata is not indexed into Elasticsearch yet, the docs should explain that `dashboard_data.json` is the source for case matrix counts, while Kibana validates event/alert/response evidence.

## Optional samples

Optional samples may be added under:

- `samples/demo_cases/*.json`
- `samples/sysmon/demo_cases/*.xml`

Sample requirements:

- No malware payloads.
- No malware download commands.
- Safe manual command markers only.
- XML samples must be compatible with the existing Sysmon Event ID 1 normalizer.
- JSON samples must be normalized ECS-like event objects compatible with existing detection or ML paths.

Prefer reusing existing Phase 8 samples when possible.

## Tests

Create `tests/test_demo_case_matrix.py`.

Tests must not require:

- Windows VM.
- Atomic Red Team.
- Docker.
- Kafka.
- Elasticsearch.
- Kibana.

Cover:

- Catalog returns around 10 cases.
- Catalog includes at least 5 attack/suspicious cases with `expected_alert = true`.
- Catalog includes at least 2 benign true-negative expected cases.
- Catalog includes at least 1 expected false-positive analysis case.
- Catalog includes at least 1 known limitation / false-negative case.
- Case IDs are unique.
- Case fields validate allowed enums.
- `classify_case()` returns `true_positive`.
- `classify_case()` returns `true_negative`.
- `classify_case()` returns `false_positive`.
- `classify_case()` returns `false_negative`.
- Matrix runner generates rows for all cases without live infrastructure.
- Matrix runner writes JSON and Markdown outputs.
- Matrix includes TP/TN/FP/FN counts.
- Matrix includes actual alert rule IDs and engines.
- Matrix includes response counts for matching alert cases.
- Write flags call monkeypatched event/alert/response indexers and do not require Elasticsearch.
- Without write flags, indexers are not called.
- Dashboard data generator reads a matrix file and writes `dashboard_data.json`.
- Dashboard data includes counts by classification, rule, and engine.
- Docs exist and mention TP/TN/FP/FN, Kibana, `rule.id`, `detection.engine`, and response actions.

## Commands to run

Focused tests:

```powershell
python -m pytest tests\test_demo_case_matrix.py
```

Full regression:

```powershell
python -m pytest tests
```

Generate case matrix:

```powershell
python scripts\demo\run_demo_case_matrix.py --output reports\demo_cases\case_matrix.json
```

Generate case matrix with live indexing:

```powershell
python scripts\demo\run_demo_case_matrix.py --output reports\demo_cases\case_matrix.json --write-events --write-alerts --write-response --elasticsearch-url http://localhost:9200
```

Generate dashboard data:

```powershell
python scripts\demo\generate_demo_dashboard_data.py --case-matrix reports\demo_cases\case_matrix.json --output reports\demo_cases\dashboard_data.json
```

## Acceptance criteria

- [ ] `docs/demo_case_catalog_10_cases.md` documents around 10 labeled demo cases.
- [ ] `docs/demo_dashboard_design.md` documents TP/TN/FP/FN and Kibana dashboard panels.
- [ ] `detection/demo/case_catalog.py` defines a validated typed case catalog.
- [ ] Catalog includes at least 5 true-positive expected attack/suspicious cases.
- [ ] Catalog includes at least 2 true-negative benign cases.
- [ ] Catalog includes at least 1 expected false-positive analysis case.
- [ ] Catalog includes at least 1 known limitation / false-negative case.
- [ ] `detection/demo/classification.py` implements TP/TN/FP/FN classification as a pure function.
- [ ] `detection/demo/case_runner.py` runs every case through existing pipeline components.
- [ ] Case runner does not require live infrastructure by default.
- [ ] Case runner does not hide false positives or false negatives.
- [ ] `scripts/demo/run_demo_case_matrix.py` writes `case_matrix.json`.
- [ ] `scripts/demo/run_demo_case_matrix.py` writes `case_matrix.md`.
- [ ] Matrix rows include expected vs actual alert status.
- [ ] Matrix rows include actual rule IDs and detection engines.
- [ ] Matrix rows include response counts.
- [ ] Matrix output includes classification counts.
- [ ] `scripts/demo/generate_demo_dashboard_data.py` writes `dashboard_data.json`.
- [ ] Dashboard data includes total cases, TP/TN/FP/FN counts, alert counts by rule, alert counts by engine, response count, protection count when available, and case rows.
- [ ] `reports/demo_cases/README.md` explains report artifacts and teacher demo usage.
- [ ] Tests pass without Windows VM, Atomic Red Team, Docker, Kafka, Elasticsearch, or Kibana.
- [ ] Existing native, Sigma-like, ML, Kafka, SOAR, and Phase 8 semantics remain unchanged.

## Blocked by

- `.scratch/phase-8-vm-art-attack-demo-validation/issues/01-atomic-red-team-sysmon-dashboard-demo.md`
- `.scratch/phase-7-dashboard-report-mvp/issues/01-final-demo-report-and-operator-dashboard.md`
- `.scratch/phase-6-ml-anomaly-mvp/issues/01-process-anomaly-detection-mvp.md`
- `.scratch/phase-5-soar-response-mvp/issues/01-soar-dry-run-response-pipeline.md`
- `.scratch/phase-4-kafka-pipeline-mvp/issues/01-kafka-normalized-event-detection-pipeline.md`
- `.scratch/phase-3-live-telemetry-pipeline/issues/02-sigma-like-detection-mvp.md`
- `.scratch/phase-2-detection-engine-mvp/issues/06-native-detection-pipeline-with-alert-indexing.md`

## Out-of-scope boundaries

- Do not add malware payloads.
- Do not download malware.
- Do not add real containment yet.
- Do not change existing native rule semantics just to pass all cases.
- Do not change existing Sigma-like rule semantics just to pass all cases.
- Do not change existing ML scoring semantics just to pass all cases.
- Do not change Kafka or SOAR semantics just to pass all cases.
- Do not hide false positives or false negatives.
- Do not require Windows VM in automated tests.
- Do not require Atomic Red Team in automated tests.
- Do not require Elasticsearch, Kafka, Docker, or Kibana in automated tests.

## Comments
