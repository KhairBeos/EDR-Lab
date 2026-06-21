Status: done

# Process anomaly detection MVP

## Parent

`.scratch/phase-6-ml-anomaly-mvp/PRD.md`

## Goal

Implement a production-shaped ML-style process anomaly detection MVP using normalized Sysmon Event ID 1 ECS documents.

This must not be smoke-only. Fixture mode should be a deterministic input mode for the real anomaly pipeline, not a separate fake path.

## Context

Phase 2 Native Detection Pipeline MVP is complete.

Phase 3 Live Telemetry Pipeline, Sigma-like Detection, and Coverage Report are complete.

Phase 4 Kafka normalized event detection pipeline is complete.

Phase 5 SOAR dry-run response pipeline is complete.

Current capabilities:

- Normalize Sysmon Event ID 1 process creation telemetry into ECS-like documents.
- Generate native and Sigma-like alerts for `T1059.001` PowerShell.
- Index alert documents through `detection/rules/native/alert_indexer.py`.
- Run fixture-based and JSON/file-based pipeline commands without requiring live Elasticsearch.

## What to build

Add a lightweight deterministic ML-style anomaly pipeline:

```text
normalized Sysmon Event ID 1 event
  -> process feature extraction
  -> baseline profile comparison
  -> anomaly score and reasons
  -> anomaly alert document
  -> optional alert indexing through existing alert_indexer.py
```

The implementation should feel like a small production component: structured modules, validation, deterministic outputs, focused tests, and clear operator docs.

It must not add a training service or heavy ML dependency. This is a heuristic ML-style MVP, not trained production ML.

## Technical design

Create a small package under `detection/ml/`:

- `features.py` extracts deterministic process features from one normalized ECS Sysmon Event ID 1 document.
- `baseline.py` loads and validates a local baseline profile.
- `scorer.py` compares extracted features against the baseline and returns a score from `0.0` to `1.0` plus human-readable reasons.
- `alerts.py` builds an alert document compatible with the existing native alert indexer shape.
- `baselines/process_baseline.json` stores the local deterministic process baseline.

Create a standalone command:

- `scripts/ml/run_process_anomaly_detection.py`

The standalone command is acceptable for this issue. Optional later integration into the live telemetry pipeline may add `--engine ml-anomaly` or `--engine all`, but this issue should not require Kafka changes or broad pipeline rewrites.

## Feature extraction

Extract these features from a normalized Sysmon Event ID 1 ECS document:

- `process.name`
- `process.executable`
- `process.parent.name`
- `process.command_line` length
- `process.args` count
- executable directory depth
- `has_encoded_command` flag
- `has_network_tool_flag` for `curl`, `wget`, `nc`, `netcat`, `Invoke-WebRequest`, and equivalent PowerShell download keywords
- `hour_of_day` from `event.created` or `@timestamp`

Feature extraction requirements:

- Missing optional process fields should not crash the command.
- Missing required event/process shape should raise a clear local validation error.
- String matching should be deterministic and case-insensitive where useful.
- Timestamp parsing should support the existing normalized fixture format.
- Feature output must be JSON-compatible.

Example feature shape:

```json
{
  "process_name": "powershell.exe",
  "process_executable": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
  "parent_process_name": "explorer.exe",
  "command_line_length": 46,
  "args_count": 2,
  "executable_directory_depth": 5,
  "has_encoded_command": false,
  "has_network_tool_flag": false,
  "hour_of_day": 10
}
```

## Baseline profile

Create:

- `detection/ml/baselines/process_baseline.json`

The baseline profile must include:

- `common_process_names`
- `allowed_parent_child_pairs`
- `max_command_line_length`
- `max_args_count`
- `suspicious_keywords`
- `normal_hours` optional

Baseline validation requirements:

- Required fields exist and have the expected type.
- Numeric limits are positive.
- `allowed_parent_child_pairs` uses explicit parent/child pairs.
- `normal_hours`, if present, contains valid hour integers from `0` to `23`.
- Invalid baseline files raise clear validation errors.

Suggested baseline content should keep the default repository fixture benign or low-scoring, while still allowing crafted suspicious events to cross the default threshold.

## Scoring

Implement deterministic scoring in `detection/ml/scorer.py`.

Requirements:

- Score range is always clamped to `0.0 <= score <= 1.0`.
- Default threshold is `0.7`.
- Return both numeric score and a list of reasons.
- Add weighted risk when:
  - `process.name` is not in `common_process_names`
  - parent-child pair is not in `allowed_parent_child_pairs`
  - command line length exceeds `max_command_line_length`
  - args count exceeds `max_args_count`
  - encoded command flag is present
  - suspicious keyword is present
  - executable path is unusual
  - hour is outside `normal_hours`, when configured

The weights should be simple constants in code, easy to inspect in tests. Do not use sklearn or any heavy ML framework.

Example result shape:

```json
{
  "score": 0.82,
  "threshold": 0.7,
  "is_anomaly": true,
  "reasons": [
    "process name is not common",
    "encoded command flag present",
    "suspicious keyword matched: invoke-webrequest"
  ]
}
```

## Alert document

Produce an alert only when `score >= threshold`.

The anomaly alert must be compatible with the existing alert indexer, including:

- `alert.*`
- rule/model metadata
- `event.*`
- `process.*`
- `host` and `user` when present
- `detection.engine = ml-anomaly`
- `ml.score`
- `ml.features`
- `ml.reasons`

Deterministic alert ID:

```text
det-ml-anomaly-process-<digest>
```

Alert ID requirements:

- Include stable event/process identity material.
- Include score reasons or feature material enough that different anomaly causes can produce different IDs when appropriate.
- Do not depend on wall-clock time.

Suggested alert shape:

```json
{
  "alert": {
    "id": "det-ml-anomaly-process-...",
    "kind": "signal",
    "status": "open",
    "created": "2026-06-17T10:00:00Z",
    "severity": "medium",
    "confidence": "medium"
  },
  "rule": {
    "id": "ml.process_anomaly",
    "name": "ML-style Process Anomaly",
    "version": 1,
    "description": "Deterministic heuristic anomaly detection for process creation events."
  },
  "event": {
    "dataset": "windows.sysmon_operational",
    "code": 1,
    "kind": "event",
    "category": ["process"],
    "type": ["start"],
    "created": "2026-06-17T10:00:00Z"
  },
  "process": {},
  "host": {},
  "user": {},
  "detection": {
    "engine": "ml-anomaly"
  },
  "ml": {
    "score": 0.82,
    "threshold": 0.7,
    "features": {},
    "reasons": []
  }
}
```

## CLI

Create:

- `scripts/ml/run_process_anomaly_detection.py`

Commands:

```powershell
python scripts\ml\run_process_anomaly_detection.py --input fixture
```

```powershell
python scripts\ml\run_process_anomaly_detection.py --input json --event-path .\event.json
```

Options:

- `--threshold 0.7`
- `--write-alerts`
- `--elasticsearch-url http://localhost:9200`
- `--alert-index-prefix edr-alerts-native`
- `--output json|summary`

Behavior:

- `fixture` loads the existing normalized Sysmon Event ID 1 fixture path or uses existing fixture normalization helpers.
- Default benign fixture should produce no alert or a low score below threshold.
- Tests should include a crafted suspicious fixture/event that produces one `ml-anomaly` alert.
- `json` reads one normalized ECS event from `--event-path`.
- `--write-alerts` indexes produced anomaly alerts with the existing `index_alerts()` helper from `detection/rules/native/alert_indexer.py`.
- Without `--write-alerts`, the command must not call Elasticsearch or the alert indexer.
- Output JSON should include input mode, event count, anomaly count, alert count, score result, alerts, and indexed alert metadata.
- Summary output should be short and operator-friendly.

Suggested exit codes:

- `0` when command runs successfully, even when no anomaly is produced.
- `2` for operational failures such as bad event path, malformed JSON, Elasticsearch/indexing failure, or invalid baseline file.
- `3` for unexpected implementation failures.

## Files to create

- `detection/ml/features.py`
- `detection/ml/baseline.py`
- `detection/ml/scorer.py`
- `detection/ml/alerts.py`
- `detection/ml/baselines/process_baseline.json`
- `scripts/ml/run_process_anomaly_detection.py`
- `tests/test_process_anomaly_detection.py`
- `docs/ml_anomaly_mvp.md`

Create package `__init__.py` files only if needed for clean imports in this repo.

## Files to edit only if useful

- `README.md`
- `docs/live_telemetry_pipeline_mvp.md`
- `docs/kafka_pipeline_mvp.md`
- `docs/sigma_detection_mvp.md`

Do not edit unless needed:

- Existing native detection rule semantics.
- Existing Sigma-like detection semantics.
- Existing Kafka consumer/producer behavior.
- Existing SOAR response modules.
- Existing containment modules.

## Tests

Create:

- `tests/test_process_anomaly_detection.py`

Tests must not require live Elasticsearch.

Cover:

- Feature extraction reads process name, executable, parent name, command-line length, args count, path depth, flags, and hour.
- Feature extraction handles missing optional host/user fields.
- Feature extraction rejects missing required event/process shape with a clear error.
- Baseline loader validates required fields.
- Baseline loader rejects missing `common_process_names`.
- Baseline loader rejects invalid hour values.
- Benign fixture defaults to no anomaly or score below default threshold.
- Crafted suspicious event produces score `>= 0.7`.
- Crafted suspicious event produces one alert.
- Alert includes `detection.engine = ml-anomaly`.
- Alert ID starts with `det-ml-anomaly-process-`.
- Alert ID is deterministic for the same event, features, score, and reasons.
- Alert includes `ml.score`, `ml.features`, and `ml.reasons`.
- Alert preserves selected `event`, `process`, `host`, and `user` fields.
- `--input fixture` command runs without Elasticsearch.
- `--input json --event-path ...` command runs on one normalized ECS event.
- `--write-alerts` calls existing native `index_alerts()` with the anomaly alert.
- Without `--write-alerts`, indexer is not called.
- Indexing errors map to exit code `2`.
- Tests do not import or call SOAR/containment modules.

## Docs

Create:

- `docs/ml_anomaly_mvp.md`

Document:

- Purpose of the MVP.
- Pipeline shape:

```text
normalized event -> features -> baseline -> score -> anomaly alert -> optional alert index
```

- Why this is ML-style heuristic scoring, not trained production ML.
- Baseline profile fields.
- Feature list.
- Scoring behavior and default threshold.
- Fixture command.
- JSON command.
- Response when no anomaly is produced.
- Alert indexing command.
- Alert index name compatibility with `edr-alerts-native-YYYY.MM.DD`.
- Expected alert shape.
- Out-of-scope items.

## Commands to run

Focused tests:

```powershell
python -m pytest tests\test_process_anomaly_detection.py
```

Full regression:

```powershell
python -m pytest tests
```

Manual fixture check:

```powershell
python scripts\ml\run_process_anomaly_detection.py --input fixture
```

Manual JSON check:

```powershell
python scripts\ml\run_process_anomaly_detection.py --input json --event-path .\event.json
```

Manual summary:

```powershell
python scripts\ml\run_process_anomaly_detection.py --input fixture --output summary
```

Manual indexing check:

```powershell
python scripts\ml\run_process_anomaly_detection.py --input json --event-path .\event.json --write-alerts --elasticsearch-url http://localhost:9200
```

## Acceptance criteria

- [ ] `detection/ml/features.py` extracts deterministic process features from normalized Sysmon Event ID 1 ECS documents.
- [ ] `detection/ml/baseline.py` loads and validates a local baseline profile.
- [ ] `detection/ml/baselines/process_baseline.json` defines common process names, parent-child pairs, numeric limits, suspicious keywords, and optional normal hours.
- [ ] `detection/ml/scorer.py` produces deterministic score values from `0.0` to `1.0`.
- [ ] Default threshold is `0.7`.
- [ ] Scorer returns human-readable reasons.
- [ ] Benign fixture defaults to no anomaly or low score.
- [ ] Crafted suspicious event produces score `>= 0.7`.
- [ ] Alert is produced only when score is greater than or equal to threshold.
- [ ] Anomaly alert ID starts with `det-ml-anomaly-process-`.
- [ ] Anomaly alert ID is deterministic and does not depend on wall-clock time.
- [ ] Alert includes `detection.engine = ml-anomaly`.
- [ ] Alert includes `ml.score`, `ml.features`, and `ml.reasons`.
- [ ] Alert preserves selected `event`, `process`, `host`, and `user` context.
- [ ] Alert shape is compatible with existing `detection/rules/native/alert_indexer.py`.
- [ ] `scripts/ml/run_process_anomaly_detection.py --input fixture` runs without Elasticsearch.
- [ ] `scripts/ml/run_process_anomaly_detection.py --input json --event-path .\event.json` processes one normalized ECS event.
- [ ] `--write-alerts` indexes produced anomaly alerts through existing `index_alerts()`.
- [ ] Without `--write-alerts`, no indexing call is made.
- [ ] Tests do not require live Elasticsearch.
- [ ] Docs explain this is heuristic ML-style MVP, not trained production ML.
- [ ] Pipeline remains production-shaped and is not smoke-only.

## Blocked by

- `.scratch/phase-2-detection-engine-mvp/issues/06-native-detection-pipeline-with-alert-indexing.md`
- `.scratch/phase-3-live-telemetry-pipeline/issues/01-live-telemetry-to-detection-pipeline.md`
- `.scratch/phase-3-live-telemetry-pipeline/issues/02-sigma-like-detection-mvp.md`
- `.scratch/phase-4-kafka-pipeline-mvp/issues/01-kafka-normalized-event-detection-pipeline.md`
- `.scratch/phase-5-soar-response-mvp/issues/01-soar-dry-run-response-pipeline.md`

## Out-of-scope boundaries

- Do not add heavy ML frameworks.
- Do not add MLflow.
- Do not add a training service.
- Do not add LSTM or sequence models.
- Do not add sklearn unless it is already present and there is a strong reason; prefer standard library deterministic scoring.
- Do not change Kafka behavior.
- Do not change SOAR response behavior.
- Do not add TheHive.
- Do not add dashboards.
- Do not add real containment.
- Do not call containment modules.
- Do not require live Elasticsearch for tests.

## Comments
