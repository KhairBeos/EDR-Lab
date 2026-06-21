Status: done

# SOAR dry-run response pipeline

## Parent

`.scratch/phase-5-soar-response-mvp/PRD.md`

## Goal

Implement a production-shaped SOAR dry-run response MVP that consumes existing alert documents and produces response action records.

This must not be smoke-only. Fixture alert mode is a deterministic input mode of the real response planning pipeline.

## Context

Phase 2 Native Detection Pipeline MVP is complete.

Phase 3 Live Telemetry Pipeline, Sigma-like Detection, and Coverage Report are complete.

Phase 4 Kafka normalized event detection pipeline is complete.

Current capabilities:

- Generate native and Sigma-like alerts for `T1059.001` PowerShell.
- Index alerts to `edr-alerts-native-YYYY.MM.DD`.
- Alerts include rule metadata, ATT&CK metadata, process context, host/user context, and optional source event metadata.

## What to build

Add a safe response planning pipeline:

```text
alert document
  -> response playbook selection
  -> dry-run response action planning
  -> response record
  -> optionally index response record to edr-response-actions-YYYY.MM.DD
```

The implementation must consume alert documents from existing detection outputs. It should not re-run detection and should not modify endpoints.

## Technical design

Add a small SOAR dry-run module under `response/soar/`:

- `loader.py` owns loading and validating the local YAML playbook.
- `engine.py` owns playbook matching and response record building.
- `response_indexer.py` owns optional Elasticsearch indexing of response records.

Playbook selection:

- Match `alert.rule.id` for the existing PowerShell native or Sigma-like rule IDs.
- Also match `attack.technique.id = T1059.001` so the playbook can handle equivalent alert shapes.
- If no playbook matches, return a clear result with zero response records.

The response engine must only plan actions. It must not call existing containment modules under `response/containment/`.

## Playbook

Create:

- `response/soar/playbooks/powershell_execution.yml`

Required playbook metadata:

- `id: soar.playbook.powershell_execution`
- `name: PowerShell Execution Response`
- `status: dry-run`
- `description`
- Match criteria for:
  - native rule ID `det.t1059_001.powershell_process_start`
  - Sigma-like rule ID `sigma_like.t1059_001.powershell_process_start`
  - ATT&CK technique ID `T1059.001`

Required actions:

- `notify_analyst`
- `collect_process_context`
- `recommend_host_review`

Each action must include:

- `id`
- `type`
- `status: planned`
- `description`

Do not implement a general SOAR playbook language. Support only the minimal local YAML subset needed for this MVP.

## Response record shape

Build one response record per matching alert:

```json
{
  "response": {
    "id": "...",
    "status": "planned",
    "mode": "dry-run",
    "created": "...",
    "severity": "medium"
  },
  "alert": {
    "id": "...",
    "rule_id": "...",
    "technique_id": "T1059.001"
  },
  "playbook": {
    "id": "soar.playbook.powershell_execution",
    "name": "PowerShell Execution Response"
  },
  "actions": [
    {
      "id": "notify_analyst",
      "type": "notification",
      "status": "planned",
      "description": "Notify analyst about PowerShell execution alert."
    },
    {
      "id": "collect_process_context",
      "type": "collection",
      "status": "planned",
      "description": "Collect process, parent process, host, and user context from alert document."
    },
    {
      "id": "recommend_host_review",
      "type": "recommendation",
      "status": "planned",
      "description": "Recommend host review; no containment action is executed."
    }
  ]
}
```

Response ID requirements:

- Deterministic for the same alert and playbook.
- Include playbook ID and alert ID in the stable material.
- Include action IDs in the stable material so changed action plans get different IDs.
- Must not depend on wall-clock time.

## Files to create or edit

Create:

- `response/soar/playbooks/powershell_execution.yml`
- `response/soar/loader.py`
- `response/soar/engine.py`
- `response/soar/response_indexer.py`
- `scripts/response/run_soar_response.py`
- `tests/test_soar_response_pipeline.py`
- `docs/soar_response_mvp.md`

Edit only if needed for clean imports or cross-links:

- `docs/live_telemetry_pipeline_mvp.md`
- `docs/kafka_pipeline_mvp.md`
- `docs/sigma_detection_mvp.md`

Do not edit unless a blocking bug is found:

- Existing detection rule semantics.
- Existing alert builders.
- Existing alert indexer.
- Existing Kafka pipeline.
- Existing containment modules under `response/containment/`.

## CLI

Fixture alert input:

```powershell
python scripts\response\run_soar_response.py --input fixture-alert
```

Alert JSON input:

```powershell
python scripts\response\run_soar_response.py --input alert-json --alert-path .\alert.json
```

Elasticsearch alert query input:

```powershell
python scripts\response\run_soar_response.py --input elasticsearch --elasticsearch-url http://localhost:9200 --alert-index-pattern edr-alerts-native-*
```

Options:

- `--write-response`
- `--response-index-prefix`, default `edr-response-actions`
- `--response-index-date YYYY-MM-DD`
- `--output json|summary`

## Behavior details

Fixture alert behavior:

- Generate a deterministic PowerShell alert using the existing pipeline or alert builder.
- The fixture alert should match the PowerShell response playbook.
- Produce exactly one response record.
- Do not require live Elasticsearch.

Alert JSON behavior:

- Read one alert document from `--alert-path`.
- Validate required alert fields before planning.
- Produce one response record when the alert matches the PowerShell playbook.
- Return zero response records with a clear message when no playbook matches.

Elasticsearch behavior:

- Query `--alert-index-pattern` from `--elasticsearch-url`.
- Fetch alert documents using a small query helper that can be monkeypatched in tests.
- Process returned alerts through the same SOAR engine path as fixture and file input.
- Tests must not require live Elasticsearch.

Indexing behavior:

- By default, do not write response records.
- When `--write-response` is set, index response records to:

```text
edr-response-actions-YYYY.MM.DD
```

- Use deterministic document IDs from `response.id`.
- Return indexing result metadata in JSON output.

## Safety boundaries

This MVP is dry-run only.

The implementation must not:

- Kill processes.
- Isolate hosts.
- Block network traffic.
- Modify endpoints.
- Delete files.
- Disable users.
- Call external ticketing systems.
- Integrate TheHive.
- Trigger Shuffle or any external SOAR runtime.
- Call modules under `response/containment/`.

All response actions must have:

```json
{
  "status": "planned"
}
```

## Commands to run

Focused tests:

```powershell
python -m pytest tests\test_soar_response_pipeline.py
```

Full regression:

```powershell
python -m pytest tests
```

Manual fixture check:

```powershell
python scripts\response\run_soar_response.py --input fixture-alert
```

Manual fixture summary:

```powershell
python scripts\response\run_soar_response.py --input fixture-alert --output summary
```

Manual alert JSON:

```powershell
python scripts\response\run_soar_response.py --input alert-json --alert-path .\alert.json
```

Manual response indexing:

```powershell
python scripts\response\run_soar_response.py --input fixture-alert --write-response --response-index-date 2026-06-17
```

Manual Elasticsearch alert query:

```powershell
python scripts\response\run_soar_response.py --input elasticsearch --elasticsearch-url http://localhost:9200 --alert-index-pattern edr-alerts-native-*
```

## Acceptance criteria

- [ ] A PowerShell execution SOAR playbook exists at `response/soar/playbooks/powershell_execution.yml`.
- [ ] Playbook loader validates required metadata, match criteria, and actions.
- [ ] Playbook matches native PowerShell alerts by `rule.id`.
- [ ] Playbook matches Sigma-like PowerShell alerts by `rule.id`.
- [ ] Playbook matches equivalent alerts by `attack.technique.id = T1059.001`.
- [ ] Fixture alert input produces one response record.
- [ ] Alert JSON input produces one response record.
- [ ] Elasticsearch input can be monkeypatched in tests.
- [ ] Non-matching alert returns zero response records with a clear message.
- [ ] Response record includes deterministic `response.id`.
- [ ] Response record includes `response.status = planned`.
- [ ] Response record includes `response.mode = dry-run`.
- [ ] Response record copies alert ID, rule ID, and technique ID.
- [ ] Response record includes playbook ID and name.
- [ ] Response record includes exactly three planned actions: `notify_analyst`, `collect_process_context`, `recommend_host_review`.
- [ ] Every action has `status = planned`.
- [ ] No containment module is called.
- [ ] `--write-response` indexes response records to `edr-response-actions-YYYY.MM.DD`.
- [ ] Response indexing uses `response.id` as the document ID.
- [ ] Tests do not require live Elasticsearch.
- [ ] Docs clearly state dry-run safety boundaries.
- [ ] Pipeline remains production-shaped and is not smoke-only.

## Blocked by

- `.scratch/phase-2-detection-engine-mvp/issues/06-native-detection-pipeline-with-alert-indexing.md`
- `.scratch/phase-3-live-telemetry-pipeline/issues/01-live-telemetry-to-detection-pipeline.md`
- `.scratch/phase-3-live-telemetry-pipeline/issues/02-sigma-like-detection-mvp.md`
- `.scratch/phase-4-kafka-pipeline-mvp/issues/01-kafka-normalized-event-detection-pipeline.md`

## Out-of-scope boundaries

- Do not add TheHive.
- Do not add real containment.
- Do not modify endpoints.
- Do not kill processes.
- Do not isolate hosts.
- Do not block network traffic.
- Do not call external ticketing systems.
- Do not add ML.
- Do not create dashboards.
- Do not replace existing detection or alert semantics.
- Do not require live Elasticsearch for tests.

## Comments
