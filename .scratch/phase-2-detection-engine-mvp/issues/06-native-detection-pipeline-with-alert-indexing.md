Status: done

# Native detection pipeline with alert indexing

## Parent

`.scratch/phase-2-detection-engine-mvp/PRD.md`

## Goal

Turn the current Phase 2 native PowerShell detection components into a real local detection pipeline, not a separate smoke-only path.

The pipeline should support deterministic fixture input, real Elasticsearch candidate input, native rule evaluation, in-memory alert building, JSON/summary output, and opt-in alert writes to Elasticsearch.

## What to build

Build a production-shaped local native detection runner.

The runner should:

- Treat fixture mode as an input mode, not as another smoke-only feature.
- Treat Elasticsearch mode as an input mode for real normalized Sysmon Event ID 1 events.
- Load the existing native `T1059.001` PowerShell rule.
- Evaluate normalized candidate events using the existing native evaluator.
- Build alert documents using the existing alert builder.
- Print JSON or summary output.
- Write alerts to Elasticsearch only when `--write-alerts` is explicitly provided.

Add a small alert indexer that writes alert documents to a daily native alert index:

```text
edr-alerts-native-YYYY.MM.DD
```

The indexer must use `alert.alert.id` as the Elasticsearch document ID.

## Files to create or edit

Create:

- `detection/rules/native/alert_indexer.py`
- `scripts/detection/run_native_detection.py`
- `tests/test_alert_indexer.py`
- `tests/test_run_native_detection.py`

Edit:

- `docs/phase_2_detection_engine_mvp.md`

Do not edit unless a blocking bug is found:

- Native rule loader/evaluator.
- Alert builder.
- Elasticsearch candidate query client.
- Existing Phase 2 smoke command.
- Existing Phase 1 smoke command.

## Commands to run

Focused tests:

```powershell
python -m pytest tests\test_alert_indexer.py
python -m pytest tests\test_run_native_detection.py
```

Full regression:

```powershell
python -m pytest tests
```

Manual fixture mode:

```powershell
python scripts\detection\run_native_detection.py
python scripts\detection\run_native_detection.py --output summary
python scripts\detection\run_native_detection.py --fixture-no-match
```

Manual Elasticsearch mode:

```powershell
docker compose up -d
python scripts\detection\run_native_detection.py --input elasticsearch
```

Manual opt-in alert indexing:

```powershell
python scripts\detection\run_native_detection.py --input elasticsearch --write-alerts
```

## Acceptance criteria

- [ ] A real detection runner exists at `scripts/detection/run_native_detection.py`.
- [ ] Fixture mode is an input mode of the real detection runner.
- [ ] No new smoke-only script is created.
- [ ] Fixture mode runs without Docker, Elasticsearch, Logstash, Kibana, Kafka, or Windows VM.
- [ ] Elasticsearch mode uses the existing Elasticsearch candidate query client.
- [ ] The runner loads the existing native `T1059.001` PowerShell rule.
- [ ] The runner evaluates candidates with the existing native evaluator.
- [ ] The runner builds alerts with the existing alert document builder.
- [ ] The runner prints JSON by default.
- [ ] The runner supports summary output.
- [ ] The runner does not write alerts unless `--write-alerts` is explicitly set.
- [ ] When `--write-alerts` is set, alerts write to `edr-alerts-native-YYYY.MM.DD`.
- [ ] Alert indexing uses `alert.alert.id` as the Elasticsearch document ID.
- [ ] The alert indexer uses only Python standard library `urllib.request`.
- [ ] Source metadata from Elasticsearch candidates is preserved in alert documents.
- [ ] Alert indexing errors map to an operational failure.
- [ ] Tests do not require live Elasticsearch.
- [ ] Documentation is updated to describe the production-shaped runner and opt-in alert indexing.

## Blocked by

- `.scratch/phase-2-detection-engine-mvp/issues/01-native-powershell-detection-rule.md`
- `.scratch/phase-2-detection-engine-mvp/issues/02-alert-document-for-powershell-rule.md`
- `.scratch/phase-2-detection-engine-mvp/issues/03-elasticsearch-query-for-normalized-powershell-events.md`
- `.scratch/phase-2-detection-engine-mvp/issues/04-detection-smoke-command.md`
- `.scratch/phase-2-detection-engine-mvp/issues/05-phase-2-detection-operator-docs.md`

## Out-of-scope boundaries

- Do not add Kafka.
- Do not add ML.
- Do not add SOAR.
- Do not add TheHive.
- Do not import SigmaHQ.
- Do not create dashboards.
- Do not add new Sysmon Event IDs.
- Do not write alerts unless `--write-alerts` is explicitly set.
- Do not create another smoke-only script.
