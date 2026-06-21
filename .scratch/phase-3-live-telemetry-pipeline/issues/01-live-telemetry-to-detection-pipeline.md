Status: done

# Live telemetry to detection pipeline

## Parent

`.scratch/phase-2-detection-engine-mvp/PRD.md`

## Goal

Implement a production-shaped live telemetry pipeline MVP that connects event ingestion, normalization, Elasticsearch event indexing, native detection, and alert indexing.

This must not be a smoke-only script. Fixture mode is a deterministic input mode of the real pipeline.

## What to build

Build a local live telemetry pipeline runner that supports:

- `fixture` input mode using the existing Phase 1 Sysmon Event ID 1 XML fixture.
- `xml` input mode using a Sysmon Event ID 1 XML file exported from Windows Event Viewer.
- Normalization with the existing Sysmon Event ID 1 normalizer.
- Optional normalized event indexing to Elasticsearch only when `--write-events` is set.
- Native `T1059.001` PowerShell detection in memory.
- Alert document building in memory.
- Optional alert indexing to Elasticsearch only when `--write-alerts` is set.
- JSON and summary output.

Add an Elasticsearch event indexer for normalized ECS events:

```text
edr-normalized-events-YYYY.MM.DD
```

The event indexer must use deterministic document IDs:

1. `event.id` if present.
2. Else `sysmon.event_data.ProcessGuid`.
3. Else stable hash from event dataset/code/created/process fields.

## Files to create or edit

Create:

- `collection/elasticsearch/event_indexer.py`
- `scripts/pipeline/run_live_telemetry_pipeline.py`
- `tests/test_event_indexer.py`
- `tests/test_live_telemetry_pipeline.py`
- `docs/live_telemetry_pipeline_mvp.md`

Do not edit unless a blocking bug is found:

- `normalization/sysmon/process_create_normalizer.py`
- `detection/rules/native/loader.py`
- `detection/rules/native/evaluator.py`
- `detection/rules/native/alerts.py`
- `detection/rules/native/alert_indexer.py`
- Existing smoke scripts.

## CLI

Fixture input:

```powershell
python scripts\pipeline\run_live_telemetry_pipeline.py --input fixture
```

XML input:

```powershell
python scripts\pipeline\run_live_telemetry_pipeline.py --input xml --xml-path <path>
```

Options:

- `--write-events`
- `--write-alerts`
- `--elasticsearch-url`, default `http://localhost:9200`
- `--event-index-prefix`, default `edr-normalized-events`
- `--alert-index-prefix`, default `edr-alerts-native`
- `--event-index-date YYYY-MM-DD`
- `--alert-index-date YYYY-MM-DD`
- `--output json|summary`
- `--fixture-detectable-powershell`

## Commands to run

Focused tests:

```powershell
python -m pytest tests\test_event_indexer.py
python -m pytest tests\test_live_telemetry_pipeline.py
```

Full regression:

```powershell
python -m pytest tests
```

Manual fixture mode:

```powershell
python scripts\pipeline\run_live_telemetry_pipeline.py --input fixture
python scripts\pipeline\run_live_telemetry_pipeline.py --input fixture --fixture-detectable-powershell
```

Manual XML mode:

```powershell
python scripts\pipeline\run_live_telemetry_pipeline.py --input xml --xml-path <path>
```

Manual indexing:

```powershell
python scripts\pipeline\run_live_telemetry_pipeline.py --input fixture --write-events
python scripts\pipeline\run_live_telemetry_pipeline.py --input fixture --fixture-detectable-powershell --write-alerts
python scripts\pipeline\run_live_telemetry_pipeline.py --input xml --xml-path <path> --write-events --write-alerts
```

## Acceptance criteria

- [ ] Fixture input can normalize and output one normalized event without Elasticsearch.
- [ ] Fixture input without `--fixture-detectable-powershell` produces zero alerts because current process is `cmd.exe`.
- [ ] Fixture input with `--fixture-detectable-powershell` can produce one alert without Elasticsearch.
- [ ] XML input path works for an exported Sysmon Event ID 1 XML file.
- [ ] XML input uses `normalize_sysmon_event_1`.
- [ ] With `--write-events`, normalized event is indexed to `edr-normalized-events-YYYY.MM.DD`.
- [ ] Event indexing uses deterministic event document ID: `event.id`, else `sysmon.event_data.ProcessGuid`, else stable hash.
- [ ] With `--write-alerts`, alert is indexed to `edr-alerts-native-YYYY.MM.DD`.
- [ ] Alerts are built with existing native alert builder.
- [ ] Detection uses existing native rule loader and evaluator.
- [ ] Output includes JSON or summary result.
- [ ] Output includes event indexing result when `--write-events` is set.
- [ ] Output includes alert indexing result when `--write-alerts` is set.
- [ ] Tests do not require live Elasticsearch.
- [ ] Runner is production-shaped, not smoke-only.
- [ ] Documentation exists at `docs/live_telemetry_pipeline_mvp.md`.

## Blocked by

- `.scratch/phase-2-detection-engine-mvp/issues/01-native-powershell-detection-rule.md`
- `.scratch/phase-2-detection-engine-mvp/issues/02-alert-document-for-powershell-rule.md`
- `.scratch/phase-2-detection-engine-mvp/issues/06-native-detection-pipeline-with-alert-indexing.md`

## Out-of-scope boundaries

- Do not add Kafka.
- Do not add ML.
- Do not add SOAR.
- Do not add TheHive.
- Do not import SigmaHQ.
- Do not create dashboards.
- Do not add new Sysmon Event IDs.
- Do not write events unless `--write-events` is explicitly set.
- Do not write alerts unless `--write-alerts` is explicitly set.
- Do not create another smoke-only script.
