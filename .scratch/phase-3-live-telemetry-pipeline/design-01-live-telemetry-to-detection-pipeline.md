Status: done

# Technical Design: Live Telemetry To Detection Pipeline

## Scope

This design covers the implementation issue:

`.scratch/phase-2-detection-engine-mvp/issues/07-live-telemetry-to-detection-pipeline.md`

Goal: implement a production-shaped live telemetry pipeline MVP that connects Sysmon XML ingestion, normalization, optional normalized event indexing, native detection, alert building, and optional alert indexing.

This is not a smoke-only script. Fixture mode is a deterministic input mode of the real pipeline.

In scope:

- Input mode `fixture` using the existing Phase 1 Sysmon Event ID 1 XML fixture.
- Input mode `xml` using a Sysmon Event ID 1 XML file exported from Windows Event Viewer.
- Parse and normalize Sysmon Event ID 1 XML using `normalization/sysmon/process_create_normalizer.py`.
- Optionally index normalized events to `edr-normalized-events-YYYY.MM.DD` only when `--write-events` is set.
- Run native `T1059.001` PowerShell detection in memory against the normalized event.
- Build alert documents in memory.
- Optionally index alerts to `edr-alerts-native-YYYY.MM.DD` only when `--write-alerts` is set.
- Print JSON or summary output.

Out of scope:

- Kafka.
- ML.
- SOAR.
- TheHive.
- SigmaHQ import.
- Dashboards.
- New Sysmon Event IDs.
- Automatic Windows Event Log subscription.
- Long-running daemon/service mode.

## Architecture

New pipeline runner:

```text
scripts/pipeline/run_live_telemetry_pipeline.py
```

New event indexer:

```text
collection/elasticsearch/event_indexer.py
```

Pipeline:

```text
input mode
  -> XML string
  -> normalize_sysmon_event_1(xml)
  -> optional fixture detectable PowerShell adaptation
  -> optional index normalized event
  -> load native T1059.001 PowerShell rule
  -> evaluate_rule(rule, normalized_event)
  -> build_alert_document(match, rule, normalized_event, source=event_index_source_if_written)
  -> optional index alert
  -> print JSON or summary
```

Important architectural boundary:

- Event indexing and alert indexing are opt-in.
- Detection runs in memory regardless of whether event indexing is enabled.
- Alert indexing is independent of event indexing. A user may run `--write-alerts` without `--write-events`, but alert `source` metadata will only include normalized event index identity when the event was indexed.
- This runner should not call the existing smoke command. It may reuse the same fixture file and existing normalizer.

## CLI Interface

Primary command:

```powershell
python scripts\pipeline\run_live_telemetry_pipeline.py --input fixture
```

XML file input:

```powershell
python scripts\pipeline\run_live_telemetry_pipeline.py --input xml --xml-path C:\path\to\sysmon_event_1.xml
```

Supported options:

- `--input fixture|xml`: required or default to `fixture`; recommend default `fixture` for local deterministic runs.
- `--xml-path <path>`: required when `--input xml`.
- `--write-events`: opt-in normalized event indexing.
- `--write-alerts`: opt-in alert indexing.
- `--elasticsearch-url`: default `http://localhost:9200`.
- `--event-index-prefix`: default `edr-normalized-events`.
- `--alert-index-prefix`: default `edr-alerts-native`.
- `--event-index-date YYYY-MM-DD`: optional deterministic event index date.
- `--alert-index-date YYYY-MM-DD`: optional deterministic alert index date.
- `--output json|summary`: default `json`.
- `--fixture-detectable-powershell`: adapt the normalized fixture current process fields to `powershell.exe` so deterministic fixture mode produces one alert.

Examples:

```powershell
python scripts\pipeline\run_live_telemetry_pipeline.py --input fixture
python scripts\pipeline\run_live_telemetry_pipeline.py --input fixture --fixture-detectable-powershell
python scripts\pipeline\run_live_telemetry_pipeline.py --input xml --xml-path .\event.xml
python scripts\pipeline\run_live_telemetry_pipeline.py --input fixture --write-events
python scripts\pipeline\run_live_telemetry_pipeline.py --input fixture --fixture-detectable-powershell --write-alerts
python scripts\pipeline\run_live_telemetry_pipeline.py --input xml --xml-path .\event.xml --write-events --write-alerts
```

## Data Flow

Fixture mode:

```text
collection/sysmon/fixtures/sysmon_event_1_process_create.xml
  -> read XML
  -> normalize_sysmon_event_1(xml)
  -> optional current-process PowerShell adaptation when --fixture-detectable-powershell
```

XML mode:

```text
--xml-path
  -> read XML file
  -> normalize_sysmon_event_1(xml)
```

Detection:

```text
load_rule()
  -> evaluate_rule(rule, normalized_event)
  -> if matched:
       build_alert_document(match, rule, normalized_event, source=event_source)
```

Indexing:

```text
if --write-events:
  index normalized event to edr-normalized-events-YYYY.MM.DD
  event_source = {"index": index, "document_id": document_id}

if --write-alerts:
  index alert to edr-alerts-native-YYYY.MM.DD using alert.alert.id
```

Output:

```text
{
  "mode": "fixture" | "xml",
  "normalized_event_count": 1,
  "event_indexed_count": 0 | 1,
  "alert_count": 0 | 1,
  "alert_indexed_count": 0 | 1,
  "normalized_events": [...],
  "event_index_results": [...],
  "alerts": [...],
  "alert_index_results": [...]
}
```

## Elasticsearch Event Index Contract

Index format:

```text
edr-normalized-events-YYYY.MM.DD
```

Example:

```text
edr-normalized-events-2026.06.17
```

Write endpoint:

```http
PUT /edr-normalized-events-YYYY.MM.DD/_doc/<event-document-id>
Content-Type: application/json
```

Document ID strategy:

1. Use `event.id` if present and non-empty.
2. Else use `sysmon.event_data.ProcessGuid` if present and non-empty.
3. Else build a stable SHA-256 hash from:
   - `event.dataset`
   - `event.code`
   - `event.created` or `@timestamp`
   - `host.name`
   - `process.entity_id`
   - `process.pid`
   - `process.executable`
   - `process.command_line`

Event indexer public API:

```python
@dataclass(frozen=True)
class EventIndexingConfig:
    base_url: str = "http://localhost:9200"
    timeout_seconds: int = 10
    index_prefix: str = "edr-normalized-events"


@dataclass(frozen=True)
class EventIndexResult:
    index: str
    document_id: str
    result: str
    status: int


class EventIndexingError(RuntimeError):
    pass


def build_event_index_name(index_date: date | str | None = None, prefix: str = "edr-normalized-events") -> str:
    ...


def build_event_document_id(event: dict[str, Any]) -> str:
    ...


def index_event(event: dict[str, Any], config: EventIndexingConfig, *, index_date: date | str | None = None) -> EventIndexResult:
    ...
```

Use standard library `urllib.request` only.

Success:

- Accept HTTP `200` and `201`.
- Parse response JSON and preserve `result`.

Errors:

- Missing/invalid event document.
- Invalid index date.
- Network/timeout.
- Non-2xx response.
- Malformed JSON response.
- Missing `result` in response JSON.

## Elasticsearch Alert Index Contract

Reuse existing:

```text
detection/rules/native/alert_indexer.py
```

Alert index format:

```text
edr-alerts-native-YYYY.MM.DD
```

Document ID:

```text
alert.alert.id
```

Alert indexing remains opt-in with `--write-alerts`.

## Error Handling

Recommended exit codes:

- `0`: pipeline ran successfully and produced one or more normalized events. Alerts may be zero if no rule matched.
- `1`: pipeline ran successfully but produced zero alerts when a detectable alert was expected by the selected fixture option. This can be used for `--fixture-detectable-powershell` no-alert regression.
- `2`: operational failure:
  - XML file missing/unreadable.
  - Sysmon XML malformed.
  - Unsupported Sysmon Event ID.
  - event indexing failure.
  - alert indexing failure.
  - Elasticsearch unavailable.
- `3`: unexpected detection or alert generation failure.

Alternative stricter rule:

- Return `1` whenever alert count is zero. This matches existing runner behavior, but may be awkward for XML mode because benign/non-PowerShell Event ID 1 XML can be valid input.

Recommendation:

- For this live telemetry pipeline, return `0` when normalization succeeds, even with zero alerts, unless the caller used `--fixture-detectable-powershell` and no alert was produced.
- Include `alert_count` and `message` in JSON for automation.

Predictable errors:

- `LiveTelemetryPipelineError` for CLI/input orchestration errors.
- Reuse `SysmonNormalizationError` and `UnsupportedSysmonEventError`.
- Reuse `EventIndexingError`.
- Reuse `AlertIndexingError`.

## Tests

Tests must not require live Elasticsearch.

`tests/test_event_indexer.py`:

- Builds event index name from `YYYY-MM-DD`.
- Builds event index name from `date` object.
- Uses `event.id` as document ID when present.
- Uses `sysmon.event_data.ProcessGuid` as fallback.
- Uses stable hash fallback when no explicit event ID exists.
- Stable hash is deterministic for same event.
- Uses `PUT`.
- Writes to `/edr-normalized-events-YYYY.MM.DD/_doc/<event-id>`.
- Sends event JSON body unchanged.
- Parses successful `created` and `updated` responses.
- Raises `EventIndexingError` for network/HTTP errors.
- Raises `EventIndexingError` for malformed JSON response.

`tests/test_live_telemetry_pipeline.py`:

- Fixture input normalizes and outputs one normalized event without Elasticsearch.
- Fixture input without `--fixture-detectable-powershell` produces zero alerts because current process is `cmd.exe`.
- Fixture input with `--fixture-detectable-powershell` produces one alert without Elasticsearch.
- XML input path works using a temp file containing the existing fixture XML.
- `--write-events` calls event indexer and includes event indexing result.
- `--write-alerts` calls alert indexer and includes alert indexing result.
- Without `--write-events`, event indexer is not called.
- Without `--write-alerts`, alert indexer is not called.
- JSON output is valid.
- Summary output works.
- Event indexing error maps to operational failure.
- Alert indexing error maps to operational failure.
- Malformed XML maps to operational failure.

Commands:

```powershell
python -m pytest tests\test_event_indexer.py
python -m pytest tests\test_live_telemetry_pipeline.py
python -m pytest tests
```

## Acceptance Criteria

- [ ] Runner exists at `scripts/pipeline/run_live_telemetry_pipeline.py`.
- [ ] Runner is production-shaped, not smoke-only.
- [ ] Fixture mode reads the existing Phase 1 Sysmon Event ID 1 XML fixture.
- [ ] XML mode reads a Sysmon Event ID 1 XML file from `--xml-path`.
- [ ] Pipeline normalizes XML using `normalize_sysmon_event_1`.
- [ ] Pipeline can output one normalized event without Elasticsearch.
- [ ] `--fixture-detectable-powershell` produces one alert without Elasticsearch.
- [ ] Native detection uses existing loader/evaluator/alert builder.
- [ ] `--write-events` indexes normalized event to `edr-normalized-events-YYYY.MM.DD`.
- [ ] Event document ID uses `event.id`, else `sysmon.event_data.ProcessGuid`, else stable hash.
- [ ] `--write-alerts` indexes alerts to `edr-alerts-native-YYYY.MM.DD`.
- [ ] Alert indexing uses existing alert indexer.
- [ ] JSON and summary output are supported.
- [ ] Tests do not require live Elasticsearch.
- [ ] Docs explain fixture mode, XML mode, event indexing, alert indexing, and verification queries.

## Files To Create/Edit

Create:

- `collection/elasticsearch/event_indexer.py`
- `scripts/pipeline/run_live_telemetry_pipeline.py`
- `tests/test_event_indexer.py`
- `tests/test_live_telemetry_pipeline.py`
- `docs/live_telemetry_pipeline_mvp.md`

Do not edit unless necessary:

- `normalization/sysmon/process_create_normalizer.py`
- `detection/rules/native/loader.py`
- `detection/rules/native/evaluator.py`
- `detection/rules/native/alerts.py`
- `detection/rules/native/alert_indexer.py`
- Existing smoke scripts.

Do not add:

- Kafka.
- ML.
- SOAR.
- TheHive.
- SigmaHQ.
- Dashboards.
