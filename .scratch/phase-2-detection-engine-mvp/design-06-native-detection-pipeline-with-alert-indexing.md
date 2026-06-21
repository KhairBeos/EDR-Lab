Status: done

# Technical Design: Native Detection Pipeline With Alert Indexing

## Scope

This design covers the implementation issue:

`.scratch/phase-2-detection-engine-mvp/issues/06-native-detection-pipeline-with-alert-indexing.md`

Goal: turn the current Phase 2 native PowerShell detection components into a real local detection pipeline, not another smoke-only path.

In scope:

- Fixture mode as an input mode for deterministic tests.
- Elasticsearch mode as an input mode for real normalized Sysmon Event ID 1 events.
- Native `T1059.001` PowerShell rule loading.
- Native evaluator execution.
- Alert document building.
- Optional alert indexing to Elasticsearch only when `--write-alerts` is explicitly set.
- JSON and summary output.
- Alert index name `edr-alerts-native-YYYY.MM.DD`.
- Elasticsearch document ID set to `alert.alert.id`.

Out of scope:

- Kafka.
- ML.
- SOAR.
- TheHive.
- SigmaHQ import.
- Dashboards.
- Full ATT&CK coverage.
- New Sysmon Event IDs.
- Alert writes unless `--write-alerts` is provided.

## Architecture

The production-shaped local runner should live outside `scripts/smoke/`:

```text
scripts/detection/run_native_detection.py
```

The pipeline reuses existing Phase 2 modules:

```text
input mode
  -> candidate events
  -> load_rule()
  -> evaluate_rule(rule, candidate.event)
  -> build_alert_document(match, rule, candidate.event, source=candidate.source)
  -> optional index_alert(alert)
  -> print JSON or summary
```

New component:

```text
detection/rules/native/alert_indexer.py
```

Responsibilities:

- Build daily native alert index name.
- Write alert documents to Elasticsearch using standard library `urllib.request`.
- Use `alert.alert.id` as Elasticsearch document ID.
- Raise predictable errors for network, non-2xx, malformed alert, and invalid JSON response.

Runner responsibilities:

- CLI parsing.
- Select input mode: fixture or Elasticsearch.
- Orchestrate rule/evaluator/alert builder/indexer.
- Print output.
- Map errors to exit codes.

The existing `scripts/smoke/phase_2_detection_smoke.py` remains a smoke script and should not be extended into the real runner. This issue creates a separate production-shaped detection runner.

## CLI Interface

Primary runner:

```powershell
python scripts\detection\run_native_detection.py
```

Default behavior:

- Input mode: fixture.
- Output: JSON.
- Alert writing: disabled.

Recommended CLI options:

```powershell
python scripts\detection\run_native_detection.py `
  --input fixture `
  --output json
```

Elasticsearch input:

```powershell
python scripts\detection\run_native_detection.py `
  --input elasticsearch `
  --elasticsearch-url http://localhost:9200 `
  --index-pattern edr-raw-events-* `
  --size 100 `
  --timeout-seconds 10
```

Write alerts:

```powershell
python scripts\detection\run_native_detection.py `
  --input elasticsearch `
  --write-alerts
```

Explicit alert index date for deterministic tests/manual replay:

```powershell
python scripts\detection\run_native_detection.py `
  --input fixture `
  --write-alerts `
  --alert-index-date 2026-06-17
```

Arguments:

- `--input`: `fixture` or `elasticsearch`; default `fixture`.
- `--output`: `json` or `summary`; default `json`.
- `--elasticsearch-url`: default `http://localhost:9200`.
- `--index-pattern`: default `edr-raw-events-*`.
- `--size`: default `100`.
- `--timeout-seconds`: default `10`.
- `--write-alerts`: opt-in alert indexing.
- `--alert-index-date`: optional `YYYY-MM-DD`; default current UTC date.
- `--fixture-no-match`: test/debug no-alert fixture mode, same semantics as current smoke command.

Avoid:

- No Kafka options.
- No SOAR/TheHive options.
- No dashboard options.
- No SigmaHQ options.

## Data Flow

Fixture input mode:

```text
load_fixture()
  -> build_smoke_payloads(xml)
  -> normalized payload
  -> copy normalized payload
  -> adapt current process fields to powershell.exe unless --fixture-no-match
  -> SearchCandidate(event=adapted_event, source={})
```

Elasticsearch input mode:

```text
ElasticsearchConfig(...)
  -> search_powershell_candidates(config)
  -> list[SearchCandidate]
```

Processing:

```text
load_rule()
  -> for each candidate:
       match = evaluate_rule(rule, candidate.event)
       if match.matched:
         alert = build_alert_document(
           match=match,
           rule=rule,
           event=candidate.event,
           source=candidate.source,
         )
```

Output:

```text
if --write-alerts:
  index each alert to edr-alerts-native-YYYY.MM.DD using alert.alert.id

print result as JSON or summary
exit according to result/error
```

Fixture mode is not a separate smoke feature. It is the deterministic input mode of the real detection runner.

## Elasticsearch Alert Index Contract

Index name:

```text
edr-alerts-native-YYYY.MM.DD
```

Example:

```text
edr-alerts-native-2026.06.17
```

Index date source:

- Default: current UTC date.
- Tests/manual replay: `--alert-index-date YYYY-MM-DD`.

Write endpoint:

```http
PUT /edr-alerts-native-YYYY.MM.DD/_doc/<alert.alert.id>
Content-Type: application/json
```

Document ID:

```text
alert["alert"]["id"]
```

Alert body:

- Use the alert document produced by `build_alert_document()`.
- Do not mutate alert before indexing.
- Do not add TheHive/SOAR/Kafka fields.

Indexer public API:

```python
@dataclass(frozen=True)
class AlertIndexingConfig:
    base_url: str = "http://localhost:9200"
    timeout_seconds: int = 10
    index_prefix: str = "edr-alerts-native"


@dataclass(frozen=True)
class AlertIndexResult:
    index: str
    document_id: str
    result: str
    status: int


class AlertIndexingError(RuntimeError):
    pass


def build_alert_index_name(index_date: date | str | None = None, prefix: str = "edr-alerts-native") -> str:
    ...


def index_alert(alert: dict[str, Any], config: AlertIndexingConfig, *, index_date: date | str | None = None) -> AlertIndexResult:
    ...
```

Response handling:

- Accept HTTP `200` and `201` as success.
- Parse JSON response if present.
- Preserve Elasticsearch `result` when returned, e.g. `created`, `updated`.
- Raise `AlertIndexingError` for missing `alert.alert.id`, network error, timeout, non-2xx, invalid JSON response shape if parsing is required.

## Error Handling

Runner exit codes:

- `0`: command ran successfully and produced one or more alerts.
- `1`: command ran successfully but produced zero alerts.
- `2`: operational failure, including Elasticsearch candidate query failure or alert indexing failure.
- `3`: unexpected detection or alert generation error.

Operational failures:

- Elasticsearch candidate query unavailable.
- Malformed Elasticsearch search response.
- Alert index write network failure.
- Alert index write non-2xx response.
- Missing `alert.alert.id` during indexing.

Unexpected failures:

- Rule/evaluator internal error.
- Alert builder error not caused by indexing.
- Invalid CLI values not caught by argparse.

Behavior:

- If `--write-alerts` is not provided, never call alert indexer.
- If `--write-alerts` is provided and one alert fails indexing, return exit code `2`.
- Print useful error messages to stderr.
- Keep successful result printable to stdout only.

## Tests

Tests must not require live Elasticsearch.

`tests/test_alert_indexer.py`:

- Builds alert index name with current-style date input.
- Builds alert index name from `YYYY-MM-DD`.
- Uses `alert.alert.id` as document ID.
- Uses `PUT`.
- Writes to `/edr-alerts-native-YYYY.MM.DD/_doc/<alert-id>`.
- Sends JSON body unchanged.
- Parses successful `created` response.
- Raises `AlertIndexingError` when `alert.alert.id` is missing.
- Raises `AlertIndexingError` for network/HTTP errors.

Testing approach:

- Monkeypatch `urllib.request.urlopen`.
- Use fake response objects with `status`, `getcode()`, `read()`, and context manager methods.

`tests/test_run_native_detection.py`:

- Fixture input produces one alert.
- Fixture input preserves rule metadata.
- Fixture input preserves ATT&CK metadata.
- Fixture input preserves ART metadata.
- JSON output is valid.
- Summary output works.
- No-alert fixture returns alert count zero and exit code `1`.
- `main([])` returns `0`.
- Elasticsearch input can be monkeypatched with fake `SearchCandidate`.
- Elasticsearch candidate source metadata appears in alert.
- `--write-alerts` indexes alerts only when explicitly provided.
- Without `--write-alerts`, indexer is not called.
- Indexed result appears in command result, e.g. `indexed_count`, `indexed_alerts`.
- Elasticsearch candidate query errors map to exit code `2`.
- Alert indexing errors map to exit code `2`.
- Unexpected detection/alert errors map to exit code `3`.

Recommended commands:

```powershell
python -m pytest tests\test_alert_indexer.py
python -m pytest tests\test_run_native_detection.py
python -m pytest tests
```

Manual commands:

```powershell
python scripts\detection\run_native_detection.py
python scripts\detection\run_native_detection.py --output summary
python scripts\detection\run_native_detection.py --fixture-no-match
python scripts\detection\run_native_detection.py --input elasticsearch
python scripts\detection\run_native_detection.py --input elasticsearch --write-alerts
```

## Acceptance Criteria

- [ ] A real detection runner exists at `scripts/detection/run_native_detection.py`.
- [ ] Fixture mode is implemented as an input mode of the detection runner, not as a new smoke-only script.
- [ ] Elasticsearch mode reads normalized candidates using existing Issue 03 query client.
- [ ] Runner loads the existing native `T1059.001` PowerShell rule.
- [ ] Runner evaluates candidates using the existing native evaluator.
- [ ] Runner builds alert documents using the existing alert builder.
- [ ] Runner prints JSON by default.
- [ ] Runner supports summary output.
- [ ] Runner does not write alerts unless `--write-alerts` is set.
- [ ] When `--write-alerts` is set, alerts are written to `edr-alerts-native-YYYY.MM.DD`.
- [ ] Alert indexing uses `alert.alert.id` as Elasticsearch document ID.
- [ ] Indexer uses only standard library `urllib.request`.
- [ ] Source metadata from Elasticsearch candidates is preserved in alert documents.
- [ ] Tests do not require live Elasticsearch.
- [ ] Documentation explains the new runner and de-emphasizes smoke-only workflow.

## Files To Create/Edit

Create:

- `detection/rules/native/alert_indexer.py`
- `scripts/detection/run_native_detection.py`
- `tests/test_alert_indexer.py`
- `tests/test_run_native_detection.py`

Edit:

- `docs/phase_2_detection_engine_mvp.md`

Do not edit unless necessary:

- Native rule loader/evaluator.
- Alert builder.
- Elasticsearch candidate query client.
- Existing Phase 2 smoke command.
- Phase 1 smoke command.

Do not add:

- Kafka.
- ML.
- SOAR.
- TheHive.
- SigmaHQ.
- Dashboards.
