Status: done

# Technical Design: Phase 2 Detection Smoke Command

## Scope

Design này chỉ bao phủ issue:

`.scratch/phase-2-detection-engine-mvp/issues/04-detection-smoke-command.md`

Mục tiêu là tạo local smoke command nối các phần đã có:

- Native PowerShell detection rule từ Issue 01.
- Native evaluator từ Issue 01.
- Alert document builder từ Issue 02.
- Elasticsearch query client từ Issue 03.

In scope:

- Query existing normalized events from Elasticsearch.
- Evaluate candidates bằng native rule.
- Build alert documents in memory.
- Print alerts as JSON hoặc summary.
- Fixture/offline mode để chạy không cần Docker.

Out of scope:

- Write alerts to Elasticsearch.
- Create Kibana dashboards.
- TheHive.
- SOAR.
- ML.
- Kafka.
- Windows VM requirement.

## Command Interface

Proposed file:

`scripts/smoke/phase_2_detection_smoke.py`

Default mode should be fixture/offline mode:

```powershell
python scripts\smoke\phase_2_detection_smoke.py
```

Elasticsearch mode:

```powershell
python scripts\smoke\phase_2_detection_smoke.py --from-elasticsearch
```

Useful options:

```powershell
python scripts\smoke\phase_2_detection_smoke.py `
  --from-elasticsearch `
  --elasticsearch-url http://localhost:9200 `
  --index-pattern edr-raw-events-* `
  --size 100 `
  --timeout-seconds 10 `
  --output json
```

Recommended args:

- `--from-elasticsearch`: use Issue 03 ES query path instead of fixture-only mode.
- `--elasticsearch-url`: default `http://localhost:9200`.
- `--index-pattern`: default `edr-raw-events-*`.
- `--size`: default `100`.
- `--timeout-seconds`: default `10`.
- `--output`: `json` or `summary`; default `json`.
- `--include-non-matches`: optional debug mode, default false.

Avoid:

- No `--write-alerts`.
- No `--kibana`.
- No TheHive/SOAR args.
- No Kafka args.

## Data Flow

Fixture/offline flow:

```text
load_fixture()
  -> build_smoke_payloads(xml)
  -> normalized payload
  -> adapt current process to powershell.exe for Issue 01 semantics
  -> load native rule
  -> evaluate_rule(rule, event)
  -> build_alert_document(match, rule, event, source=None)
  -> print JSON
```

Elasticsearch flow:

```text
ElasticsearchConfig
  -> search_powershell_candidates(config)
  -> list[SearchCandidate]
  -> load native rule
  -> for each candidate:
       evaluate_rule(rule, candidate.event)
       if matched:
         build_alert_document(
           match=match,
           rule=rule,
           event=candidate.event,
           source=candidate.source,
         )
  -> print JSON
```

Important boundary:

- Query layer returns candidates only.
- Evaluator decides true match.
- Alert builder builds documents in memory only.
- Smoke command prints; it does not persist.

## Fixture / Offline Mode

Fixture mode should run without:

- Docker.
- Logstash.
- Elasticsearch.
- Kibana.
- Kafka.
- Windows VM.

Current Phase 1 fixture has `process.name = cmd.exe` and `process.parent.name = powershell.exe`. Issue 01 intentionally does **not** match parent-only PowerShell. Therefore fixture mode must create a detection-specific normalized event variant by copying the normalized payload and changing current process fields:

```python
event["process"]["name"] = "powershell.exe"
event["process"]["executable"] = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
event["process"]["command_line"] = "powershell.exe -NoLogo"
event["process"]["args"] = ["powershell.exe", "-NoLogo"]
```

Reason:

- Reuses existing normalization contract and ART metadata.
- Avoids adding a new Sysmon XML fixture in this issue.
- Keeps Issue 01 semantics clean: current PowerShell process creation only.

Trade-off:

- Mutated fixture is less realistic than a real PowerShell process XML event.
- It is acceptable for MVP smoke because normalization is already tested separately and this smoke command validates detection wiring.

Optional debug no-alert fixture:

```powershell
python scripts\smoke\phase_2_detection_smoke.py --fixture-no-match
```

This can keep the original `cmd.exe` payload to prove clear no-alert output. If implementation wants fewer args, no-alert behavior can be covered by unit tests only.

## Elasticsearch Mode

Elasticsearch mode should:

1. Build `ElasticsearchConfig` from CLI args.
2. Call `search_powershell_candidates(config)`.
3. Evaluate each `SearchCandidate.event` with native rule.
4. Pass `SearchCandidate.source` into alert builder so `_index` and `_id` appear in alert `source`.
5. Print alert JSON or no-alert summary.

Manual run:

```powershell
docker compose up -d
python scripts\smoke\end_to_end_art_telemetry_smoke.py --post-logstash
python scripts\smoke\phase_2_detection_smoke.py --from-elasticsearch
```

Caveat:

- Existing Phase 1 smoke payload may not contain current `process.name = powershell.exe`; it contains parent PowerShell. Since Issue 03 query only searches current process fields, live ES mode may return no alerts unless Elasticsearch contains a current PowerShell process event.
- This is correct for Issue 01 semantics.
- Docs should state fixture mode is the primary deterministic acceptance path, ES mode validates live query plumbing when matching data exists.

## Output Format

Default `--output json`:

```json
{
  "mode": "fixture",
  "rule_id": "det.t1059_001.powershell_process_start",
  "candidate_count": 1,
  "alert_count": 1,
  "alerts": [
    {
      "alert": {
        "id": "det-t1059-001-powershell-process-start-7b7c9d2a4f8e91bc",
        "kind": "signal",
        "status": "open",
        "created": "2026-06-16T15:30:00Z",
        "severity": "medium",
        "confidence": "high"
      },
      "rule": {
        "id": "det.t1059_001.powershell_process_start",
        "name": "PowerShell Process Execution",
        "version": 1
      },
      "attack": {
        "technique": {
          "id": "T1059.001",
          "name": "PowerShell"
        },
        "tactic": ["Execution"]
      }
    }
  ]
}
```

No-alert JSON:

```json
{
  "mode": "elasticsearch",
  "rule_id": "det.t1059_001.powershell_process_start",
  "candidate_count": 0,
  "alert_count": 0,
  "alerts": [],
  "message": "No matching PowerShell alerts produced."
}
```

Summary output:

```text
Phase 2 detection smoke
Mode: fixture
Rule: det.t1059_001.powershell_process_start
Candidates: 1
Alerts: 1
- det-t1059-001-powershell-process-start-7b7c9d2a4f8e91bc medium high WIN11-EDR-LAB powershell.exe
```

Recommendation:

- Implement JSON first because it is easiest to test.
- Summary can be simple and optional.

## Exit Codes

Recommended exit codes:

- `0`: command ran successfully and produced one or more alerts.
- `1`: command ran successfully but produced zero alerts.
- `2`: expected operational failure, e.g. Elasticsearch unavailable, malformed ES response, invalid CLI args.
- `3`: unexpected detection or alert generation error.

Rationale:

- No-alert is not a crash, but should be non-zero for smoke acceptance so automation can catch missing detection.
- Elasticsearch unavailable should be distinguishable from no-alert.

Behavior:

- Fixture mode should normally exit `0`.
- Fixture no-match/debug mode may exit `1`.
- Elasticsearch mode exits `0` if alerts exist, `1` if query succeeds but no alerts, `2` if ES query fails.

## Test Strategy

Core tests should not require Docker or live Elasticsearch.

Suggested implementation design for testability:

```python
def run_fixture_detection(*, created_at: str | None = None) -> dict:
    ...


def run_elasticsearch_detection(config: ElasticsearchConfig, *, created_at: str | None = None) -> dict:
    ...


def render_result(result: dict, output: str) -> str:
    ...


def main(argv: list[str] | None = None) -> int:
    ...
```

Primary tests:

1. Fixture mode builds one candidate and one alert.
2. Fixture mode alert includes rule metadata and ATT&CK metadata.
3. Fixture mode preserves ART metadata from existing smoke payload.
4. Fixture mode does not require Elasticsearch.
5. No-alert path returns result with `alert_count = 0` and message.
6. JSON output is valid JSON.
7. `main([])` returns `0` for fixture success.
8. Elasticsearch mode can be tested by monkeypatching `search_powershell_candidates()` to return fake `SearchCandidate` objects.
9. Elasticsearch mode passes candidate source metadata to alert builder.
10. Elasticsearch query error maps to exit code `2`.
11. Unexpected alert/evaluator error maps to exit code `3`.
12. Existing tests still pass.

Commands:

```powershell
python -m pytest tests\test_phase_2_detection_smoke.py
python -m pytest tests
```

Manual commands:

```powershell
python scripts\smoke\phase_2_detection_smoke.py
python scripts\smoke\phase_2_detection_smoke.py --output summary
docker compose up -d
python scripts\smoke\end_to_end_art_telemetry_smoke.py --post-logstash
python scripts\smoke\phase_2_detection_smoke.py --from-elasticsearch
```

## Files To Create Or Edit

Recommended implementation files:

- `scripts/smoke/phase_2_detection_smoke.py`
- `tests/test_phase_2_detection_smoke.py`

Allowed supporting edits if needed:

- `docs/end_to_end_smoke_path.md` should not be changed in this issue unless implementation wants a small cross-link. Prefer leaving docs to Issue 05.

Do not edit:

- `scripts/smoke/end_to_end_art_telemetry_smoke.py`
- Native evaluator semantics.
- Alert builder semantics.
- Elasticsearch query semantics, unless a bug blocks command integration.
- Response/SOAR modules.
- ML modules.
- Kafka config.

## Acceptance Criteria

- [ ] Running `python scripts\smoke\phase_2_detection_smoke.py` uses fixture/offline mode.
- [ ] Fixture/offline mode runs without Docker, Logstash, Elasticsearch, Kibana, Kafka, or Windows VM.
- [ ] Fixture/offline mode reuses existing Sysmon Event ID 1 smoke fixture path.
- [ ] Fixture/offline mode evaluates the `T1059.001` native PowerShell rule.
- [ ] Fixture/offline mode emits at least one alert document.
- [ ] No-alert result is clear and exits non-zero.
- [ ] `--from-elasticsearch` mode queries Elasticsearch using Issue 03 client.
- [ ] Elasticsearch candidates are evaluated with the same native evaluator.
- [ ] Alerts are built in memory with Issue 02 alert builder.
- [ ] Elasticsearch `_index` and `_id` appear in alert `source` when available.
- [ ] Command prints JSON output by default.
- [ ] Command does not write alerts anywhere.
- [ ] Tests cover fixture success, no-alert behavior, ES source propagation, and error exit mapping.

## Implementation Notes For Later

- Use fixed `created_at` only in tests; production smoke can use alert builder default current UTC.
- Keep functions importable so tests can call orchestration without subprocess.
- Keep CLI output to stdout and errors to stderr.
- Avoid network call in unit tests by monkeypatching ES search function.
- Avoid broad exception swallowing in helpers; map exceptions in `main()`.
