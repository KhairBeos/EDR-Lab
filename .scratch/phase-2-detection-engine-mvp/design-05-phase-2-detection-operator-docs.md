Status: done

# Technical Design: Phase 2 Detection Operator Docs

## Scope

Design này chỉ bao phủ issue:

`.scratch/phase-2-detection-engine-mvp/issues/05-phase-2-detection-operator-docs.md`

Mục tiêu là document operator workflow cho Phase 2 Detection Engine MVP, để một junior engineer có thể chạy fixture/offline detection path, optional Elasticsearch detection path, đọc output, hiểu exit codes, và troubleshoot lỗi thường gặp.

In scope:

- Native PowerShell detection rule.
- Alert document builder.
- Elasticsearch candidate query.
- Fixture/offline detection smoke command.
- Optional Elasticsearch detection smoke command.
- Expected outputs.
- Exit codes.
- Troubleshooting.
- Acceptance criteria.

Out of scope:

- Code changes.
- Detection logic changes.
- Writing alerts to Elasticsearch.
- TheHive.
- SOAR.
- ML.
- Kafka.
- SigmaHQ import.
- Production deployment docs.
- Full ATT&CK coverage claims.

## Proposed Docs Files

Primary new runbook:

```text
docs/phase_2_detection_engine_mvp.md
```

Optional small cross-links:

```text
docs/architecture.md
docs/end_to_end_smoke_path.md
```

Recommendation:

- Create the runbook in `docs/phase_2_detection_engine_mvp.md`.
- Add one short link in `docs/architecture.md` under Phase 1/Phase 2 notes if useful.
- Avoid changing Phase 1 smoke docs unless a single "Next step: Phase 2 detection smoke" link helps navigation.

## Runbook Structure

Recommended outline:

```markdown
# Phase 2 Detection Engine MVP Runbook

## Purpose
## What This MVP Proves
## Scope Boundaries
## Components
## Fixture/Offline Detection Workflow
## Optional Elasticsearch Detection Workflow
## Expected Outputs
## Exit Codes
## Troubleshooting
## Acceptance Checklist
## Commands Reference
```

## Purpose Section

Explain:

- Phase 2 MVP is the first detection-layer vertical slice.
- It detects `T1059.001` PowerShell execution from normalized Sysmon Event ID 1 ECS documents.
- It proves normalized event -> native rule evaluator -> alert document.
- It does not persist alerts yet.

Suggested wording:

```markdown
This runbook validates the first Phase 2 detection path: native PowerShell detection for MITRE ATT&CK `T1059.001` using normalized Sysmon Event ID 1 ECS documents.
```

## What This MVP Proves

Document the end-to-end logical path:

```text
Sysmon Event ID 1 fixture
  -> ECS normalized payload
  -> native T1059.001 PowerShell rule
  -> native evaluator
  -> alert document builder
  -> JSON/summary output
```

Also document optional live path:

```text
Elasticsearch edr-raw-events-*
  -> normalized Sysmon Event ID 1 candidate query
  -> native evaluator
  -> alert document builder
  -> JSON/summary output
```

## Scope Boundaries Section

Must explicitly state:

- Only `T1059.001` PowerShell execution.
- Only normalized Sysmon Event ID 1 ECS documents.
- Only current process fields for rule matching:
  - `process.name`
  - `process.executable`
  - `process.command_line`
- Parent-only PowerShell does not match this rule.
- Fixture/offline mode mutates a copied normalized fixture into a current PowerShell process event for deterministic detection validation.

Out of scope list:

- No ML.
- No Kafka.
- No TheHive.
- No SOAR.
- No SigmaHQ import.
- No full ATT&CK coverage.
- No new Sysmon Event IDs.
- No alert writes to Elasticsearch.
- No Kibana dashboards.
- No Windows VM requirement for MVP acceptance.

## Components Section

Document the relevant implementation components at high level:

- Native rule file:
  - `detection/rules/native/t1059_001_powershell_process_start.yml`
- Rule loader/evaluator:
  - `detection/rules/native/loader.py`
  - `detection/rules/native/evaluator.py`
- Alert builder:
  - `detection/rules/native/alerts.py`
- Elasticsearch query client:
  - `detection/rules/native/elasticsearch.py`
- Smoke command:
  - `scripts/smoke/phase_2_detection_smoke.py`
- Existing Phase 1 fixture path:
  - `collection/sysmon/fixtures/sysmon_event_1_process_create.xml`
- Existing Phase 1 smoke payload builder:
  - `scripts/smoke/end_to_end_art_telemetry_smoke.py`

Keep descriptions concise; no code snippets unless showing commands/output.

## Fixture / Offline Detection Workflow

This is the primary acceptance workflow.

Commands:

```powershell
python scripts\smoke\phase_2_detection_smoke.py
```

Expected behavior:

- Does not require Docker.
- Does not require Elasticsearch.
- Does not require Logstash/Kibana/Kafka.
- Does not require Windows VM.
- Reuses the existing Sysmon Event ID 1 fixture path.
- Builds normalized payload.
- Copies payload and adapts current process fields to `powershell.exe`.
- Loads native T1059.001 rule.
- Evaluates event.
- Builds alert in memory.
- Prints JSON by default.
- Exits `0` when alert is produced.

Summary mode:

```powershell
python scripts\smoke\phase_2_detection_smoke.py --output summary
```

No-alert check:

```powershell
python scripts\smoke\phase_2_detection_smoke.py --fixture-no-match
```

Expected no-alert behavior:

- Prints JSON with `alert_count = 0`.
- Exits `1`.
- Does not indicate crash; it means no matching current PowerShell process event.

## Optional Elasticsearch Detection Workflow

Document this as optional live validation, not the primary acceptance path.

Commands:

```powershell
docker compose up -d
python scripts\smoke\end_to_end_art_telemetry_smoke.py --post-logstash
python scripts\smoke\phase_2_detection_smoke.py --from-elasticsearch
```

Custom connection:

```powershell
python scripts\smoke\phase_2_detection_smoke.py `
  --from-elasticsearch `
  --elasticsearch-url http://localhost:9200 `
  --index-pattern edr-raw-events-* `
  --size 100 `
  --timeout-seconds 10
```

Important caveat:

- Current Phase 1 smoke fixture has `cmd.exe` as current process and PowerShell as parent process.
- Issue 01 rule does not match parent-only PowerShell.
- The Issue 03 Elasticsearch query searches current process fields only.
- Therefore ES mode may return zero alerts unless the local Elasticsearch index contains a current `powershell.exe` normalized Sysmon Event ID 1 document.

This caveat prevents false expectations.

## Expected Outputs

JSON success shape:

```json
{
  "mode": "fixture",
  "rule_id": "det.t1059_001.powershell_process_start",
  "candidate_count": 1,
  "alert_count": 1,
  "alerts": [
    {
      "alert": {
        "id": "det-t1059-001-powershell-process-start-...",
        "kind": "signal",
        "status": "open",
        "created": "2026-06-16T15:35:14Z",
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

Mention high-level alert fields:

- `alert.*`: ID, kind, status, created time, severity, confidence.
- `rule.*`: native rule metadata.
- `attack.*`: ATT&CK technique/tactic metadata.
- `event.*`: normalized Sysmon event metadata.
- `host`, `user`, `process`, `process.parent`: investigation context.
- `art.*`: Atomic Red Team metadata if present.
- `source.*`: Elasticsearch `_index` / `_id` when running ES mode.

No-alert shape:

```json
{
  "mode": "fixture",
  "rule_id": "det.t1059_001.powershell_process_start",
  "candidate_count": 1,
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
- det-t1059-001-powershell-process-start-... medium high WIN11-EDR-LAB powershell.exe
```

## Exit Codes

Document exactly:

| Exit code | Meaning |
| --- | --- |
| `0` | Command ran successfully and produced one or more alerts. |
| `1` | Command ran successfully but produced zero alerts. |
| `2` | Operational failure, such as Elasticsearch unavailable or malformed Elasticsearch response. |
| `3` | Unexpected detection or alert generation error. |

Clarify:

- Exit `1` is a no-alert condition, not a Python crash.
- Exit `2` usually means ES mode cannot reach/query Elasticsearch.
- Fixture mode should normally exit `0`.

## Troubleshooting Section

Troubleshooting matrix:

| Symptom | Likely cause | Check / fix |
| --- | --- | --- |
| Fixture mode returns `alert_count = 0` | Running `--fixture-no-match`, or fixture adaptation failed | Run without `--fixture-no-match`; run tests. |
| ES mode exits `2` | Elasticsearch unavailable | Run `docker compose up -d`; check `docker compose ps`. |
| ES mode returns zero alerts | No current PowerShell process event in ES | Use fixture mode for deterministic acceptance; ingest a current `powershell.exe` normalized event for ES validation. |
| ES mode sees raw events but no alerts | Raw payload has `event.dataset = edr.raw` | Confirm normalized event has `event.dataset = windows.sysmon_operational` and `event.code = 1`. |
| Parent PowerShell does not alert | Rule intentionally matches current process fields only | This is expected for Issue 01 semantics. |
| JSON output is hard to read in terminal | Need compact human view | Run `--output summary`. |
| Tests fail around alert IDs | Alert ID uses stable event material | Check process fields/source metadata changed. |

Useful verification commands:

```powershell
python -m pytest tests
python scripts\smoke\phase_2_detection_smoke.py
python scripts\smoke\phase_2_detection_smoke.py --output summary
python scripts\smoke\phase_2_detection_smoke.py --fixture-no-match
```

Optional ES check:

```powershell
curl.exe -s "http://localhost:9200/edr-raw-events-*/_search?q=event.dataset:windows.sysmon_operational&size=5&pretty"
```

## Acceptance Criteria

The docs issue should be complete when:

- [ ] Runbook explains fixture/offline workflow.
- [ ] Runbook explains optional Elasticsearch workflow.
- [ ] Runbook lists expected alert fields at a high level.
- [ ] Runbook describes how existing normalized Sysmon Event ID 1 fixture is used.
- [ ] Runbook states first rule covers `T1059.001` PowerShell execution only.
- [ ] Runbook states parent-only PowerShell does not match this issue.
- [ ] Runbook documents JSON and summary output.
- [ ] Runbook documents exit codes.
- [ ] Runbook documents troubleshooting for no-alert results.
- [ ] Runbook documents troubleshooting for unavailable Elasticsearch.
- [ ] Runbook explicitly lists out-of-scope items.
- [ ] Existing docs link to the runbook where useful.

## Files To Create Or Edit

Recommended:

- `docs/phase_2_detection_engine_mvp.md`

Optional small cross-link:

- `docs/architecture.md`
- `docs/end_to_end_smoke_path.md`

Do not edit:

- Detection rule/evaluator code.
- Alert builder code.
- Elasticsearch query code.
- Smoke command code.
- Response/SOAR modules.
- ML modules.
- Kafka config.

## Implementation Notes For Later

- Keep docs command examples Windows PowerShell-friendly.
- Do not over-document internals; operator needs commands, expected output, and troubleshooting.
- Avoid claiming production detection quality. This is MVP wiring validation.
- Be explicit that alert documents are printed, not persisted.
- Keep scope boundaries visible near the top so future agents do not accidentally expand Phase 2.
