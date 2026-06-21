Status: done

# Lab-only kill-process protection action

## Goal

Implement a guarded lab-only protection action MVP for the EDR demo: kill a detected malicious/suspicious process by PID only when explicitly requested, record the protection action, and show it in demo/dashboard artifacts.

This is the first real response/protection execution path. It must be safe-by-default.

## Context

Current project capabilities:

- Native and Sigma-like PowerShell detections.
- ML anomaly detection.
- SOAR dry-run response planning.
- Phase 9 demo case matrix with TP/TN/FP/FN.
- Elasticsearch indexes:
  - `edr-normalized-events-*`
  - `edr-alerts-native-*`
  - `edr-response-actions-*`
- Protection is currently not executed. SOAR actions are planned only.
- There is a placeholder `response/containment/process_kill.py`, but no implemented protected execution path yet.

## Problem

The live teacher demo needs to show EDR protection behavior:

```text
attack process starts
  -> Sysmon Event ID 1
  -> detection alert
  -> response planning
  -> guarded lab-only protection action
  -> process terminated
  -> protection action record
  -> dashboard/report evidence
```

The implementation must show the full response/protection loop without making the repo dangerous by default.

## Safety requirements

- Default must be dry-run.
- Real kill requires explicit `--execute-protection`.
- Real kill must require `--lab-allow-execute`.
- Real kill must require a process PID from alert/process context or explicit `--pid`.
- Do not kill system-critical processes.
- Do not kill without matching approved rule ID or demo marker unless `--force-lab-demo` is set.
- Do not run in CI.
- Do not require Windows for tests.
- Tests must monkeypatch process killing and must never kill real processes.

## What to build

Create:

- `response/protection/policy.py`
- `response/protection/actions.py`
- `response/protection/records.py`
- `response/protection/protection_indexer.py`
- `scripts/response/run_protection_action.py`
- `tests/test_protection_action.py`
- `docs/protection_action_mvp.md`

Optional:

- `reports/protection/README.md`

Create package `__init__.py` files where needed.

Reuse existing style from:

- `response/soar/engine.py`
- `response/soar/response_indexer.py`
- `scripts/response/run_soar_response.py`
- `detection/rules/native/alert_indexer.py`
- `collection/elasticsearch/event_indexer.py`

Do not modify detection rule semantics to make protection pass.

## Protection policy

Create `response/protection/policy.py`.

Implement:

- `ProtectionPolicyError`
- `ProtectionDecision` dataclass or JSON-compatible dict
- `evaluate_kill_process_policy(alert_or_response, execute=False, lab_allow_execute=False, force_lab_demo=False, explicit_pid=None)`

Policy should allow dry-run by default:

- Dry-run does not kill.
- Dry-run should still evaluate safety metadata and produce a decision.
- Dry-run should be allowed for matching demo alerts even when execution flags are absent.

Policy should allow execution only when:

- `execute = True`
- `lab_allow_execute = True`
- Action is `kill_process`
- `process.pid` exists in alert/process context or explicit PID is provided by CLI.
- `rule.id` is one of:
  - `det.t1059_001.powershell_process_start`
  - `sigma_like.t1059_001.powershell_process_start`
  - `ml.process_anomaly`
- `process.name` is not a protected system process.
- Host/user context exists when available.

Execution should be blocked unless one of these is true:

- Rule ID is approved.
- A safe demo marker is present in the alert/process command line.
- `force_lab_demo = True`.

Approved safe demo marker examples:

- `EDR_DEMO_T1059_001`
- `EDR_SAFE_MANUAL_T1059_001`
- `phase_8_demo`
- `phase_9_demo`

Protected process names:

- `System`
- `Registry`
- `smss.exe`
- `csrss.exe`
- `wininit.exe`
- `services.exe`
- `lsass.exe`
- `svchost.exe`
- `winlogon.exe`
- `explorer.exe`

Return decision:

```json
{
  "allowed": true,
  "mode": "dry-run",
  "reason": "dry-run planned for approved detection alert",
  "pid": 1234,
  "process_name": "powershell.exe",
  "rule_id": "det.t1059_001.powershell_process_start",
  "safety_checks": [
    "dry_run_default",
    "approved_rule_id",
    "pid_present",
    "process_not_protected"
  ]
}
```

Validation details:

- Invalid PID values should produce a blocked decision or clear `ProtectionPolicyError`.
- Missing PID in execute mode should block.
- Missing PID in dry-run may still produce a planned record if alert context is otherwise valid, but the reason should mention PID missing.
- Protected process names must compare case-insensitively.
- `force_lab_demo` should be recorded as a safety check and must not bypass protected-process checks.

## Protection actions

Create `response/protection/actions.py`.

Implement:

- `ProtectionActionError`
- `kill_process(pid, dry_run=True)`

Behavior:

- `dry_run=True` returns a planned result without killing.
- `dry_run=False` kills process by PID.
- Use standard library only.
- On Windows, use `taskkill /PID <pid> /T /F`.
- On non-Windows, use `os.kill(pid, signal.SIGTERM)` for tests/dev only, but tests must monkeypatch this.
- Never use `shell=True`.
- Raise clear errors for invalid PID, command failure, missing process.

Suggested result shape:

```json
{
  "action": "kill_process",
  "pid": 1234,
  "dry_run": true,
  "status": "planned",
  "message": "dry-run only; process was not killed"
}
```

For execute mode:

```json
{
  "action": "kill_process",
  "pid": 1234,
  "dry_run": false,
  "status": "executed",
  "message": "process termination requested"
}
```

## Protection records

Create `response/protection/records.py`.

Implement:

- `build_protection_record(alert_or_response, decision, action_result, created_at=None)`

Record shape:

```json
{
  "protection": {
    "id": "protection-kill-process-...",
    "action": "kill_process",
    "mode": "dry-run",
    "status": "planned",
    "created": "2026-06-17T10:00:00Z",
    "reason": "dry-run planned for approved detection alert"
  },
  "target": {
    "pid": 1234,
    "process_name": "powershell.exe",
    "host": "WIN11-EDR-LAB"
  },
  "alert": {
    "id": "det-t1059-001-powershell-process-start-...",
    "rule_id": "det.t1059_001.powershell_process_start",
    "technique_id": "T1059.001"
  },
  "safety": {
    "checks": []
  },
  "result": {}
}
```

Status mapping:

- Decision blocked => `blocked`
- Action dry-run planned => `planned`
- Action executed => `executed`
- Action failed => `failed`

Deterministic ID requirements:

- Include alert ID, action, PID, mode, and decision reason.
- Do not depend on wall-clock time.
- Same alert + decision + action result should produce the same ID even when `created_at` changes.

## Protection indexer

Create `response/protection/protection_indexer.py`.

Index protection records to:

```text
edr-protection-actions-YYYY.MM.DD
```

Document ID:

- `protection.id`

Implementation requirements:

- Follow the existing indexer style in `response/soar/response_indexer.py`.
- Use `urllib.request` or an existing indexing style.
- Accept HTTP `200` and `201`.
- Raise clear `ProtectionIndexingError` for connection, HTTP, malformed JSON, and missing result failures.
- Tests must monkeypatch network calls.

Suggested dataclasses:

- `ProtectionIndexingConfig`
- `ProtectionIndexResult`

## CLI

Create `scripts/response/run_protection_action.py`.

Commands:

```powershell
python scripts\response\run_protection_action.py --input fixture-alert --action kill-process
```

```powershell
python scripts\response\run_protection_action.py --input alert-json --alert-path .\alert.json --action kill-process
```

```powershell
python scripts\response\run_protection_action.py --input alert-json --alert-path .\alert.json --action kill-process --execute-protection --lab-allow-execute
```

```powershell
python scripts\response\run_protection_action.py --input alert-json --alert-path .\alert.json --action kill-process --write-protection --elasticsearch-url http://localhost:9200
```

Options:

- `--input fixture-alert|alert-json`
- `--alert-path`, required for `alert-json`
- `--action kill-process`
- `--pid`, optional override
- `--execute-protection`
- `--lab-allow-execute`
- `--force-lab-demo`
- `--write-protection`
- `--elasticsearch-url`, default `http://localhost:9200`
- `--protection-index-prefix`, default `edr-protection-actions`
- `--output json|summary`, default `json`

Behavior:

- `fixture-alert` produces a PowerShell alert and dry-run protection record.
- `alert-json` reads one alert from file.
- Default mode is dry-run.
- Execute mode requires both `--execute-protection` and `--lab-allow-execute`.
- Blocked policy still creates a protection record with `status = blocked`.
- `--write-protection` indexes the protection record.
- Output includes `decision`, `action_result`, `protection_record`, and `index_result`.
- If policy is blocked, do not call `kill_process()`.
- If action execution fails, create a failed protection record when possible and return operational failure.

Exit codes:

- `0` for dry-run planned or execute success.
- `1` for policy blocked.
- `2` for operational failure.
- `3` for unexpected failure.

Suggested main function shape:

```python
def run_protection_action(
    *,
    input_mode: str,
    alert_path: Path | None = None,
    action: str = "kill-process",
    pid: int | None = None,
    execute_protection: bool = False,
    lab_allow_execute: bool = False,
    force_lab_demo: bool = False,
    write_protection: bool = False,
    elasticsearch_url: str = "http://localhost:9200",
    protection_index_prefix: str = "edr-protection-actions",
) -> dict[str, Any]:
    ...
```

## Demo and dashboard integration

Update Phase 9 dashboard docs/data if useful and low-risk:

- Add `edr-protection-actions-*`.
- Mention `protection.status`.
- Mention `protection.mode`.
- Mention `protection.action: kill_process`.
- Keep `protection_count` support in dashboard data.

Do not require this integration in existing tests unless it is small and deterministic.

## Docs

Create `docs/protection_action_mvp.md`.

Document:

- This is lab-only.
- Default dry-run.
- Real execution requires explicit flags.
- Never run on production endpoints.
- How to use a long-running safe demo process:

```powershell
powershell.exe -NoProfile -Command "Start-Sleep -Seconds 300"
```

- How to get PID:

```powershell
Get-Process powershell | Select-Object Id, ProcessName, Path
```

- How to run dry-run:

```powershell
python scripts\response\run_protection_action.py --input fixture-alert --action kill-process --output summary
```

- How to run execute in isolated lab:

```powershell
python scripts\response\run_protection_action.py --input alert-json --alert-path .\alert.json --action kill-process --pid <PID> --execute-protection --lab-allow-execute --output summary
```

- How to verify process terminated.
- How to index protection record.
- How to view in Kibana:
  - `edr-protection-actions-*`
  - `protection.action: kill_process`
  - `protection.status: executed`
  - `protection.mode: execute`

Also document safety trade-offs:

- Killing by PID is simple and demoable but risky if PID is stale or reused.
- Lab-only flags reduce accidental execution risk.
- Future production implementation should use endpoint identity, process entity ID, host isolation policy, approval workflow, and richer allow/deny lists.

## Optional report docs

Optionally create `reports/protection/README.md`.

Document:

- Expected protection record artifacts.
- How to regenerate demo evidence.
- Why execute mode is lab-only.

## Tests

Create `tests/test_protection_action.py`.

Tests must not kill real processes.

Cover:

- Default dry-run allowed for matching PowerShell alert.
- Execute blocked without `lab_allow_execute`.
- Execute blocked for protected system process.
- Execute allowed only with `execute + lab_allow_execute`.
- Unsupported rule blocked.
- Force lab demo can bypass unsupported rule but cannot bypass protected process.
- `kill_process(dry_run=True)` does not call OS kill.
- `kill_process(dry_run=False)` uses monkeypatched OS call.
- Windows taskkill path can be monkeypatched without running taskkill.
- Invalid PID raises clear action/policy error.
- Protection record deterministic ID.
- Blocked decision creates blocked protection record.
- Failed action creates failed protection record when possible.
- CLI `fixture-alert` dry-run works.
- CLI `alert-json` dry-run works.
- CLI returns `1` for policy blocked.
- `--write-protection` calls monkeypatched indexer.
- Protection indexer builds `edr-protection-actions-YYYY.MM.DD`.
- Protection indexer uses `protection.id` as document ID.
- Tests do not require Windows.
- Tests do not require Elasticsearch.

Monkeypatch requirements:

- Monkeypatch `subprocess.run` for Windows taskkill execution tests.
- Monkeypatch `os.kill` for non-Windows execution tests.
- Monkeypatch protection indexer network calls or `index_protection_records()`.
- Never call a real OS kill in tests.

## Commands to run

Focused tests:

```powershell
python -m pytest tests\test_protection_action.py
```

Full regression:

```powershell
python -m pytest tests
```

Manual dry-run:

```powershell
python scripts\response\run_protection_action.py --input fixture-alert --action kill-process --output summary
```

Manual alert JSON dry-run:

```powershell
python scripts\response\run_protection_action.py --input alert-json --alert-path .\alert.json --action kill-process --output summary
```

Manual isolated lab execute:

```powershell
python scripts\response\run_protection_action.py --input alert-json --alert-path .\alert.json --action kill-process --pid <PID> --execute-protection --lab-allow-execute --output summary
```

Manual indexing:

```powershell
python scripts\response\run_protection_action.py --input alert-json --alert-path .\alert.json --action kill-process --write-protection --elasticsearch-url http://localhost:9200
```

## Acceptance criteria

- [ ] `response/protection/policy.py` implements guarded kill-process policy evaluation.
- [ ] Default protection mode is dry-run.
- [ ] Real execution requires both `--execute-protection` and `--lab-allow-execute`.
- [ ] Execution requires PID from alert/process context or explicit `--pid`.
- [ ] Protected system process names are blocked case-insensitively.
- [ ] Approved rule IDs include native PowerShell, Sigma-like PowerShell, and ML anomaly rules.
- [ ] Unsupported rule IDs are blocked unless `--force-lab-demo` is set.
- [ ] `--force-lab-demo` does not bypass protected-process checks.
- [ ] `response/protection/actions.py` implements dry-run and execute kill-process behavior using standard library only.
- [ ] `kill_process(dry_run=True)` never kills a process.
- [ ] `kill_process(dry_run=False)` uses `taskkill` on Windows and `os.kill(..., SIGTERM)` on non-Windows.
- [ ] `shell=True` is never used.
- [ ] `response/protection/records.py` builds deterministic protection records.
- [ ] Blocked policy creates a protection record with `status = blocked`.
- [ ] Failed action creates a protection record with `status = failed` when possible.
- [ ] `response/protection/protection_indexer.py` indexes to `edr-protection-actions-YYYY.MM.DD`.
- [ ] Protection indexer uses `protection.id` as the document ID.
- [ ] `scripts/response/run_protection_action.py` supports fixture alert and alert JSON input.
- [ ] CLI dry-run returns exit code `0`.
- [ ] CLI policy block returns exit code `1`.
- [ ] CLI operational failures return exit code `2`.
- [ ] CLI output includes decision, action result, protection record, and index result.
- [ ] `docs/protection_action_mvp.md` documents lab-only usage and safety flags.
- [ ] Tests monkeypatch process killing and never kill real processes.
- [ ] Tests do not require Windows or Elasticsearch.
- [ ] Existing detection, SOAR dry-run, Phase 9 case matrix, and dashboard behavior remain unchanged unless explicitly cross-linked.

## Blocked by

- `.scratch/phase-9-demo-case-dashboard-mvp/issues/01-multi-attack-case-dashboard-validation.md`
- `.scratch/phase-8-vm-art-attack-demo-validation/issues/01-atomic-red-team-sysmon-dashboard-demo.md`
- `.scratch/phase-5-soar-response-mvp/issues/01-soar-dry-run-response-pipeline.md`
- `.scratch/phase-2-detection-engine-mvp/issues/06-native-detection-pipeline-with-alert-indexing.md`

## Out-of-scope boundaries

- Do not add real containment beyond kill-process.
- Do not execute protection by default.
- Do not kill real processes in tests.
- Do not require Windows in tests.
- Do not require Elasticsearch in tests.
- Do not change detection semantics.
- Do not change SOAR dry-run semantics.
- Do not hide FP/FN cases.
- Do not add host isolation.
- Do not add network blocking.
- Do not add production policy enforcement.

## Comments
