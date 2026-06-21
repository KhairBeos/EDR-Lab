# Protection Action MVP

Phase 10 adds the first guarded lab-only protection execution path: kill a process by PID after an EDR alert. It is safe-by-default.

Do not run execute mode on production endpoints.

This complements the Phase 9 10-case TP/TN/FP/FN matrix by adding explicit protection records for demo evidence. False positives and false negatives remain visible in the matrix; protection records should not be used to hide or rewrite those classifications.

## Safety Model

- Default mode is dry-run.
- Real execution requires both `--execute-protection` and `--lab-allow-execute`.
- Execution requires an alert process PID or explicit `--pid`.
- Protected system processes are blocked.
- Unsupported rule IDs are blocked unless `--force-lab-demo` is used.
- `--force-lab-demo` does not bypass protected-process checks.
- Tests monkeypatch process killing and never kill real processes.

Killing by PID is simple and demoable, but risky if the PID is stale or reused. A production version should use endpoint identity, process entity ID, host policy, approval workflow, and richer allow/deny lists.

## Safe Demo Process

Start a long-running process in an isolated Windows lab VM:

```powershell
powershell.exe -NoProfile -Command "Start-Sleep -Seconds 300"
```

Get the PID:

```powershell
Get-Process powershell | Select-Object Id, ProcessName, Path
```

## Dry-Run

Dry-run creates a planned protection record and does not kill anything:

```powershell
python scripts\response\run_protection_action.py --input fixture-alert --action kill-process --output summary
```

Alert JSON dry-run:

```powershell
python scripts\response\run_protection_action.py --input alert-json --alert-path .\alert.json --action kill-process --output summary
```

## Execute In Isolated Lab

Only use this in an isolated lab VM:

```powershell
python scripts\response\run_protection_action.py --input alert-json --alert-path .\alert.json --action kill-process --pid <PID> --execute-protection --lab-allow-execute --output summary
```

Verify the process terminated:

```powershell
Get-Process -Id <PID>
```

If the process is gone, PowerShell reports that no process exists with that ID.

## Index Protection Record

```powershell
python scripts\response\run_protection_action.py --input alert-json --alert-path .\alert.json --action kill-process --write-protection --elasticsearch-url http://localhost:9200
```

Protection records are indexed to:

```text
edr-protection-actions-YYYY.MM.DD
```

Kibana data views should use:

```text
edr-protection-actions-*
```

## Kibana Validation

Use data view:

```text
edr-protection-actions-*
```

Useful filters:

- `protection.action: kill_process`
- `protection.status: executed`
- `protection.status: planned`
- `protection.status: blocked`
- `protection.mode: execute`
- `protection.mode: dry-run`

Expected live demo flow:

```text
attack process starts
  -> Sysmon Event ID 1
  -> alert
  -> SOAR dry-run planning
  -> guarded protection action
  -> protection action record
  -> Kibana evidence
```

For the final dashboard, use protection records alongside:

- Phase 9 10 demo cases.
- TP/TN/FP/FN classification counts.
- `reports/demo_cases/case_matrix.json`.
- `reports/demo_cases/dashboard_data.json`.

No production containment is implemented. The only execution path is lab-only kill-process with explicit safety flags.
