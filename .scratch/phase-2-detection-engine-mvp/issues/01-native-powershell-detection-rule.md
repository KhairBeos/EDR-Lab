Status: done

# Native PowerShell detection rule

## Parent

`.scratch/phase-2-detection-engine-mvp/PRD.md`

## Goal

Create the first deterministic detection rule for `T1059.001` PowerShell execution using existing normalized Sysmon Event ID 1 ECS documents. This slice should prove that a normalized fixture payload can be evaluated locally and produce a rule match without Elasticsearch, Docker, Logstash, Kafka, ML, or external services.

## What to build

Build one small native or Sigma-like detection rule and a minimal rule evaluator. The evaluator should accept normalized ECS dictionaries from the existing fixture-based smoke path, ignore raw/non-normalized payloads, and return a match only when PowerShell evidence appears in supported Sysmon Event ID 1 process fields.

The MVP should support the current fixture shape by matching PowerShell evidence in either the process fields or parent process fields. That keeps validation aligned with the existing smoke fixture, where `cmd.exe` is spawned by a PowerShell parent.

## Files to create or edit

- Create or edit detection rule module under the existing detection area.
- Create one local rule definition for `T1059.001` PowerShell execution.
- Create unit tests for rule matching and ignored events.
- Reuse existing fixture payload builders from the smoke path instead of creating a parallel fixture pipeline.

## Commands to run

```powershell
python -m pytest tests\test_end_to_end_smoke_path.py
python -m pytest tests
```

If focused tests are added for this slice, also run:

```powershell
python -m pytest tests\test_powershell_detection_rule.py
```

## Acceptance criteria

- [ ] A single rule exists for `T1059.001` PowerShell execution.
- [ ] The rule metadata includes rule ID, name, version, severity, confidence, ATT&CK technique ID, ATT&CK technique name, tactic, and expected ECS data source.
- [ ] The evaluator accepts normalized Sysmon Event ID 1 ECS dictionaries.
- [ ] The evaluator ignores raw payloads where `event.dataset = edr.raw`.
- [ ] The evaluator ignores events where `event.dataset` is not `windows.sysmon_operational`.
- [ ] The evaluator ignores events where `event.code` is not `1`.
- [ ] The evaluator matches PowerShell evidence in `process.name`, `process.executable`, or `process.command_line`.
- [ ] The evaluator matches PowerShell evidence in `process.parent.name`, `process.parent.executable`, or `process.parent.command_line` so the current smoke fixture can validate the MVP.
- [ ] The evaluator does not match unrelated process events.
- [ ] Tests assert external behavior: matched event versus ignored event, not private helper internals.

## Blocked by

None - can start immediately.

## Out-of-scope boundaries

- Do not implement ML detection.
- Do not implement Kafka consumers or producers.
- Do not implement TheHive case creation.
- Do not implement SOAR or containment.
- Do not import SigmaHQ rules.
- Do not implement a full Sigma compiler.
- Do not add new Sysmon Event IDs.
- Do not expand to other ATT&CK techniques.
