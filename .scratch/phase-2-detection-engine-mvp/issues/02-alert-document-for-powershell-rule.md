Status: done

# Alert document for PowerShell rule

## Parent

`.scratch/phase-2-detection-engine-mvp/PRD.md`

## Goal

Produce a simple, stable alert document from the `T1059.001` PowerShell rule match. This slice should turn a matched normalized Sysmon Event ID 1 ECS document into alert JSON that later correlation and response layers can consume.

## What to build

Add alert generation for the PowerShell detection rule. Given a rule match, emit one JSON-compatible alert document containing alert metadata, rule metadata, ATT&CK metadata, event evidence, host/user/process context, source event references when available, and preserved Atomic Red Team metadata.

The alert builder should be testable without Elasticsearch. It should accept the matched event and rule metadata directly, so the fixture-based smoke payload can validate alert behavior deterministically.

## Files to create or edit

- Create or edit alert document builder under the detection layer.
- Create tests for alert document shape and deterministic fields.
- Edit the PowerShell rule/evaluator tests if needed to assert match-to-alert behavior.
- Reuse existing normalized Sysmon Event ID 1 fixture payloads from the smoke path.

## Commands to run

```powershell
python -m pytest tests\test_end_to_end_smoke_path.py
python -m pytest tests
```

If focused tests are added for this slice, also run:

```powershell
python -m pytest tests\test_detection_alert_document.py
```

## Acceptance criteria

- [ ] A matched PowerShell rule can produce one alert document.
- [ ] The alert document includes `alert.id`, `alert.kind`, `alert.status`, `alert.created`, `alert.severity`, and `alert.confidence`.
- [ ] The alert document includes rule metadata for the `T1059.001` PowerShell rule.
- [ ] The alert document includes ATT&CK metadata for `T1059.001` and Execution.
- [ ] The alert document includes source event evidence from normalized ECS fields.
- [ ] The alert document includes host, user, process, parent process, and command line evidence when those fields exist.
- [ ] The alert document preserves `art.*` metadata when the matched event contains it.
- [ ] Alert ID generation is deterministic for fixture-based tests.
- [ ] Alert generation handles missing optional evidence fields without crashing.
- [ ] Tests assert the public alert contract, not implementation details.

## Blocked by

- `.scratch/phase-2-detection-engine-mvp/issues/01-native-powershell-detection-rule.md`

## Out-of-scope boundaries

- Do not write alerts to TheHive.
- Do not trigger SOAR playbooks.
- Do not implement correlation or deduplication across multiple rules.
- Do not add alert scoring beyond simple severity/confidence metadata.
- Do not implement Kafka alert transport.
- Do not add ML fields or model scores.
- Do not build a UI dashboard.
