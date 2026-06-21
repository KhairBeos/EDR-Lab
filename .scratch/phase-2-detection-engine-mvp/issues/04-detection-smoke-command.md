Status: done

# Detection smoke command

## Parent

`.scratch/phase-2-detection-engine-mvp/PRD.md`

## Goal

Provide a simple smoke command that validates the Phase 2 detection path end-to-end using the existing fixture-based smoke payloads. This slice should let the operator run fixture -> normalized ECS document -> PowerShell rule -> alert document locally.

## What to build

Add a small command-line smoke entry point for the detection engine. It should run in a fixture-only mode without Docker and optionally in an Elasticsearch mode when the local lab is running. The command should print generated alert documents or a clear no-alert result.

The fixture-only mode is the primary acceptance path. Elasticsearch mode is an optional extension that proves live query integration after smoke payloads are posted to Logstash.

## Files to create or edit

- Create or edit a detection smoke script under the existing smoke scripts area.
- Wire the script to existing Phase 1 payload builders.
- Wire the script to the PowerShell rule evaluator and alert builder.
- Optionally wire the script to the Elasticsearch query client.
- Add tests for the command behavior where practical.

## Commands to run

```powershell
python scripts\smoke\end_to_end_art_telemetry_smoke.py --print-payloads
python scripts\smoke\phase_2_detection_smoke.py
python -m pytest tests
```

For optional local Elastic validation:

```powershell
docker compose up -d
python scripts\smoke\end_to_end_art_telemetry_smoke.py --post-logstash
python scripts\smoke\phase_2_detection_smoke.py --from-elasticsearch
```

## Acceptance criteria

- [ ] A fixture-only smoke command runs without Docker, Logstash, Elasticsearch, Kibana, Kafka, or a Windows VM.
- [ ] The command reuses the existing Sysmon Event ID 1 fixture-based smoke payload path.
- [ ] The command evaluates the `T1059.001` PowerShell rule against the normalized payload.
- [ ] The command emits at least one alert document for the current fixture path.
- [ ] The command clearly reports when no alert is produced.
- [ ] The command exits non-zero on unexpected detection or alert generation errors.
- [ ] Optional Elasticsearch mode queries local Elasticsearch and feeds returned events through the same evaluator and alert builder.
- [ ] Tests or documented manual checks cover the happy path and no-alert behavior.

## Blocked by

- `.scratch/phase-2-detection-engine-mvp/issues/01-native-powershell-detection-rule.md`
- `.scratch/phase-2-detection-engine-mvp/issues/02-alert-document-for-powershell-rule.md`
- `.scratch/phase-2-detection-engine-mvp/issues/03-elasticsearch-query-for-normalized-powershell-events.md`

## Out-of-scope boundaries

- Do not require a live Windows VM.
- Do not require Docker for fixture-only mode.
- Do not write alerts to a persistent alert index unless a later issue asks for it.
- Do not trigger response automation.
- Do not add Kafka transport.
- Do not add UI dashboards.
- Do not broaden beyond `T1059.001`.
