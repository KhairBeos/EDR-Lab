Status: done

# Phase 2 detection operator docs

## Parent

`.scratch/phase-2-detection-engine-mvp/PRD.md`

## Goal

Document the Phase 2 Detection Engine MVP operator workflow so a junior engineer can run the fixture-only path, optionally run the Elasticsearch path, and understand the exact scope boundaries.

## What to build

Create concise operator documentation for the first detection path. The docs should explain how to generate Phase 1 fixture payloads, run the Phase 2 detection smoke command, optionally post payloads to Logstash and query Elasticsearch, and inspect the generated alert document.

The docs should explicitly state that this MVP does not include ML, Kafka, TheHive, SOAR, full SigmaHQ import, full ATT&CK coverage, or new Sysmon Event IDs.

## Files to create or edit

- Create a Phase 2 detection MVP runbook under project docs.
- Optionally update existing architecture or smoke-path docs with a short link to the Phase 2 runbook.
- Do not rewrite unrelated Phase 1 documentation unless a command reference needs a small cross-link.

## Commands to run

```powershell
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

- [ ] The runbook explains the fixture-only detection workflow.
- [ ] The runbook explains the optional Elasticsearch workflow.
- [ ] The runbook lists expected alert fields at a high level.
- [ ] The runbook describes how the existing normalized Sysmon Event ID 1 fixture is used.
- [ ] The runbook states that the first rule covers `T1059.001` PowerShell execution only.
- [ ] The runbook documents troubleshooting for no-alert results and unavailable Elasticsearch.
- [ ] The runbook explicitly lists the out-of-scope items from the PRD.
- [ ] Existing docs link to the runbook where useful.

## Blocked by

- `.scratch/phase-2-detection-engine-mvp/issues/04-detection-smoke-command.md`

## Out-of-scope boundaries

- Do not write production deployment docs.
- Do not document unsupported ML, Kafka, TheHive, SOAR, or full SigmaHQ workflows as if they exist.
- Do not claim full ATT&CK coverage.
- Do not add new Sysmon setup requirements.
- Do not require a Windows VM for the MVP acceptance flow.
