Status: done

# Phase 1 operator docs and acceptance runbook

## Parent

`.scratch/phase-1-foundation/PRD.md`

## What to build

Create the operator-facing documentation that ties the Phase 1 foundation together. A new contributor should be able to understand what runs on the Windows endpoint, what runs on the Elastic Stack host, how to start the lab, how to run the first Atomic Red Team technique, and how to decide whether Phase 1 is complete.

This slice turns the implemented foundation into a repeatable workflow rather than a collection of disconnected scripts.

## Acceptance criteria

- [x] Documentation explains the Phase 1 architecture in terms of Windows endpoint, Sysmon, Elastic Stack, Atomic Red Team, and ECS normalization.
- [x] Quick-start commands cover dependency setup, stack deployment, first ART run, and Kibana verification.
- [x] The runbook clearly separates automated steps from manual Windows endpoint steps.
- [x] Troubleshooting guidance covers common failures: unhealthy Elastic services, missing Sysmon events, failed ART execution, malformed normalized events, and missing Kibana results.
- [x] Acceptance criteria state that Phase 1 is complete only when raw ART events are visible in Kibana by technique ID.
- [x] Documentation uses the project glossary terms from `CONTEXT.md`.
- [x] Existing README guidance is updated or cross-linked so there is one clear Phase 1 path.

## Blocked by

- `.scratch/phase-1-foundation/issues/01-bootstrap-local-elastic-lab.md`
- `.scratch/phase-1-foundation/issues/02-define-windows-endpoint-setup-path.md`
- `.scratch/phase-1-foundation/issues/03-installable-sysmon-telemetry-baseline.md`
- `.scratch/phase-1-foundation/issues/04-atomic-red-team-selected-technique-runner.md`
- `.scratch/phase-1-foundation/issues/05-ecs-normalization-for-sysmon-process-events.md`
- `.scratch/phase-1-foundation/issues/06-end-to-end-art-telemetry-ingestion-smoke-path.md`
