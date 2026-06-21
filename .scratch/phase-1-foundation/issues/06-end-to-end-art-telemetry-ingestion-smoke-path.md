Status: done

# End-to-end ART telemetry ingestion smoke path

## Parent

`.scratch/phase-1-foundation/PRD.md`

## What to build

Connect the Phase 1 pieces into a narrow end-to-end smoke path. A selected Atomic Red Team execution should produce tagged telemetry, the collection path should ingest it, normalization should produce ECS-compatible records, and Kibana should allow filtering raw ART-related events by `art.technique_id`.

This is the first demoable slice that proves the README's Phase 1 deliverable.

## Acceptance criteria

- [x] A documented smoke command or runbook starts the Elastic lab and prepares the ingestion path.
- [x] A selected ART run can produce or simulate tagged endpoint telemetry.
- [x] Ingested events preserve `art.technique_id` and related `art.*` fields.
- [x] Normalized events are searchable separately from raw events or clearly marked as normalized.
- [x] Kibana can filter events by `art.technique_id`.
- [x] Kafka topic names are documented and configured for the intended raw, normalized, enriched, and alert streams, even if the first smoke path uses direct Logstash ingestion.
- [x] The smoke path has an automated fixture-based test and a manual Windows endpoint acceptance checklist.

## Blocked by

- `.scratch/phase-1-foundation/issues/01-bootstrap-local-elastic-lab.md`
- `.scratch/phase-1-foundation/issues/03-installable-sysmon-telemetry-baseline.md`
- `.scratch/phase-1-foundation/issues/04-atomic-red-team-selected-technique-runner.md`
- `.scratch/phase-1-foundation/issues/05-ecs-normalization-for-sysmon-process-events.md`
