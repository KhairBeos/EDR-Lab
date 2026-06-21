Status: done

# Bootstrap the local Elastic lab

## Parent

`.scratch/phase-1-foundation/PRD.md`

## What to build

Create the first runnable local lab slice for Phase 1: a Docker Compose based Elastic Stack with Elasticsearch, Kibana, and Logstash, plus setup and deployment commands that let a developer start the stack and verify it is healthy.

This slice should make the lab infrastructure real without requiring a Windows endpoint or Atomic Red Team execution yet. It should provide the service boundary that later endpoint telemetry and normalized events will flow into.

## Acceptance criteria

- [ ] Docker Compose defines Elasticsearch, Kibana, and Logstash services suitable for local Phase 1 development.
- [ ] Services have health checks or equivalent verification commands documented.
- [ ] Elasticsearch and Kibana use persistent local volumes appropriate for development.
- [ ] Logstash has an initial pipeline entry point for incoming endpoint or fixture events.
- [ ] Setup and deployment scripts can prepare dependencies and start the stack.
- [ ] A developer can follow documented commands to start the stack and verify Kibana is reachable.
- [ ] Configuration validation tests cover Docker Compose and Logstash pipeline syntax where practical.

## Blocked by

None - can start immediately.
