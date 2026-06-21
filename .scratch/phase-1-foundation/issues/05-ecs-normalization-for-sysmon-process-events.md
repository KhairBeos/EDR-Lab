Status: done

# ECS normalization for Sysmon process events

## Parent

`.scratch/phase-1-foundation/PRD.md`

## What to build

Build the first ECS normalization slice for Sysmon process creation telemetry. Given a representative Sysmon Event ID 1 record and optional Atomic Red Team metadata, the normalization path should emit an ECS-compatible event with stable process, parent process, user, host, and event timestamp fields.

This slice establishes the normalized event contract that later Sigma and behavioral detection work will consume.

## Acceptance criteria

- [ ] Sysmon Event ID 1 maps into ECS-compatible process, parent process, user, host, and event fields.
- [ ] Required fields include `process.name`, `process.executable`, `process.pid`, `process.parent.name`, `process.parent.pid`, `process.command_line`, `process.args`, `user.name`, `host.name`, and `event.created`.
- [ ] Raw events and normalized events remain distinguishable by index naming, metadata, or documented event fields.
- [ ] Mapping definitions are versioned and easy to extend for additional Sysmon Event IDs.
- [ ] Malformed or partial input events produce predictable errors or skipped-event records rather than crashes.
- [ ] Unit tests cover happy-path Event ID 1 normalization and malformed input handling.
- [ ] An integration-style fixture test proves a sample Sysmon event becomes a normalized ECS event without a live Windows endpoint.

## Blocked by

- `.scratch/phase-1-foundation/issues/01-bootstrap-local-elastic-lab.md`
- `.scratch/phase-1-foundation/issues/03-installable-sysmon-telemetry-baseline.md`
