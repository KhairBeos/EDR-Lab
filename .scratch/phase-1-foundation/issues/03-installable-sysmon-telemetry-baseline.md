Status: done

# Installable Sysmon telemetry baseline

## Parent

`.scratch/phase-1-foundation/PRD.md`

## What to build

Create an installable Sysmon baseline for Phase 1 endpoint telemetry. The baseline should follow the SwiftOnSecurity-style baseline concept while ensuring the README's priority Sysmon Event IDs are collected for process, network, image-load, remote-thread, process-access, file, registry, alternate data stream, and DNS telemetry.

The result should let a Windows endpoint produce the raw telemetry needed by later Atomic Red Team and ECS normalization slices.

## Acceptance criteria

- [ ] Sysmon configuration collects Event IDs 1, 3, 7, 8, 10, 11, 12, 13, 15, and 22.
- [ ] The configuration is stored locally and documented as the Phase 1 baseline.
- [ ] Installation and update commands are documented for a Windows endpoint.
- [ ] The baseline avoids relying on detection rules from later phases.
- [ ] A validation step confirms the Sysmon XML is parseable.
- [ ] A fixture or sample event exists for at least Sysmon Event ID 1.
- [ ] Documentation explains how this telemetry supports later detection validation.

## Blocked by

- `.scratch/phase-1-foundation/issues/02-define-windows-endpoint-setup-path.md`
