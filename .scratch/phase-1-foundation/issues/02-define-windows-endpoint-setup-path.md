Status: done

# Define the Windows endpoint setup path

## Parent

`.scratch/phase-1-foundation/PRD.md`

## What to build

Document and script the Windows 10/11 endpoint setup path for Phase 1 telemetry generation. This slice should make the endpoint assumptions explicit: required admin permissions, event channels, PowerShell logging, network connectivity to the collection endpoint, and the operational steps needed before Sysmon and Atomic Red Team can run reliably.

This is marked HITL in the breakdown because the final environment may depend on the user's real lab topology, but the implementation should still provide a useful default path for a Windows victim VM.

## Acceptance criteria

- [x] Endpoint setup documentation distinguishes Windows endpoint steps from Docker/Elastic host steps.
- [x] Required admin permissions and Windows version assumptions are documented.
- [x] PowerShell 4103 and 4104 logging enablement is documented or scripted.
- [x] Security, PowerShell, and WMI-Activity event channel requirements are documented.
- [x] Network connectivity from the endpoint to the Logstash/Elastic collection host is documented with verification commands.
- [x] Endpoint-specific values are represented as local configuration or environment variables rather than hardcoded constants.
- [x] The runbook names the manual decisions a human must confirm for their lab topology.

## Blocked by

None - can start immediately.
