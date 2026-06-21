Status: done

# Atomic Red Team selected-technique runner

## Parent

`.scratch/phase-1-foundation/PRD.md`

## What to build

Implement the first Atomic Red Team execution slice: selected technique configuration plus a runner interface that can execute or dry-run a Windows technique and produce deterministic `art.*` metadata for every run.

The initial required happy path is T1059.001 PowerShell on Windows. The runner should make execution repeatable and diagnosable without requiring ad hoc shell commands.

## Acceptance criteria

- [ ] Selected Atomic Red Team techniques are configured explicitly, including T1059.001 for Windows.
- [ ] The runner accepts technique ID, platform, and metadata-tagging options.
- [ ] The runner can operate in dry-run mode for local tests without a Windows endpoint.
- [ ] Each run produces `art.technique_id`, `art.test_guid`, `art.test_name`, `art.platform`, `art.executor`, and `art.run_timestamp`.
- [ ] Failed runs still produce a structured execution record with enough context to diagnose the failure.
- [ ] Unit tests verify deterministic metadata injection and preservation of original event fields.
- [ ] Documentation explains how to run the first ART test from the Phase 1 runbook.

## Blocked by

- `.scratch/phase-1-foundation/issues/02-define-windows-endpoint-setup-path.md`
