# Atomic Red Team Phase 1 Integration

Phase 1 supports exactly one Atomic Red Team path: `T1059.001` PowerShell in the Windows VM endpoint.

This is intentionally not a broad attack simulation framework. The goal is to produce one safe, repeatable PowerShell execution that the existing Sysmon baseline can observe.

## Selected Technique

The allowlist lives in `atomic-red-team/techniques/selected_techniques.yml`.

Allowed test:

- Technique: `T1059.001`
- Display name: `Command and Scripting Interpreter: PowerShell`
- Test name: `PowerShell Command Execution`
- Test GUID: `a538de64-1c74-46ed-aa60-b995ed302598`
- Platform: `windows`
- Executor: `powershell`

The runner refuses every other technique, platform, executor, and test GUID.

## Required Setup

Developer host:

- Start the local Elastic lab if you want to inspect downstream events later.
- Confirm the Windows VM can reach the developer host as described in `docs/windows_endpoint_setup.md`.

Windows VM endpoint:

- Use the Phase 1 Windows VM endpoint, not a personal or production endpoint.
- Take a VM snapshot before execute mode.
- Install the Sysmon baseline from `docs/sysmon_baseline.md`.
- Confirm the Sysmon Operational channel exists.
- Confirm the PowerShell Operational channel exists.
- Install/import Invoke-AtomicRedTeam so `Invoke-AtomicTest` is available.

The repository does not download Atomic Red Team content or install Invoke-AtomicRedTeam for you.

## Dry Run

Dry-run mode is the default and does not execute anything:

```powershell
python atomic-red-team/execution/runner.py --mode dry-run
```

Use dry-run to verify:

- The selected technique config is readable.
- The allowlist is intact.
- The planned command targets only `T1059.001`.
- Verification commands are printed for the operator.

## Execute

Run execute mode only inside the Windows VM endpoint:

```powershell
python atomic-red-team/execution/runner.py --mode execute --confirm-vm
```

Execute mode runs exactly one command:

```powershell
Invoke-AtomicTest T1059.001 -TestGuids a538de64-1c74-46ed-aa60-b995ed302598
```

It does not run the whole T1059.001 technique, the full Atomic Red Team suite, or any other configured tests.

## Safety

- Use a VM snapshot before execute mode.
- Execute mode requires `--confirm-vm`.
- Do not run this on a physical endpoint for Phase 1.
- Do not run all tests for `T1059.001`.
- Do not use broad tactic or technique execution.
- Keep the VM isolated from sensitive networks.
- Revert the VM snapshot if cleanup is uncertain.

This MVP does not implement cleanup automation yet. The selected test is low-impact, but the safest rollback remains a VM snapshot.

## Verification

After execute mode, verify Sysmon Event ID 1 observed PowerShell:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 100 |
  Where-Object { $_.Id -eq 1 -and $_.Message -match "powershell.exe" } |
  Select-Object -First 5 TimeCreated, Id, Message
```

Verify PowerShell Operational logging:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -MaxEvents 100 |
  Select-Object -First 10 TimeCreated, Id, Message
```

Expected telemetry:

- Sysmon Event ID 1 for `powershell.exe`.
- PowerShell Operational events if operational logging is enabled.
- Additional Sysmon noise may appear from image loads or supporting process activity.

## Out Of Scope

- Running all Atomic Red Team tests.
- Building a generic execution framework.
- Elastic ingestion.
- ECS normalization.
- Detection rules.
- `tag_injector.py`.
- Metadata persistence.
