# Sysmon Phase 1 Telemetry Baseline

This document describes the installable Sysmon baseline for the Phase 1 Windows VM endpoint.

The baseline is stored at `collection/sysmon/sysmon_config.xml`. It is designed to collect endpoint telemetry for later Atomic Red Team execution and ECS normalization. It is not a detection rule pack.

## Scope

In scope:

- A local Sysmon XML baseline.
- Minimal self-noise exclusions.
- Required Phase 1 Sysmon event coverage.
- Windows VM install and update commands.
- Repository-only validation of XML shape and fixture coverage.
- A sample Sysmon Event ID 1 process creation fixture.

Out of scope:

- Downloading Sysmon binaries.
- Installing Sysmon on any machine from this repository.
- Running Atomic Red Team.
- Configuring Elastic Agent or Winlogbeat.
- Implementing ECS normalization.
- Adding Sigma or behavioral detection logic.

## Required Event Coverage

The Phase 1 baseline includes the event sections needed for these Sysmon event IDs:

| Event ID | Sysmon event section | Purpose |
| --- | --- | --- |
| 1 | `ProcessCreate` | Process creation and parent-child process telemetry |
| 3 | `NetworkConnect` | Network connection telemetry |
| 7 | `ImageLoad` | DLL and image load telemetry |
| 8 | `CreateRemoteThread` | Remote thread creation telemetry |
| 10 | `ProcessAccess` | Process access telemetry, including LSASS access observation |
| 11 | `FileCreate` | File creation telemetry |
| 12 | `RegistryEvent` | Registry object create/delete telemetry |
| 13 | `RegistryEvent` | Registry value set telemetry |
| 15 | `FileCreateStreamHash` | Alternate data stream hash telemetry |
| 22 | `DnsQuery` | DNS query telemetry |

`RegistryEvent` also covers Event ID 14, but Phase 1 specifically requires Event IDs 12 and 13.

## Baseline Design

The config follows a telemetry-first style:

- Default behavior is to collect the required event classes.
- Exclusions are limited to Sysmon's own process paths.
- The config avoids product-specific exclusions that could hide Atomic Red Team activity.
- The config avoids detection logic. Detection belongs in later Sigma, ML, and behavioral layers.

Event ID 7 can be noisy. Keep it enabled for Phase 1 because image-load telemetry is important for later detection coverage and validation experiments.

## Windows VM Installation Commands

Run these commands inside the Windows VM endpoint from an elevated PowerShell session after acquiring Sysmon from Microsoft Sysinternals.

Install Sysmon with the Phase 1 baseline:

```powershell
.\Sysmon64.exe -accepteula -i .\collection\sysmon\sysmon_config.xml
```

Update an existing Sysmon installation with the Phase 1 baseline:

```powershell
.\Sysmon64.exe -c .\collection\sysmon\sysmon_config.xml
```

Print the active Sysmon configuration:

```powershell
.\Sysmon64.exe -c
```

Check the Sysmon service:

```powershell
Get-Service Sysmon64
```

Check the Sysmon event channel:

```powershell
Get-WinEvent -ListLog "Microsoft-Windows-Sysmon/Operational"
```

## Safe Event ID 1 Smoke Check

After Sysmon is installed in the Windows VM, run a safe command that should generate Event ID 1:

```powershell
cmd.exe /c whoami
```

Then inspect recent Sysmon process creation events:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 50 |
  Where-Object { $_.Id -eq 1 } |
  Select-Object -First 5 TimeCreated, Id, ProviderName, Message
```

This only verifies local Sysmon telemetry. Shipping events to Logstash, ECS normalization, and Atomic Red Team execution are handled by later issues.

## Repository Validation

Validate the repository config and Event ID 1 fixture without installing Sysmon:

```powershell
.\scripts\setup\validate_sysmon_config.ps1
```

The script verifies:

- `collection/sysmon/sysmon_config.xml` is well-formed XML.
- The root element is `Sysmon`.
- Required event sections are present.
- `collection/sysmon/fixtures/sysmon_event_1_process_create.xml` is well-formed XML.
- The fixture contains Sysmon Event ID 1.
- The fixture includes the fields needed by later ECS process normalization.

## Fixture

The fixture at `collection/sysmon/fixtures/sysmon_event_1_process_create.xml` represents a safe `cmd.exe /c whoami` process creation event.

It includes fields future normalization work needs:

- `UtcTime`
- `ProcessGuid`
- `ProcessId`
- `Image`
- `CommandLine`
- `CurrentDirectory`
- `User`
- `Hashes`
- `ParentProcessGuid`
- `ParentProcessId`
- `ParentImage`
- `ParentCommandLine`
- `ParentUser`

## Safety Notes

- Use the Windows VM endpoint from `docs/windows_endpoint_setup.md`.
- Take a VM snapshot before installing or updating Sysmon.
- Do not run this baseline on a personal or production endpoint for Phase 1.
- Keep Logstash, Elasticsearch, and Kibana ports restricted to the lab network.
- Treat Sysmon telemetry as sensitive because it can contain usernames, process paths, command lines, hashes, DNS queries, and network destinations.
- Keep exclusions minimal until the detection validation loop proves which noise should be filtered.

## Acceptance Criteria

Issue 03 is complete when:

- [ ] `collection/sysmon/sysmon_config.xml` contains the Phase 1 telemetry baseline.
- [ ] Event ID 1 Process Create is covered.
- [ ] Event IDs 3, 7, 8, 10, 11, 12, 13, 15, and 22 are covered by the relevant Sysmon sections.
- [ ] Installation and update commands are documented for the Windows VM endpoint.
- [ ] The baseline avoids detection rules from later phases.
- [ ] Repository validation confirms XML shape and required event sections.
- [ ] A Sysmon Event ID 1 fixture exists for later ECS normalization work.
- [ ] Documentation explains how the telemetry supports later detection validation.
