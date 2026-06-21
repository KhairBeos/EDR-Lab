# Windows VM Atomic Red Team Demo

Phase 8 validates the EDR MVP with real lab-generated Sysmon telemetry from an isolated Windows VM.

This workflow is lab-only. Do not run Atomic Red Team on production endpoints, shared corporate laptops, or unmanaged networks.

## Roles

- Atomic Red Team creates safe attack simulation activity.
- Sysmon records Windows endpoint telemetry.
- The EDR pipeline consumes exported Sysmon XML and runs the existing normalization, detection, ML anomaly, SOAR dry-run, and reporting paths.

## Lab Safety

- Use an isolated Windows VM.
- Take a VM snapshot before installing tools.
- Run only tests you understand and have reviewed.
- Prefer the documented safe `T1059.001` PowerShell case for this project.
- Do not enable real containment actions. This repo only plans dry-run SOAR response records.

## Install Sysmon

Download Sysmon manually from Microsoft Sysinternals inside the lab VM. Copy this repo's Sysmon config into the VM, then install from an elevated PowerShell session:

```powershell
.\Sysmon64.exe -accepteula -i .\collection\sysmon\sysmon_config.xml
```

Update an existing install:

```powershell
.\Sysmon64.exe -c .\collection\sysmon\sysmon_config.xml
```

## Confirm Sysmon

Check the service:

```powershell
Get-Service Sysmon64
```

Check the event channel:

```powershell
Get-WinEvent -ListLog "Microsoft-Windows-Sysmon/Operational"
```

Generate a safe process event:

```powershell
powershell.exe -NoProfile -Command "Write-Output EDR_SYSMON_CHECK"
```

Confirm Sysmon Event ID 1:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 20 |
  Where-Object { $_.Id -eq 1 } |
  Select-Object -First 5 TimeCreated, Id, ProviderName, Message
```

## Install Atomic Red Team

Install Atomic Red Team / `Invoke-AtomicRedTeam` only in the isolated lab VM. Follow the official Atomic Red Team installation guidance from Red Canary, then verify the module is available:

```powershell
Get-Command Invoke-AtomicTest
```

Review tests before running them:

```powershell
Invoke-AtomicTest T1059.001 -ShowDetailsBrief
```

Run only a safe lab test that creates benign PowerShell process telemetry. If Atomic Red Team is unavailable, use the fallback command documented in `docs/atomic_attack_case_catalog.md`.

## Validate With This Repo

After running the safe `T1059.001` test, export the Sysmon Event ID 1 XML and copy it to the host project folder:

```text
samples/sysmon/art_t1059_001_powershell_event.xml
```

Then run:

```powershell
python scripts\demo\run_art_sysmon_demo_validation.py --input xml --xml-path .\samples\sysmon\art_t1059_001_powershell_event.xml --engine all --output summary
```

Expected result:

- One normalized Sysmon Event ID 1 event.
- One native `T1059.001` PowerShell alert.
- One Sigma-like `T1059.001` PowerShell alert.

