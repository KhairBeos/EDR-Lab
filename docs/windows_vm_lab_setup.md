# Windows VM / Sysmon Lab Setup

The Windows VM is the optional endpoint lab used to generate real Sysmon and Atomic Red Team telemetry. It is not required for tests because the repository includes deterministic Sysmon Event ID 1 fixtures.

## VM Role

Use an isolated Windows 10/11 VM as the endpoint. The VM is responsible for:

- Running Sysmon.
- Generating Windows process creation telemetry.
- Optionally running allowed Atomic Red Team tests.
- Exporting Sysmon Event ID 1 XML for local pipeline validation.

Do not run Atomic Red Team tests on production endpoints.

## Sysmon Expectation

Install Sysmon with a configuration that captures Event ID 1 Process Create. The current pipeline expects XML with fields such as:

- `Image`
- `CommandLine`
- `ProcessId`
- `ProcessGuid`
- `ParentImage`
- `ParentCommandLine`
- `UtcTime`
- `User`

The deterministic fixture lives at:

```text
collection/sysmon/fixtures/sysmon_event_1_process_create.xml
```

## Atomic Red Team Expectation

Atomic Red Team is used as a controlled source of ATT&CK-shaped telemetry. For this MVP, keep execution limited to isolated lab activity such as `T1059.001` PowerShell.

Safety notes:

- Run only in an isolated VM snapshot.
- Do not run on production endpoints.
- Prefer dry-run review before execution.
- Record which technique/test generated each exported event.

## Exporting Sysmon Event ID 1 XML

You can export an Event ID 1 record from Event Viewer or PowerShell, then save it as XML for local processing.

The local pipeline maps fixture/XML input into:

```text
Sysmon Event ID 1 XML
  -> normalize_sysmon_event_1()
  -> ECS-like event
  -> detection / Kafka dry-run / ML scoring / reports
```

Example XML path usage:

```powershell
python scripts\pipeline\run_live_telemetry_pipeline.py --input xml --xml-path .\event.xml --engine all
```

## Local-Only Safety Notes

- The VM is not required for CI or tests.
- The repository fixtures are enough for deterministic validation.
- Keep VM networking isolated unless you intentionally connect it to the local Docker lab.
- Revert snapshots after running Atomic Red Team.

## Troubleshooting

### Missing Sysmon Service

Check that Sysmon is installed and running. Reinstall Sysmon with the intended config if the service is absent.

### Sysmon Event ID 1 Not Appearing

Confirm the Sysmon config includes Process Create logging. Run a simple process such as `cmd.exe /c whoami` and refresh Event Viewer.

### PowerShell Execution Policy Blocks ART Setup

Use a lab-only execution policy override for the current process when needed. Do not weaken production endpoint policy.

### XML Export Path Wrong

Verify the exported XML file path and use an absolute path when testing from a different working directory.

### Host Timezone / Timestamp Confusion

Sysmon `UtcTime` is UTC. The normalizer preserves UTC timestamps in ECS-compatible fields, so compare with UTC when validating event timing.
