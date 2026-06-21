# ECS Normalization

Phase 1 introduced Sysmon Event ID 1 Process Create normalization. Phase 12 expands the broader Sysmon coverage to Event ID 1, 3, 11, and 13; see `docs/sysmon_event_coverage.md`.

This document describes the original Event ID 1 mapping. The Event ID 1 implementation lives in `normalization/sysmon/process_create_normalizer.py` and uses `collection/sysmon/fixtures/sysmon_event_1_process_create.xml` as its first fixture.

## Scope

In scope:

- Sysmon Event ID 1 Process Create XML.
- ECS-compatible process, parent process, user, host, event, log, data stream, and tag fields.
- Preservation of the original XML in `event.original`.
- Preservation of original Sysmon `EventData` fields in `sysmon.event_data`.
- Rejection of unsupported Event IDs.

Out of scope:

- Detection logic for additional Sysmon Event IDs.
- Elastic ingestion.
- Detection rules.
- Atomic Red Team execution.

## Source Fields

From the Sysmon `System` section:

- `Provider.Name`
- `EventID`
- `TimeCreated.SystemTime`
- `Channel`
- `Computer`

From the Sysmon `EventData` section:

- `RuleName`
- `UtcTime`
- `ProcessGuid`
- `ProcessId`
- `Image`
- `FileVersion`
- `Description`
- `Product`
- `Company`
- `OriginalFileName`
- `CommandLine`
- `CurrentDirectory`
- `User`
- `LogonGuid`
- `LogonId`
- `TerminalSessionId`
- `IntegrityLevel`
- `Hashes`
- `ParentProcessGuid`
- `ParentProcessId`
- `ParentImage`
- `ParentCommandLine`
- `ParentUser`

## Mapping Table

| Sysmon source | ECS target | Transformation |
| --- | --- | --- |
| `System.TimeCreated.SystemTime` | `@timestamp` | Copy ISO timestamp |
| `System.EventID` | `event.code` | Parse to integer |
| constant | `event.kind` | `event` |
| constant | `event.category` | `["process"]` |
| constant | `event.type` | `["start"]` |
| constant | `event.action` | `Process Create` |
| constant | `event.module` | `sysmon` |
| `System.Provider.Name` | `event.provider` | Copy |
| constant | `event.dataset` | `windows.sysmon_operational` |
| `EventData.UtcTime` | `event.created` | Parse Sysmon UTC time to ISO-8601 UTC |
| raw XML | `event.original` | Preserve exact input string |
| `System.Channel` | `log.channel` | Copy |
| `System.Computer` | `host.name` | Copy |
| constant | `host.os.type` | `windows` |
| `EventData.User` | `user.domain`, `user.name` | Split `DOMAIN\user` |
| `EventData.ProcessId` | `process.pid` | Parse to integer |
| `EventData.ProcessGuid` | `process.entity_id` | Copy |
| `EventData.Image` | `process.executable` | Copy |
| `EventData.Image` | `process.name` | Windows path basename |
| `EventData.CommandLine` | `process.command_line` | Copy |
| `EventData.CommandLine` | `process.args` | Best-effort Windows command-line split |
| `EventData.CurrentDirectory` | `process.working_directory` | Copy |
| `EventData.Hashes` | `process.hash.*` | Parse comma-separated `KEY=value` pairs |
| `EventData.ParentProcessId` | `process.parent.pid` | Parse to integer |
| `EventData.ParentProcessGuid` | `process.parent.entity_id` | Copy |
| `EventData.ParentImage` | `process.parent.executable` | Copy |
| `EventData.ParentImage` | `process.parent.name` | Windows path basename |
| `EventData.ParentCommandLine` | `process.parent.command_line` | Copy |
| `EventData.ParentUser` | `process.parent.user.domain`, `process.parent.user.name` | Split `DOMAIN\user` |
| `EventData.IntegrityLevel` | `process.Ext.token.integrity_level_name` | Copy as Elastic extension field |
| all `EventData` | `sysmon.event_data.*` | Preserve original Sysmon field names and string values |
| constant | `data_stream.type` | `logs` |
| constant | `data_stream.dataset` | `windows.sysmon_operational` |
| constant | `data_stream.namespace` | `phase1` |
| constant | `tags` | `["ecs_normalized", "sysmon_event_1"]` |

## Transformation Rules

- Accept only `System.EventID == 1`.
- Reject unsupported Event IDs with a predictable `UnsupportedSysmonEventError`.
- Reject malformed XML with a predictable `SysmonNormalizationError`.
- Preserve the full input XML in `event.original`.
- Preserve all original Sysmon `EventData` values under `sysmon.event_data`.
- Store `event.code` as an integer for this project phase.
- Set `event.module` to `sysmon`.
- Set `host.os.type` to `windows`.
- Parse process IDs as integers.
- Derive process names from Windows executable paths.
- Split Windows users on the first backslash into domain and account name.
- Parse Sysmon `Hashes` into `process.hash` keys using lowercase hash algorithm names.
- Keep custom Sysmon-only fields under `sysmon.*` or `process.Ext.*`.

## Example Input Event

Abbreviated from `collection/sysmon/fixtures/sysmon_event_1_process_create.xml`:

```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" />
    <EventID>1</EventID>
    <TimeCreated SystemTime="2026-06-08T02:30:00.0000000Z" />
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>WIN11-EDR-LAB</Computer>
  </System>
  <EventData>
    <Data Name="UtcTime">2026-06-08 02:30:00.000</Data>
    <Data Name="ProcessGuid">{9f7f5c20-1c5d-6666-0100-000000000400}</Data>
    <Data Name="ProcessId">5824</Data>
    <Data Name="Image">C:\Windows\System32\cmd.exe</Data>
    <Data Name="CommandLine">cmd.exe /c whoami</Data>
    <Data Name="User">WIN11-EDR-LAB\edr-lab</Data>
    <Data Name="ParentProcessId">4460</Data>
    <Data Name="ParentImage">C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data>
    <Data Name="ParentCommandLine">powershell.exe -NoLogo</Data>
    <Data Name="ParentUser">WIN11-EDR-LAB\edr-lab</Data>
  </EventData>
</Event>
```

## Example Normalized Output

```json
{
  "@timestamp": "2026-06-08T02:30:00.0000000Z",
  "event": {
    "kind": "event",
    "category": ["process"],
    "type": ["start"],
    "action": "Process Create",
    "code": 1,
    "module": "sysmon",
    "provider": "Microsoft-Windows-Sysmon",
    "dataset": "windows.sysmon_operational",
    "created": "2026-06-08T02:30:00.000Z",
    "original": "<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\">...</Event>"
  },
  "log": {
    "channel": "Microsoft-Windows-Sysmon/Operational"
  },
  "host": {
    "name": "WIN11-EDR-LAB",
    "os": {
      "type": "windows"
    }
  },
  "user": {
    "domain": "WIN11-EDR-LAB",
    "name": "edr-lab"
  },
  "process": {
    "pid": 5824,
    "entity_id": "{9f7f5c20-1c5d-6666-0100-000000000400}",
    "name": "cmd.exe",
    "executable": "C:\\Windows\\System32\\cmd.exe",
    "command_line": "cmd.exe /c whoami",
    "args": ["cmd.exe", "/c", "whoami"],
    "working_directory": "C:\\Users\\edr-lab\\",
    "parent": {
      "pid": 4460,
      "entity_id": "{9f7f5c20-1c58-6666-ff00-000000000400}",
      "name": "powershell.exe",
      "executable": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
      "command_line": "powershell.exe -NoLogo",
      "user": {
        "domain": "WIN11-EDR-LAB",
        "name": "edr-lab"
      }
    }
  },
  "sysmon": {
    "event_data": {
      "ProcessId": "5824",
      "Image": "C:\\Windows\\System32\\cmd.exe",
      "CommandLine": "cmd.exe /c whoami"
    }
  },
  "tags": ["ecs_normalized", "sysmon_event_1"]
}
```

## Validation Strategy

- Normalize the existing Event ID 1 fixture.
- Assert required ECS fields exist:
  - `process.name`
  - `process.executable`
  - `process.pid`
  - `process.parent.name`
  - `process.parent.pid`
  - `process.command_line`
  - `process.args`
  - `user.name`
  - `host.name`
  - `host.os.type`
  - `event.created`
  - `event.module`
- Assert `event.code` is integer `1`.
- Assert `event.original` equals the original XML string.
- Assert original Sysmon fields are preserved under `sysmon.event_data`.
- Assert unsupported Event IDs are rejected.
- Assert malformed XML returns a predictable normalization error.
