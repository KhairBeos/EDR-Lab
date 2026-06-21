Status: done

# Sysmon Event 3/11/13 normalization and routing

## Goal

Expand the EDR telemetry normalization layer from Sysmon Event ID 1 only to a multi-event Sysmon normalization layer supporting Event ID 1, 3, 11, and 13.

This phase adds telemetry coverage and a normalization router. It does not add new detection rules yet.

## Context

Current project capabilities:

- Sysmon Event ID 1 Process Create normalization in `normalization/sysmon/process_create_normalizer.py`.
- Native and Sigma-like PowerShell T1059.001 detection.
- ML anomaly detection.
- SOAR dry-run response.
- Lab-only kill-process protection.
- Phase 9 TP/TN/FP/FN case matrix.
- Phase 10 submission-ready final report.

The current telemetry layer relies mostly on process creation. A stronger EDR demo needs normalized telemetry for:

- process creation
- network connections
- file creation
- registry persistence changes

This issue should keep the existing Event ID 1 semantics stable while adding a router and three new event-specific normalizers.

## What to build

Create:

- `normalization/sysmon/event_router.py`
- `normalization/sysmon/network_connection_normalizer.py`
- `normalization/sysmon/file_create_normalizer.py`
- `normalization/sysmon/registry_value_set_normalizer.py`
- `samples/sysmon/event_3_network_connection.xml`
- `samples/sysmon/event_11_file_create.xml`
- `samples/sysmon/event_13_registry_value_set.xml`
- `tests/test_sysmon_event_router.py`
- `tests/test_sysmon_event_3_normalization.py`
- `tests/test_sysmon_event_11_normalization.py`
- `tests/test_sysmon_event_13_normalization.py`
- `docs/sysmon_event_coverage.md`

Update only if low-risk:

- `README.md`
- `docs/architecture.md`
- `docs/ecs_normalization.md`

## Technical design

### Router

Create `normalization/sysmon/event_router.py`.

Expose:

```python
def normalize_sysmon_event(xml: str) -> dict[str, Any]:
    ...
```

Router behavior:

- Parse enough XML to read `System.EventID`.
- Route Event ID `1` to existing `normalize_sysmon_event_1()`.
- Route Event ID `3` to `normalize_sysmon_event_3()`.
- Route Event ID `11` to `normalize_sysmon_event_11()`.
- Route Event ID `13` to `normalize_sysmon_event_13()`.
- Unsupported Event IDs raise `UnsupportedSysmonEventError` with a clear message.
- Malformed XML raises `SysmonNormalizationError` or a router-specific subclass with a clear message.
- Preserve deterministic behavior.
- Do not require Elasticsearch, Windows, Docker, Kafka, or Sysmon to run tests.

Prefer reusing existing helpers and exception types from `process_create_normalizer.py` where practical. If helper reuse would make imports messy, extract shared XML utilities into a small internal module such as `normalization/sysmon/common.py` without changing the public behavior of `normalize_sysmon_event_1()`.

Trade-off: reusing the existing Event ID 1 parser keeps compatibility, but a shared helper module reduces duplication across the new normalizers. Keep the extraction small and covered by existing Event ID 1 tests.

### Event ID 3: Network connection

Create `normalization/sysmon/network_connection_normalizer.py`.

Expose:

```python
def normalize_sysmon_event_3(xml_event: str) -> dict[str, Any]:
    ...
```

Map fields:

- `@timestamp` from `System.TimeCreated.SystemTime`
- `data_stream.type = "logs"`
- `data_stream.dataset = "windows.sysmon_operational"`
- `data_stream.namespace` should remain deterministic and project-local
- `event.kind = "event"`
- `event.module = "sysmon"`
- `event.dataset = "windows.sysmon_operational"`
- `event.provider = "Microsoft-Windows-Sysmon"`
- `event.code = 3`
- `event.action = "Network connection detected"`
- `event.category = ["network"]`
- `event.type = ["connection"]`
- `event.original` preserves exact input XML
- `host.name` from `System.Computer`
- `host.os.type = "windows"`
- `log.channel` from `System.Channel`
- `process.entity_id` from `EventData.ProcessGuid`
- `process.pid` from `EventData.ProcessId`
- `process.executable` from `EventData.Image`
- `process.name` from the basename of `EventData.Image`
- `user.domain` and `user.name` from `EventData.User`
- `source.ip` from `EventData.SourceIp`
- `source.port` from `EventData.SourcePort`
- `destination.ip` from `EventData.DestinationIp`
- `destination.port` from `EventData.DestinationPort`
- `destination.domain` from `EventData.DestinationHostname`
- `network.transport` from `EventData.Protocol`
- `network.direction` from `EventData.Initiated` when available
- `sysmon.event_data` preserves all original `EventData` fields
- `tags = ["ecs_normalized", "sysmon_event_3"]`

Direction rule:

- If `Initiated` is `"true"` or `"True"`, set `network.direction = "outbound"`.
- If `Initiated` is `"false"` or `"False"`, set `network.direction = "inbound"`.
- If missing or unknown, omit `network.direction` or set it to an empty string consistently with existing style.

Use a safe deterministic sample with `certutil.exe` connecting to `127.0.0.1` or `example.test`. Do not create external network dependencies.

### Event ID 11: File create

Create `normalization/sysmon/file_create_normalizer.py`.

Expose:

```python
def normalize_sysmon_event_11(xml_event: str) -> dict[str, Any]:
    ...
```

Map fields:

- `@timestamp` from `System.TimeCreated.SystemTime`
- `event.kind = "event"`
- `event.module = "sysmon"`
- `event.dataset = "windows.sysmon_operational"`
- `event.provider = "Microsoft-Windows-Sysmon"`
- `event.code = 11`
- `event.action = "File created"`
- `event.category = ["file"]`
- `event.type = ["creation"]`
- `event.original` preserves exact input XML
- `host.name` from `System.Computer`
- `host.os.type = "windows"`
- `log.channel` from `System.Channel`
- `process.entity_id` from `EventData.ProcessGuid`
- `process.pid` from `EventData.ProcessId`
- `process.executable` from `EventData.Image`
- `process.name` from the basename of `EventData.Image`
- `file.path` from `EventData.TargetFilename`
- `file.name` from the basename of `EventData.TargetFilename`
- `file.extension` from the final extension of `EventData.TargetFilename`
- `user.domain` and `user.name` from `EventData.User`
- `sysmon.event_data` preserves all original `EventData` fields
- `data_stream` uses the same Sysmon dataset pattern as Event ID 1
- `tags = ["ecs_normalized", "sysmon_event_11"]`

Use a safe deterministic sample where a file is created at:

```text
C:\Users\edr-lab\Downloads\edr_demo.txt
```

### Event ID 13: Registry value set

Create `normalization/sysmon/registry_value_set_normalizer.py`.

Expose:

```python
def normalize_sysmon_event_13(xml_event: str) -> dict[str, Any]:
    ...
```

Map fields:

- `@timestamp` from `System.TimeCreated.SystemTime`
- `event.kind = "event"`
- `event.module = "sysmon"`
- `event.dataset = "windows.sysmon_operational"`
- `event.provider = "Microsoft-Windows-Sysmon"`
- `event.code = 13`
- `event.action = "Registry value set"`
- `event.category = ["registry"]`
- `event.type = ["change"]`
- `event.original` preserves exact input XML
- `host.name` from `System.Computer`
- `host.os.type = "windows"`
- `log.channel` from `System.Channel`
- `process.entity_id` from `EventData.ProcessGuid`
- `process.pid` from `EventData.ProcessId`
- `process.executable` from `EventData.Image`
- `process.name` from the basename of `EventData.Image`
- `registry.path` from `EventData.TargetObject`
- `registry.value` from the final segment of `EventData.TargetObject` when derivable
- `registry.data.strings` from `EventData.Details`
- `user.domain` and `user.name` from `EventData.User`
- `sysmon.event_data` preserves all original `EventData` fields
- `data_stream` uses the same Sysmon dataset pattern as Event ID 1
- `tags = ["ecs_normalized", "sysmon_event_13"]`

Use a safe deterministic sample for:

```text
HKCU\Software\Microsoft\Windows\CurrentVersion\Run\EDRDemo
```

Do not include malware payloads, credential dumping commands, or real persistence instructions beyond a synthetic registry path sample.

## Sample XML requirements

The three new sample files must be deterministic and safe:

- Event 3: `certutil.exe` connecting to `127.0.0.1` or `example.test`
- Event 11: file created at `C:\Users\edr-lab\Downloads\edr_demo.txt`
- Event 13: registry value set at `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\EDRDemo`

Samples must:

- Use `Provider Name="Microsoft-Windows-Sysmon"`.
- Use `Channel` value `Microsoft-Windows-Sysmon/Operational`.
- Use host `WIN11-EDR-LAB`.
- Use user `WIN11-EDR-LAB\edr-lab`.
- Include realistic `UtcTime`, `ProcessGuid`, `ProcessId`, and `Image`.
- Avoid malware payloads.
- Avoid external network dependency.
- Avoid credential dumping content.

## Docs

Create `docs/sysmon_event_coverage.md`.

Document:

- Event ID 1 Process Create: implemented
- Event ID 3 Network Connection: implemented
- Event ID 11 File Create: implemented
- Event ID 13 Registry Value Set: implemented
- How Event ID 3 supports future T1105 evidence through network connection telemetry
- How Event ID 11 supports download/dropper evidence through file creation telemetry
- How Event ID 13 supports future T1547.001 evidence through registry Run key telemetry
- How `normalize_sysmon_event()` is intended to be used by future collection and pipeline code

If low-risk, update README and architecture docs to mention Sysmon Event ID 1/3/11/13 coverage. Do not rewrite the whole architecture document.

## Tests

Create focused tests covering:

- Router routes Event ID 1 to the existing process create normalizer.
- Router routes Event ID 3 to the network connection normalizer.
- Router routes Event ID 11 to the file create normalizer.
- Router routes Event ID 13 to the registry value set normalizer.
- Router raises `UnsupportedSysmonEventError` for an unsupported Event ID.
- Router raises a clear normalization error for invalid XML.
- Event ID 3 sample normalizes expected network fields.
- Event ID 11 sample normalizes expected file fields.
- Event ID 13 sample normalizes expected registry fields.
- `event.original` is preserved exactly for all new event types.
- `sysmon.event_data` preserves original Sysmon fields for all new event types.
- Tags include `ecs_normalized` plus the correct event-specific tag.
- Tests do not require Elasticsearch, Windows, Docker, Kafka, Kibana, or live Sysmon.

Regression expectations:

- Existing `tests/test_sysmon_event_1_normalization.py` still passes.
- Existing detection, SOAR, ML, protection, and dashboard tests continue to pass.
- No detection rule behavior changes are introduced in this issue.

## Commands to run

Focused tests:

```powershell
python -m pytest tests\test_sysmon_event_router.py
python -m pytest tests\test_sysmon_event_3_normalization.py
python -m pytest tests\test_sysmon_event_11_normalization.py
python -m pytest tests\test_sysmon_event_13_normalization.py
```

Full regression:

```powershell
python -m pytest tests --basetemp=.pytest_tmp
```

## Acceptance criteria

- [ ] `normalization/sysmon/event_router.py` exposes `normalize_sysmon_event(xml: str) -> dict`.
- [ ] Router detects `System.EventID` from XML.
- [ ] Router sends Event ID 1 to the existing Event ID 1 normalizer without changing Event ID 1 semantics.
- [ ] Router sends Event ID 3 to the network connection normalizer.
- [ ] Router sends Event ID 11 to the file create normalizer.
- [ ] Router sends Event ID 13 to the registry value set normalizer.
- [ ] Unsupported Event IDs raise a clear `UnsupportedSysmonEventError`.
- [ ] Invalid XML raises a clear normalization error.
- [ ] Event ID 3 normalizer maps ECS network fields, process fields, host fields, user fields, `event.original`, `sysmon.event_data`, and tags.
- [ ] Event ID 11 normalizer maps ECS file fields, process fields, host fields, user fields, `event.original`, `sysmon.event_data`, and tags.
- [ ] Event ID 13 normalizer maps ECS registry fields, process fields, host fields, user fields, `event.original`, `sysmon.event_data`, and tags.
- [ ] New sample XML files are deterministic and safe.
- [ ] `docs/sysmon_event_coverage.md` documents implemented Event ID 1/3/11/13 coverage and future ATT&CK relevance.
- [ ] README and architecture docs mention expanded telemetry coverage only if the update is small and low-risk.
- [ ] Tests cover routing, field mapping, error handling, original XML preservation, event data preservation, and tags.
- [ ] Tests do not require Windows, Sysmon, Elasticsearch, Docker, Kafka, or Kibana.
- [ ] Existing detection, SOAR dry-run, ML anomaly, protection, Phase 9 matrix, and final-report behavior remain unchanged.

## Blocked by

- `.scratch/phase-10-protection-action-mvp/issues/01-lab-only-kill-process-protection-action.md`
- `.scratch/phase-9-demo-case-dashboard-mvp/issues/01-multi-attack-case-dashboard-validation.md`
- `.scratch/phase-6-ml-anomaly-mvp/issues/01-process-anomaly-detection-mvp.md`
- `.scratch/phase-2-detection-engine-mvp/issues/06-native-detection-pipeline-with-alert-indexing.md`
- `.scratch/phase-1-foundation/issues/05-ecs-normalization-for-sysmon-process-events.md`

## Out-of-scope boundaries

- Do not add new detection rules yet.
- Do not add T1105 or T1547.001 detection logic in this issue.
- Do not change Event ID 1 semantics.
- Do not change native PowerShell detection behavior.
- Do not change Sigma-like detection behavior.
- Do not change ML anomaly detection behavior.
- Do not change SOAR dry-run behavior.
- Do not change protection action behavior.
- Do not require Windows, Sysmon, Elasticsearch, Docker, Kafka, or Kibana in tests.
- Do not add malware payloads, credential dumping content, or external network dependencies.

## Implementation notes

Best practice for this issue is to keep each normalizer pure:

```python
normalized = normalize_sysmon_event(xml)
assert normalized["event"]["dataset"] == "windows.sysmon_operational"
assert normalized["event"]["code"] in {1, 3, 11, 13}
assert normalized["event"]["original"] == xml
```

Avoid hidden I/O in normalizers. The collection and indexing layers can call the router later, but this phase should remain a deterministic XML-to-dict transformation layer.

## Comments
