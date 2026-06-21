# Sysmon Event Coverage

The normalization layer supports deterministic XML-to-dict conversion for a small Sysmon telemetry set used by this EDR lab.

## Implemented Event IDs

| Sysmon Event ID | Name | Status | Normalizer |
| --- | --- | --- | --- |
| `1` | Process Create | Implemented | `normalization/sysmon/process_create_normalizer.py` |
| `3` | Network Connection | Implemented | `normalization/sysmon/network_connection_normalizer.py` |
| `11` | File Create | Implemented | `normalization/sysmon/file_create_normalizer.py` |
| `13` | Registry Value Set | Implemented | `normalization/sysmon/registry_value_set_normalizer.py` |

The router entrypoint is:

```python
from normalization.sysmon.event_router import normalize_sysmon_event

normalized = normalize_sysmon_event(xml)
```

It reads `System.EventID` and dispatches to the matching event-specific normalizer. Unsupported Event IDs raise `UnsupportedSysmonEventError`. Malformed XML raises `SysmonNormalizationError`.

## ATT&CK Relevance

Event ID 3 Network Connection gives future pipelines evidence for `T1105` Ingress Tool Transfer because it records outbound connection metadata such as process identity, destination IP/domain, destination port, protocol, and direction.

Event ID 11 File Create gives download/dropper evidence because it records the process that created a file and the target path, filename, and extension.

Event ID 13 Registry Value Set gives future pipelines evidence for `T1547.001` Registry Run Keys / Startup Folder because it records Run-key style value changes, the process responsible, and the registry value data.

## Field Guarantees

All supported normalizers preserve:

- `event.original` as the exact input XML string.
- `sysmon.event_data` as the original Sysmon `EventData` key/value map.
- `event.module = "sysmon"`.
- `event.dataset = "windows.sysmon_operational"`.
- `data_stream.dataset = "windows.sysmon_operational"`.
- `host.os.type = "windows"`.
- `tags` with `ecs_normalized` and an event-specific tag.

Event-specific tags:

- Event ID 1: `sysmon_event_1`
- Event ID 3: `sysmon_event_3`
- Event ID 11: `sysmon_event_11`
- Event ID 13: `sysmon_event_13`

## Future Pipeline Usage

Collection code can call `normalize_sysmon_event()` when it receives raw Sysmon XML instead of calling an Event ID 1-specific normalizer directly:

```python
def handle_raw_sysmon_xml(xml: str) -> dict:
    normalized = normalize_sysmon_event(xml)
    return normalized
```

This keeps routing in the normalization layer and lets future collection, Kafka, indexing, detection, and correlation code work with normalized ECS-like documents.

## Boundaries

This coverage expansion does not add detection rules. It only adds normalized telemetry for process creation, network connections, file creation, and registry value changes.

The deterministic tests use safe XML samples and do not require Windows, Sysmon, Elasticsearch, Docker, Kafka, or Kibana.
