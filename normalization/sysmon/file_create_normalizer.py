"""Normalize Sysmon Event ID 11 File Create events."""

from __future__ import annotations

from typing import Any

from normalization.sysmon.common import (
    SYSMON_DATASET,
    SYSMON_DATA_STREAM,
    file_extension,
    parse_int,
    parse_sysmon_event,
    split_windows_user,
    system_attr,
    system_text,
    windows_basename,
)
from normalization.sysmon.process_create_normalizer import UnsupportedSysmonEventError


def normalize_sysmon_event_11(xml_event: str) -> dict[str, Any]:
    """Normalize one Sysmon Event ID 11 XML event into ECS-compatible JSON."""

    parsed = parse_sysmon_event(xml_event)
    event_id = system_text(parsed.system, "EventID")

    if event_id != "11":
        raise UnsupportedSysmonEventError(f"Only Sysmon Event ID 11 is supported, got {event_id!r}.")

    event_data = parsed.event_data
    process_image = event_data.get("Image", "")
    target_filename = event_data.get("TargetFilename", "")
    user_domain, user_name = split_windows_user(event_data.get("User", ""))

    return {
        "@timestamp": system_attr(parsed.system, "TimeCreated", "SystemTime"),
        "event": {
            "kind": "event",
            "category": ["file"],
            "type": ["creation"],
            "action": "File created",
            "code": parse_int(event_id, "System.EventID"),
            "module": "sysmon",
            "provider": system_attr(parsed.system, "Provider", "Name"),
            "dataset": SYSMON_DATASET,
            "original": xml_event,
        },
        "log": {
            "channel": system_text(parsed.system, "Channel"),
        },
        "host": {
            "name": system_text(parsed.system, "Computer"),
            "os": {
                "type": "windows",
            },
        },
        "user": {
            "domain": user_domain,
            "name": user_name,
        },
        "process": {
            "pid": parse_int(event_data.get("ProcessId", ""), "ProcessId"),
            "entity_id": event_data.get("ProcessGuid", ""),
            "name": windows_basename(process_image),
            "executable": process_image,
        },
        "file": {
            "path": target_filename,
            "name": windows_basename(target_filename),
            "extension": file_extension(target_filename),
        },
        "sysmon": {
            "event_data": dict(event_data),
        },
        "data_stream": dict(SYSMON_DATA_STREAM),
        "tags": ["ecs_normalized", "sysmon_event_11"],
    }
