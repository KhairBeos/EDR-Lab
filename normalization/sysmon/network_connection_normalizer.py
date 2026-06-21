"""Normalize Sysmon Event ID 3 Network Connection events."""

from __future__ import annotations

from typing import Any

from normalization.sysmon.common import (
    SYSMON_DATASET,
    SYSMON_DATA_STREAM,
    parse_int,
    parse_sysmon_event,
    split_windows_user,
    system_attr,
    system_text,
    windows_basename,
)
from normalization.sysmon.process_create_normalizer import UnsupportedSysmonEventError


def normalize_sysmon_event_3(xml_event: str) -> dict[str, Any]:
    """Normalize one Sysmon Event ID 3 XML event into ECS-compatible JSON."""

    parsed = parse_sysmon_event(xml_event)
    event_id = system_text(parsed.system, "EventID")

    if event_id != "3":
        raise UnsupportedSysmonEventError(f"Only Sysmon Event ID 3 is supported, got {event_id!r}.")

    event_data = parsed.event_data
    process_image = event_data.get("Image", "")
    user_domain, user_name = split_windows_user(event_data.get("User", ""))

    normalized: dict[str, Any] = {
        "@timestamp": system_attr(parsed.system, "TimeCreated", "SystemTime"),
        "event": {
            "kind": "event",
            "category": ["network"],
            "type": ["connection"],
            "action": "Network connection detected",
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
        "source": {
            "ip": event_data.get("SourceIp", ""),
            "port": parse_int(event_data.get("SourcePort", ""), "SourcePort"),
        },
        "destination": {
            "ip": event_data.get("DestinationIp", ""),
            "port": parse_int(event_data.get("DestinationPort", ""), "DestinationPort"),
            "domain": event_data.get("DestinationHostname", ""),
        },
        "network": {
            "transport": event_data.get("Protocol", "").lower(),
        },
        "sysmon": {
            "event_data": dict(event_data),
        },
        "data_stream": dict(SYSMON_DATA_STREAM),
        "tags": ["ecs_normalized", "sysmon_event_3"],
    }

    direction = _network_direction(event_data.get("Initiated", ""))
    if direction:
        normalized["network"]["direction"] = direction

    return normalized


def _network_direction(initiated: str) -> str:
    value = initiated.strip().lower()
    if value == "true":
        return "outbound"
    if value == "false":
        return "inbound"
    return ""
