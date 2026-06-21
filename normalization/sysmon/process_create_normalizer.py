"""Normalize Sysmon Event ID 1 Process Create events to ECS-compatible JSON."""

from __future__ import annotations

import re
import shlex
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


class SysmonNormalizationError(ValueError):
    """Raised when a Sysmon event cannot be normalized."""


class UnsupportedSysmonEventError(SysmonNormalizationError):
    """Raised when the event is not supported by this Phase 1 normalizer."""


@dataclass(frozen=True)
class ParsedSysmonEvent:
    root: ET.Element
    system: ET.Element
    event_data: dict[str, str]
    original_xml: str


def normalize_sysmon_event_1(xml_event: str) -> dict[str, Any]:
    """Normalize one Sysmon Event ID 1 XML event into ECS-compatible JSON."""

    parsed = _parse_sysmon_event(xml_event)
    event_id = _system_text(parsed.system, "EventID")

    if event_id != "1":
        raise UnsupportedSysmonEventError(f"Only Sysmon Event ID 1 is supported, got {event_id!r}.")

    event_data = parsed.event_data
    process_image = event_data.get("Image", "")
    parent_image = event_data.get("ParentImage", "")
    user_domain, user_name = _split_windows_user(event_data.get("User", ""))
    parent_user_domain, parent_user_name = _split_windows_user(event_data.get("ParentUser", ""))

    normalized: dict[str, Any] = {
        "@timestamp": _normalize_windows_timestamp(_system_attr(parsed.system, "TimeCreated", "SystemTime")),
        "event": {
            "kind": "event",
            "category": ["process"],
            "type": ["start"],
            "action": "Process Create",
            "code": _parse_int(event_id, "System.EventID"),
            "module": "sysmon",
            "provider": _system_attr(parsed.system, "Provider", "Name"),
            "dataset": "windows.sysmon_operational",
            "created": _normalize_sysmon_utc_time(event_data.get("UtcTime", "")),
            "original": xml_event,
        },
        "log": {
            "channel": _system_text(parsed.system, "Channel"),
        },
        "host": {
            "name": _system_text(parsed.system, "Computer"),
            "os": {
                "type": "windows",
            },
        },
        "user": {
            "domain": user_domain,
            "name": user_name,
        },
        "process": {
            "pid": _parse_int(event_data.get("ProcessId", ""), "ProcessId"),
            "entity_id": event_data.get("ProcessGuid", ""),
            "name": _windows_basename(process_image),
            "executable": process_image,
            "command_line": event_data.get("CommandLine", ""),
            "args": _split_windows_command_line(event_data.get("CommandLine", "")),
            "working_directory": event_data.get("CurrentDirectory", ""),
            "hash": _parse_hashes(event_data.get("Hashes", "")),
            "parent": {
                "pid": _parse_int(event_data.get("ParentProcessId", ""), "ParentProcessId"),
                "entity_id": event_data.get("ParentProcessGuid", ""),
                "name": _windows_basename(parent_image),
                "executable": parent_image,
                "command_line": event_data.get("ParentCommandLine", ""),
                "user": {
                    "domain": parent_user_domain,
                    "name": parent_user_name,
                },
            },
            "Ext": {
                "token": {
                    "integrity_level_name": event_data.get("IntegrityLevel", ""),
                },
            },
        },
        "sysmon": {
            "event_data": dict(event_data),
        },
        "data_stream": {
            "type": "logs",
            "dataset": "windows.sysmon_operational",
            "namespace": "phase1",
        },
        "tags": ["ecs_normalized", "sysmon_event_1"],
    }

    return normalized


def _parse_sysmon_event(xml_event: str) -> ParsedSysmonEvent:
    try:
        root = ET.fromstring(xml_event)
    except ET.ParseError as exc:
        raise SysmonNormalizationError(f"Malformed Sysmon XML: {exc}") from exc

    system = _child(root, "System")
    event_data_node = _child(root, "EventData")
    event_data: dict[str, str] = {}

    for data_node in _children(event_data_node, "Data"):
        name = data_node.attrib.get("Name")
        if name:
            event_data[name] = data_node.text or ""

    return ParsedSysmonEvent(root=root, system=system, event_data=event_data, original_xml=xml_event)


def _child(parent: ET.Element, local_name: str) -> ET.Element:
    for child in parent:
        if _local_name(child.tag) == local_name:
            return child
    raise SysmonNormalizationError(f"Missing XML element: {local_name}")


def _children(parent: ET.Element, local_name: str) -> list[ET.Element]:
    return [child for child in parent if _local_name(child.tag) == local_name]


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _system_text(system: ET.Element, local_name: str) -> str:
    return (_child(system, local_name).text or "").strip()


def _system_attr(system: ET.Element, local_name: str, attr_name: str) -> str:
    return _child(system, local_name).attrib.get(attr_name, "")


def _parse_int(value: str, field_name: str) -> int:
    try:
        return int(value)
    except ValueError as exc:
        raise SysmonNormalizationError(f"Expected integer for {field_name}, got {value!r}.") from exc


def _normalize_windows_timestamp(value: str) -> str:
    if not value:
        return ""
    return value


def _normalize_sysmon_utc_time(value: str) -> str:
    if not value:
        return ""

    try:
        parsed = datetime.strptime(value, "%Y-%m-%d %H:%M:%S.%f").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise SysmonNormalizationError(f"Invalid Sysmon UtcTime: {value!r}.") from exc

    return parsed.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _windows_basename(path: str) -> str:
    if not path:
        return ""
    return re.split(r"[\\/]", path)[-1]


def _split_windows_user(value: str) -> tuple[str, str]:
    if "\\" not in value:
        return "", value
    domain, user = value.split("\\", 1)
    return domain, user


def _split_windows_command_line(command_line: str) -> list[str]:
    if not command_line:
        return []

    try:
        return shlex.split(command_line, posix=False)
    except ValueError:
        return [command_line]


def _parse_hashes(value: str) -> dict[str, str]:
    hashes: dict[str, str] = {}

    for part in value.split(","):
        key, separator, digest = part.partition("=")
        if not separator:
            continue
        ecs_key = key.strip().lower()
        hashes[ecs_key] = digest.strip()

    return hashes
