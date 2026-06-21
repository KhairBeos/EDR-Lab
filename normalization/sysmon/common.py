"""Shared helpers for Sysmon XML normalization."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, timezone

from normalization.sysmon.process_create_normalizer import SysmonNormalizationError


SYSMON_DATASET = "windows.sysmon_operational"
SYSMON_MODULE = "sysmon"
SYSMON_PROVIDER = "Microsoft-Windows-Sysmon"
SYSMON_DATA_STREAM = {
    "type": "logs",
    "dataset": SYSMON_DATASET,
    "namespace": "phase12",
}


@dataclass(frozen=True)
class ParsedSysmonEvent:
    root: ET.Element
    system: ET.Element
    event_data: dict[str, str]
    original_xml: str


def parse_sysmon_event(xml_event: str) -> ParsedSysmonEvent:
    try:
        root = ET.fromstring(xml_event)
    except ET.ParseError as exc:
        raise SysmonNormalizationError(f"Malformed Sysmon XML: {exc}") from exc

    system = child(root, "System")
    event_data_node = child(root, "EventData")
    event_data: dict[str, str] = {}

    for data_node in children(event_data_node, "Data"):
        name = data_node.attrib.get("Name")
        if name:
            event_data[name] = data_node.text or ""

    return ParsedSysmonEvent(root=root, system=system, event_data=event_data, original_xml=xml_event)


def child(parent: ET.Element, local_name: str) -> ET.Element:
    for node in parent:
        if local_name_of(node.tag) == local_name:
            return node
    raise SysmonNormalizationError(f"Missing XML element: {local_name}")


def children(parent: ET.Element, local_name: str) -> list[ET.Element]:
    return [node for node in parent if local_name_of(node.tag) == local_name]


def local_name_of(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def system_text(system: ET.Element, local_name: str) -> str:
    return (child(system, local_name).text or "").strip()


def system_attr(system: ET.Element, local_name: str, attr_name: str) -> str:
    return child(system, local_name).attrib.get(attr_name, "")


def parse_int(value: str, field_name: str) -> int:
    try:
        return int(value)
    except ValueError as exc:
        raise SysmonNormalizationError(f"Expected integer for {field_name}, got {value!r}.") from exc


def normalize_sysmon_utc_time(value: str) -> str:
    if not value:
        return ""

    try:
        parsed = datetime.strptime(value, "%Y-%m-%d %H:%M:%S.%f").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise SysmonNormalizationError(f"Invalid Sysmon UtcTime: {value!r}.") from exc

    return parsed.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def windows_basename(path: str) -> str:
    if not path:
        return ""
    return re.split(r"[\\/]", path)[-1]


def split_windows_user(value: str) -> tuple[str, str]:
    if "\\" not in value:
        return "", value
    domain, user = value.split("\\", 1)
    return domain, user


def file_extension(path: str) -> str:
    name = windows_basename(path)
    if "." not in name:
        return ""
    return name.rsplit(".", 1)[-1]
