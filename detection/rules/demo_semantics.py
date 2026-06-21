"""Deterministic demo detection semantics for expanded ATT&CK coverage."""

from __future__ import annotations

import json
from typing import Any


LOLBIN_DOWNLOAD_PROCESSES = {"certutil.exe", "bitsadmin.exe", "curl.exe", "powershell.exe"}
T1105_DOWNLOAD_MARKERS = (
    "urlcache",
    "bitsadmin",
    "Invoke-WebRequest",
    "iwr",
    "curl",
    "http://127.0.0.1",
    "example.test",
    "EDR_DEMO_T1105",
)
RUN_KEY_PATH_MARKERS = (
    r"\Software\Microsoft\Windows\CurrentVersion\Run",
    r"\Software\Microsoft\Windows\CurrentVersion\RunOnce",
)
T1547_DETAIL_MARKERS = ("powershell.exe", "cmd.exe", "rundll32.exe", "EDRDemo", "EDR_DEMO_T1547")
T1218_PROCESSES = {"rundll32.exe", "regsvr32.exe", "mshta.exe"}
T1218_MARKERS = (
    "EDR_DEMO_T1218",
    "javascript:",
    "scrobj.dll",
    "url.dll,FileProtocolHandler",
    "suspicious.dll",
    "example.test",
)


def match_t1105_lolbin_download(event: dict[str, Any]) -> tuple[bool, tuple[str, ...]]:
    """Match safe T1105 LOLBin download markers across process/network/file events."""

    process_name = _text(_get_field(event, "process.name")).casefold()
    command_line = _text(_get_field(event, "process.command_line"))
    event_data = _text(_get_field(event, "sysmon.event_data"))

    if _category_contains(event, "process") and process_name in LOLBIN_DOWNLOAD_PROCESSES:
        matched_fields = _matched_contains_fields(
            event,
            (
                ("process.command_line", T1105_DOWNLOAD_MARKERS),
            ),
        )
        if matched_fields:
            return True, matched_fields

    if _get_field(event, "event.code") == 3 and process_name in LOLBIN_DOWNLOAD_PROCESSES:
        destination_is_demo = _text(_get_field(event, "destination.ip")) == "127.0.0.1" or (
            _text(_get_field(event, "destination.domain")).casefold() == "example.test"
        )
        marker_available = command_line or event_data
        marker_matches = _contains_any(command_line, ("EDR_DEMO_T1105",)) or _contains_any(
            event_data,
            ("EDR_DEMO_T1105",),
        )
        if destination_is_demo and (not marker_available or marker_matches):
            fields = ["destination.ip" if _text(_get_field(event, "destination.ip")) == "127.0.0.1" else "destination.domain"]
            if marker_matches:
                if _contains_any(command_line, ("EDR_DEMO_T1105",)):
                    fields.append("process.command_line")
                if _contains_any(event_data, ("EDR_DEMO_T1105",)):
                    fields.append("sysmon.event_data")
            return True, tuple(fields)

    if _get_field(event, "event.code") == 11:
        file_path = _text(_get_field(event, "file.path"))
        file_name = _text(_get_field(event, "file.name"))
        marker_text = f"{file_path} {event_data}"
        if (
            _contains_any(file_path, ("Downloads",))
            and _contains_any(file_name, ("edr_demo",))
            and _contains_any(marker_text, ("EDR_DEMO_T1105", "edr_demo"))
        ):
            return True, ("file.path", "file.name")

    return False, ()


def match_t1547_registry_run_key(event: dict[str, Any]) -> tuple[bool, tuple[str, ...]]:
    """Match safe T1547.001 registry Run/RunOnce persistence markers."""

    if _get_field(event, "event.code") != 13 or not _category_contains(event, "registry"):
        return False, ()

    registry_path = _text(_get_field(event, "registry.path"))
    registry_value = _text(_get_field(event, "registry.value"))
    registry_data = _text(_get_field(event, "registry.data.strings"))
    event_details = _text(_get_field(event, "sysmon.event_data.Details"))

    if not registry_value:
        return False, ()
    if not _contains_any(registry_path, RUN_KEY_PATH_MARKERS):
        return False, ()
    if not _contains_any(f"{registry_data} {event_details}", T1547_DETAIL_MARKERS):
        return False, ()

    return True, ("registry.path", "registry.value", "registry.data.strings")


def match_t1218_lolbin_suspicious(event: dict[str, Any]) -> tuple[bool, tuple[str, ...]]:
    """Match safe T1218-lite LOLBin proxy execution markers."""

    process_name = _text(_get_field(event, "process.name")).casefold()
    command_line = _text(_get_field(event, "process.command_line"))

    if not _category_contains(event, "process") or process_name not in T1218_PROCESSES:
        return False, ()
    if not _contains_any(command_line, T1218_MARKERS):
        return False, ()

    return True, ("process.name", "process.command_line")


def _matched_contains_fields(event: dict[str, Any], checks: tuple[tuple[str, tuple[str, ...]], ...]) -> tuple[str, ...]:
    matched: list[str] = []
    for field, markers in checks:
        if _contains_any(_text(_get_field(event, field)), markers):
            matched.append(field)
    return tuple(matched)


def _category_contains(event: dict[str, Any], expected: str) -> bool:
    value = _get_field(event, "event.category")
    if isinstance(value, list):
        return any(isinstance(item, str) and item.casefold() == expected.casefold() for item in value)
    return expected.casefold() in _text(value).casefold()


def _contains_any(value: str, markers: tuple[str, ...]) -> bool:
    normalized_value = value.casefold()
    return any(marker.casefold() in normalized_value for marker in markers)


def _text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float, bool)):
        return str(value)
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True)
    return str(value)


def _get_field(event: dict[str, Any], field_path: str) -> Any:
    current: Any = event
    for part in field_path.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current
