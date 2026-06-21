"""Extract deterministic process anomaly features from normalized Sysmon events."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any


ENCODED_COMMAND_FLAGS = ("-enc", "-encodedcommand", "/enc", "/encodedcommand")
NETWORK_TOOL_KEYWORDS = (
    "curl",
    "wget",
    "nc",
    "netcat",
    "invoke-webrequest",
    "iwr",
    "invoke-restmethod",
    "irm",
    "downloadstring",
    "webclient",
)


class ProcessFeatureExtractionError(ValueError):
    """Raised when a process event cannot be converted into ML features."""


def extract_process_features(event: dict[str, Any]) -> dict[str, Any]:
    """Extract JSON-compatible features from one normalized Sysmon Event ID 1 ECS document."""

    event_meta = _require_event_meta(event)
    process = _require_process(event)
    parent = process.get("parent") if isinstance(process.get("parent"), dict) else {}

    process_name = _optional_string(process.get("name"))
    executable = _optional_string(process.get("executable"))
    parent_name = _optional_string(parent.get("name"))
    command_line = _optional_string(process.get("command_line"))
    args = process.get("args")
    args_count = len(args) if isinstance(args, list) else 0
    lower_command_line = command_line.lower()
    matched_network_keywords = [
        keyword for keyword in NETWORK_TOOL_KEYWORDS if _contains_keyword(lower_command_line, keyword)
    ]

    return {
        "process_name": process_name,
        "process_executable": executable,
        "parent_process_name": parent_name,
        "process_command_line": command_line,
        "command_line_length": len(command_line),
        "args_count": args_count,
        "executable_directory_depth": _executable_directory_depth(executable),
        "has_encoded_command": _has_encoded_command(command_line),
        "has_network_tool_flag": bool(matched_network_keywords),
        "matched_network_keywords": matched_network_keywords,
        "hour_of_day": _extract_hour(event, event_meta),
    }


def _require_event_meta(event: dict[str, Any]) -> dict[str, Any]:
    event_meta = event.get("event")
    if not isinstance(event_meta, dict):
        raise ProcessFeatureExtractionError("Normalized event must contain event metadata.")

    dataset = event_meta.get("dataset")
    if dataset != "windows.sysmon_operational":
        raise ProcessFeatureExtractionError(
            "Normalized event must have event.dataset = 'windows.sysmon_operational'."
        )

    code = event_meta.get("code")
    if code not in {1, "1"}:
        raise ProcessFeatureExtractionError("Normalized event must be Sysmon Event ID 1.")

    return event_meta


def _require_process(event: dict[str, Any]) -> dict[str, Any]:
    process = event.get("process")
    if not isinstance(process, dict):
        raise ProcessFeatureExtractionError("Normalized event must contain a process object.")
    return process


def _optional_string(value: Any) -> str:
    return value if isinstance(value, str) else ""


def _has_encoded_command(command_line: str) -> bool:
    tokens = [token.strip("\"'").lower() for token in re.split(r"\s+", command_line) if token]
    return any(token in ENCODED_COMMAND_FLAGS for token in tokens)


def _contains_keyword(text: str, keyword: str) -> bool:
    if keyword in {"nc", "iwr", "irm"}:
        return re.search(rf"(?<![a-z0-9_-]){re.escape(keyword)}(?![a-z0-9_-])", text) is not None
    return keyword in text


def _executable_directory_depth(executable: str) -> int:
    if not executable:
        return 0
    normalized = executable.replace("/", "\\")
    directory, separator, _ = normalized.rpartition("\\")
    if not separator or not directory:
        return 0
    return len([part for part in directory.split("\\") if part and not part.endswith(":")])


def _extract_hour(event: dict[str, Any], event_meta: dict[str, Any]) -> int | None:
    timestamp = event_meta.get("created") or event.get("@timestamp")
    if not isinstance(timestamp, str) or not timestamp:
        return None
    return _parse_timestamp_hour(timestamp)


def _parse_timestamp_hour(value: str) -> int:
    normalized = value.strip().replace("Z", "+00:00")
    normalized = re.sub(r"(\.\d{6})\d+(?=[+-])", r"\1", normalized)
    try:
        return datetime.fromisoformat(normalized).hour
    except ValueError as exc:
        raise ProcessFeatureExtractionError(f"Could not parse event timestamp hour from {value!r}.") from exc
