"""Deterministic behavioral sequence definitions for the EDR demo."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from detection.rules.demo_semantics import (
    LOLBIN_DOWNLOAD_PROCESSES,
    RUN_KEY_PATH_MARKERS,
    T1105_DOWNLOAD_MARKERS,
    T1218_MARKERS,
    T1218_PROCESSES,
    T1547_DETAIL_MARKERS,
)


StepMatcher = Callable[[dict[str, Any]], bool]

T1547_PROCESS_MARKERS = ("EDR_DEMO_T1547", "Run", "RunOnce", "registry persistence", "EDRDemo")
T1547_PAYLOAD_MARKERS = ("EDR_DEMO_T1547", "EDRDemo")


@dataclass(frozen=True)
class SequenceDefinition:
    rule_id: str
    sequence_name: str
    technique_id: str
    technique_name: str
    tactic: tuple[str, ...]
    severity: str
    confidence: str
    required_steps: tuple[str, ...]
    optional_steps: tuple[str, ...] = ()
    window_seconds: int = 300


BEHAVIORAL_SEQUENCES: tuple[SequenceDefinition, ...] = (
    SequenceDefinition(
        rule_id="det.behavioral.t1105_download_sequence",
        sequence_name="t1105_download_sequence",
        technique_id="T1105",
        technique_name="Ingress Tool Transfer",
        tactic=("Command and Control",),
        severity="high",
        confidence="high",
        required_steps=("process", "network", "file"),
        window_seconds=300,
    ),
    SequenceDefinition(
        rule_id="det.behavioral.t1547_001_registry_persistence_sequence",
        sequence_name="t1547_001_registry_persistence_sequence",
        technique_id="T1547.001",
        technique_name="Registry Run Keys / Startup Folder",
        tactic=("Persistence",),
        severity="high",
        confidence="high",
        required_steps=("process", "registry"),
        optional_steps=("follow_up_process",),
        window_seconds=600,
    ),
    SequenceDefinition(
        rule_id="det.behavioral.t1218_lolbin_sequence",
        sequence_name="t1218_lolbin_sequence",
        technique_id="T1218",
        technique_name="System Binary Proxy Execution",
        tactic=("Defense Evasion",),
        severity="medium",
        confidence="medium",
        required_steps=("process",),
        optional_steps=("network", "child_or_file"),
        window_seconds=300,
    ),
)


SEQUENCE_STEP_MATCHERS: dict[str, dict[str, StepMatcher]] = {
    "det.behavioral.t1105_download_sequence": {
        "process": lambda event: _match_t1105_process(event),
        "network": lambda event: _match_t1105_network(event),
        "file": lambda event: _match_t1105_file(event),
    },
    "det.behavioral.t1547_001_registry_persistence_sequence": {
        "process": lambda event: _match_t1547_process(event),
        "registry": lambda event: _match_t1547_registry(event),
        "follow_up_process": lambda event: _match_t1547_follow_up_process(event),
    },
    "det.behavioral.t1218_lolbin_sequence": {
        "process": lambda event: _match_t1218_process(event),
        "network": lambda event: _match_t1218_network(event),
        "child_or_file": lambda event: _match_t1218_child_or_file(event),
    },
}


def match_step(definition: SequenceDefinition, step_name: str, event: dict[str, Any]) -> bool:
    """Return whether an event matches one named step in a sequence."""

    return SEQUENCE_STEP_MATCHERS[definition.rule_id][step_name](event)


def sequence_rule_metadata(definition: SequenceDefinition) -> dict[str, Any]:
    """Return rule-shaped metadata for reporting and alert construction."""

    readable_name = definition.sequence_name.replace("_", " ")
    return {
        "id": definition.rule_id,
        "version": 1,
        "name": f"{definition.technique_id} behavioral {readable_name}",
        "description": (
            f"Correlates {', '.join(definition.required_steps)} evidence for a deterministic "
            f"{definition.technique_id} demo sequence."
        ),
        "severity": definition.severity,
        "confidence": definition.confidence,
        "attack": {
            "technique_id": definition.technique_id,
            "technique_name": definition.technique_name,
            "tactic": list(definition.tactic),
        },
    }


def event_marker_tokens(event: dict[str, Any]) -> set[str]:
    """Extract explicit safe demo marker families from an event."""

    text = _event_text(event).casefold()
    markers: set[str] = set()
    for marker in ("EDR_DEMO_T1105", "EDR_DEMO_T1547", "EDR_DEMO_T1218", "EDRDemo"):
        if marker.casefold() in text:
            markers.add(marker.casefold())
    for marker in ("example.test", "edr_demo", "suspicious.dll", "scrobj.dll", "url.dll,FileProtocolHandler"):
        if marker.casefold() in text:
            markers.add(marker.casefold())
    return markers


def _match_t1105_process(event: dict[str, Any]) -> bool:
    process_name = _text(_get_field(event, "process.name")).casefold()
    marker_text = f"{_text(_get_field(event, 'process.command_line'))} {_text(_get_field(event, 'sysmon.event_data'))}"
    return (
        _category_contains(event, "process")
        and process_name in LOLBIN_DOWNLOAD_PROCESSES
        and _contains_any(marker_text, T1105_DOWNLOAD_MARKERS)
    )


def _match_t1105_network(event: dict[str, Any]) -> bool:
    destination_is_demo = _text(_get_field(event, "destination.ip")) == "127.0.0.1" or (
        _text(_get_field(event, "destination.domain")).casefold() == "example.test"
    )
    return _event_code(event) == "3" and destination_is_demo


def _match_t1105_file(event: dict[str, Any]) -> bool:
    file_path = _text(_get_field(event, "file.path"))
    file_name = _text(_get_field(event, "file.name"))
    marker_text = f"{file_path} {file_name} {_text(_get_field(event, 'sysmon.event_data'))}"
    return (
        _event_code(event) == "11"
        and _contains_any(file_path, ("Downloads",))
        and _contains_any(f"{file_name} {file_path}", ("edr_demo",))
        and _contains_any(marker_text, ("EDR_DEMO_T1105", "edr_demo"))
    )


def _match_t1547_process(event: dict[str, Any]) -> bool:
    process_name = _text(_get_field(event, "process.name")).casefold()
    marker_text = f"{_text(_get_field(event, 'process.command_line'))} {_text(_get_field(event, 'sysmon.event_data'))}"
    return (
        _category_contains(event, "process")
        and process_name in {"reg.exe", "powershell.exe"}
        and _contains_any(marker_text, T1547_PROCESS_MARKERS)
    )


def _match_t1547_registry(event: dict[str, Any]) -> bool:
    registry_path = _text(_get_field(event, "registry.path"))
    registry_data = _text(_get_field(event, "registry.data.strings"))
    details = _text(_get_field(event, "sysmon.event_data.Details"))
    event_data = _text(_get_field(event, "sysmon.event_data"))
    return (
        _event_code(event) == "13"
        and _category_contains(event, "registry")
        and _contains_any(registry_path, RUN_KEY_PATH_MARKERS)
        and _contains_any(f"{registry_data} {details} {event_data}", T1547_DETAIL_MARKERS)
    )


def _match_t1547_follow_up_process(event: dict[str, Any]) -> bool:
    marker_text = f"{_text(_get_field(event, 'process.command_line'))} {_text(_get_field(event, 'sysmon.event_data'))}"
    return _category_contains(event, "process") and _contains_any(marker_text, T1547_PAYLOAD_MARKERS)


def _match_t1218_process(event: dict[str, Any]) -> bool:
    process_name = _text(_get_field(event, "process.name")).casefold()
    marker_text = f"{_text(_get_field(event, 'process.command_line'))} {_text(_get_field(event, 'sysmon.event_data'))}"
    return (
        _category_contains(event, "process")
        and process_name in T1218_PROCESSES
        and _contains_any(marker_text, T1218_MARKERS)
    )


def _match_t1218_network(event: dict[str, Any]) -> bool:
    destination_is_demo = _text(_get_field(event, "destination.ip")) == "127.0.0.1" or (
        _text(_get_field(event, "destination.domain")).casefold() == "example.test"
    )
    return _event_code(event) == "3" and destination_is_demo


def _match_t1218_child_or_file(event: dict[str, Any]) -> bool:
    if not (_category_contains(event, "process") or _category_contains(event, "file") or _event_code(event) == "11"):
        return False
    return _contains_any(_event_text(event), T1218_MARKERS)


def _event_code(event: dict[str, Any]) -> str:
    value = _get_field(event, "event.code")
    if value is None:
        return ""
    return str(value)


def _category_contains(event: dict[str, Any], expected: str) -> bool:
    value = _get_field(event, "event.category")
    if isinstance(value, list):
        return any(isinstance(item, str) and item.casefold() == expected.casefold() for item in value)
    return expected.casefold() in _text(value).casefold()


def _contains_any(value: str, markers: tuple[str, ...]) -> bool:
    normalized_value = value.casefold()
    return any(marker.casefold() in normalized_value for marker in markers)


def _event_text(event: dict[str, Any]) -> str:
    return " ".join(
        _text(value)
        for value in (
            event.get("@timestamp"),
            _get_field(event, "event.created"),
            _get_field(event, "event.code"),
            _get_field(event, "process.name"),
            _get_field(event, "process.command_line"),
            _get_field(event, "file.path"),
            _get_field(event, "file.name"),
            _get_field(event, "registry.path"),
            _get_field(event, "registry.value"),
            _get_field(event, "registry.data.strings"),
            _get_field(event, "destination.ip"),
            _get_field(event, "destination.domain"),
            _get_field(event, "sysmon.event_data"),
        )
    )


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
