"""Build alert documents for behavioral sequence detections."""

from __future__ import annotations

import copy
import hashlib
import json
from typing import Any

from detection.behavioral.sequences import SequenceDefinition, sequence_rule_metadata


def build_behavioral_alert(
    *,
    definition: SequenceDefinition,
    events: list[dict[str, Any]],
    sequence_steps: list[str],
    sequence_index: int,
) -> dict[str, Any]:
    """Build a deterministic behavioral alert for one correlated event sequence."""

    rule = sequence_rule_metadata(definition)
    document_ids = [
        _event_document_id(event=event, sequence_index=sequence_index, event_index=index)
        for index, event in enumerate(events)
    ]
    created_at = _latest_event_timestamp(events)
    host = _first_mapping(events, "host")
    process = _representative_process(events)

    alert = {
        "alert": {
            "id": _build_alert_id(
                definition=definition,
                document_ids=document_ids,
                host_name=host.get("name"),
                process=process,
                sequence_steps=sequence_steps,
                created_at=created_at,
            ),
            "kind": "signal",
            "status": "open",
            "severity": definition.severity,
            "confidence": definition.confidence,
            "created": created_at,
        },
        "rule": {
            "id": rule["id"],
            "name": rule["name"],
            "version": rule["version"],
            "description": rule["description"],
        },
        "detection": {
            "engine": "behavioral",
            "sequence_name": definition.sequence_name,
            "sequence_steps": list(sequence_steps),
            "correlated_event_count": len(events),
        },
        "attack": {
            "technique": {
                "id": definition.technique_id,
                "name": definition.technique_name,
            },
            "tactic": list(definition.tactic),
        },
        "host": host,
        "process": process,
        "source": {
            "document_ids": document_ids,
        },
    }
    return _omit_empty(alert)


def _build_alert_id(
    *,
    definition: SequenceDefinition,
    document_ids: list[str],
    host_name: Any,
    process: dict[str, Any],
    sequence_steps: list[str],
    created_at: str,
) -> str:
    material = {
        "rule_id": definition.rule_id,
        "sequence_name": definition.sequence_name,
        "document_ids": document_ids,
        "host_name": host_name,
        "process": _process_identity(process),
        "sequence_steps": sequence_steps,
        "created_at": created_at,
    }
    digest = hashlib.sha256(json.dumps(material, sort_keys=True).encode("utf-8")).hexdigest()[:16]
    return f"{definition.rule_id.replace('.', '-').replace('_', '-')}-{digest}"


def _event_document_id(*, event: dict[str, Any], sequence_index: int, event_index: int) -> str:
    existing = (
        event.get("_id")
        or event.get("document_id")
        or _get_field(event, "event.id")
        or _get_field(event, "source.document_id")
    )
    if isinstance(existing, str) and existing:
        return existing

    material = {
        "timestamp": event.get("@timestamp") or _get_field(event, "event.created"),
        "event_code": _get_field(event, "event.code"),
        "host_name": _get_field(event, "host.name"),
        "process": _process_identity(_copy_mapping(event.get("process"))),
        "sequence_index": sequence_index,
        "event_index": event_index,
    }
    digest = hashlib.sha256(json.dumps(material, sort_keys=True).encode("utf-8")).hexdigest()[:16]
    return f"local-{digest}"


def _latest_event_timestamp(events: list[dict[str, Any]]) -> str:
    timestamps = [_timestamp_text(event) for event in events if _timestamp_text(event)]
    if not timestamps:
        return "1970-01-01T00:00:00Z"
    return max(timestamps)


def _timestamp_text(event: dict[str, Any]) -> str:
    value = event.get("@timestamp") or _get_field(event, "event.created")
    return value if isinstance(value, str) else ""


def _first_mapping(events: list[dict[str, Any]], key: str) -> dict[str, Any]:
    for event in events:
        value = event.get(key)
        if isinstance(value, dict) and value:
            return copy.deepcopy(value)
    return {}


def _representative_process(events: list[dict[str, Any]]) -> dict[str, Any]:
    for event in events:
        process = event.get("process")
        if not isinstance(process, dict) or not process:
            continue
        return _selected_process_fields(process)
    return {}


def _selected_process_fields(process: dict[str, Any]) -> dict[str, Any]:
    return {
        "pid": process.get("pid"),
        "entity_id": process.get("entity_id"),
        "name": process.get("name"),
        "executable": process.get("executable"),
        "command_line": process.get("command_line"),
        "parent": _selected_parent_process_fields(process.get("parent")),
    }


def _selected_parent_process_fields(parent: Any) -> dict[str, Any]:
    if not isinstance(parent, dict):
        return {}
    return {
        "pid": parent.get("pid"),
        "entity_id": parent.get("entity_id"),
        "name": parent.get("name"),
        "executable": parent.get("executable"),
        "command_line": parent.get("command_line"),
    }


def _process_identity(process: dict[str, Any]) -> dict[str, Any]:
    return {
        "entity_id": process.get("entity_id"),
        "pid": process.get("pid"),
        "name": process.get("name"),
    }


def _copy_mapping(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    return copy.deepcopy(value)


def _omit_empty(value: Any) -> Any:
    if isinstance(value, dict):
        cleaned = {key: _omit_empty(child) for key, child in value.items()}
        return {
            key: child
            for key, child in cleaned.items()
            if child is not None and child != {} and child != []
        }
    if isinstance(value, list):
        return [_omit_empty(item) for item in value if item is not None]
    return value


def _get_field(event: dict[str, Any], field_path: str) -> Any:
    current: Any = event
    for part in field_path.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current
