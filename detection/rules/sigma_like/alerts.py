"""Build alert documents from Sigma-like rule matches."""

from __future__ import annotations

import copy
import hashlib
import json
from datetime import UTC, datetime
from typing import Any

from detection.rules.sigma_like.evaluator import SigmaLikeMatchResult
from detection.rules.sigma_like.loader import validate_sigma_like_rule


class SigmaLikeAlertError(ValueError):
    """Raised when a Sigma-like alert document cannot be built."""


def build_sigma_like_alert_document(
    *,
    match: SigmaLikeMatchResult,
    rule: dict[str, Any],
    event: dict[str, Any],
    created_at: datetime | str | None = None,
    source: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Build a JSON-compatible alert document from one Sigma-like match."""

    if not match.matched:
        raise SigmaLikeAlertError(f"Cannot build Sigma-like alert for non-matching rule {match.rule_id!r}.")

    validate_sigma_like_rule(rule)
    title = rule.get("title") or rule.get("name")

    alert = {
        "alert": {
            "id": _build_alert_id(rule=rule, event=event, source=source),
            "kind": "signal",
            "status": "open",
            "created": _format_created_at(created_at),
            "severity": rule["level"],
            "confidence": rule["confidence"],
        },
        "rule": {
            "id": rule["id"],
            "name": title,
            "version": 1,
            "description": rule["description"],
        },
        "attack": {
            "technique": {
                "id": rule["attack"]["technique_id"],
                "name": rule["attack"]["technique_name"],
            },
            "tactic": copy.deepcopy(rule["attack"]["tactic"]),
        },
        "event": _selected_event_fields(event),
        "host": _copy_mapping(event.get("host")),
        "user": _copy_mapping(event.get("user")),
        "process": _selected_process_fields(event.get("process")),
        "file": _copy_mapping(event.get("file")),
        "registry": _copy_mapping(event.get("registry")),
        "destination": _copy_mapping(event.get("destination")),
        "network": _selected_network_fields(event.get("network")),
        "detection": {
            "engine": "sigma-like",
            "matched_fields": list(match.matched_fields),
        },
        "source": _selected_source_fields(source),
        "art": _copy_mapping(event.get("art")),
    }

    return _omit_empty(alert)


def _build_alert_id(*, rule: dict[str, Any], event: dict[str, Any], source: dict[str, str] | None) -> str:
    material = {
        "engine": "sigma-like",
        "rule_id": rule.get("id"),
        "dataset": _get_field(event, "event.dataset"),
        "event_code": _get_field(event, "event.code"),
        "event_created": _get_field(event, "event.created") or event.get("@timestamp"),
        "host_name": _get_field(event, "host.name"),
        "process_entity_id": _get_field(event, "process.entity_id"),
        "process_pid": _get_field(event, "process.pid"),
        "process_executable": _get_field(event, "process.executable"),
        "process_command_line": _get_field(event, "process.command_line"),
        "source_document_id": (source or {}).get("document_id"),
    }
    digest = hashlib.sha256(json.dumps(material, sort_keys=True).encode("utf-8")).hexdigest()[:16]
    return f"{_alert_id_prefix(rule)}-{digest}"


def _format_created_at(created_at: datetime | str | None) -> str:
    if created_at is None:
        return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")

    if isinstance(created_at, str):
        return created_at

    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=UTC)

    return created_at.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _selected_event_fields(event: dict[str, Any]) -> dict[str, Any]:
    event_meta = event.get("event")
    if not isinstance(event_meta, dict):
        raise SigmaLikeAlertError("Matched ECS event must contain an event mapping.")

    return {
        "dataset": event_meta.get("dataset"),
        "code": event_meta.get("code"),
        "kind": event_meta.get("kind"),
        "category": copy.deepcopy(event_meta.get("category")),
        "type": copy.deepcopy(event_meta.get("type")),
        "created": event_meta.get("created"),
    }


def _selected_process_fields(process: Any) -> dict[str, Any]:
    if not isinstance(process, dict):
        return {}

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


def _selected_network_fields(network: Any) -> dict[str, Any]:
    if not isinstance(network, dict):
        return {}

    return {
        "transport": network.get("transport"),
        "direction": network.get("direction"),
    }


def _selected_source_fields(source: dict[str, str] | None) -> dict[str, str]:
    if not source:
        return {}
    return {
        "index": source.get("index"),
        "document_id": source.get("document_id"),
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


def _alert_id_prefix(rule: dict[str, Any]) -> str:
    rule_id = str(rule.get("id", "sigma-like-alert"))
    if rule_id == "sigma_like.t1059_001.powershell_process_start":
        return "det-sigma-like-t1059-001-powershell-process-start"
    return f"det-{rule_id.replace('_', '-').replace('.', '-')}"
