"""Build alert documents from ML-style process anomaly scores."""

from __future__ import annotations

import copy
import hashlib
import json
from datetime import UTC, datetime
from typing import Any


class ProcessAnomalyAlertError(ValueError):
    """Raised when an ML anomaly alert cannot be built."""


def build_process_anomaly_alert(
    event: dict[str, Any],
    features: dict[str, Any],
    score_result: dict[str, Any],
    created_at: datetime | str | None = None,
    source: dict[str, str] | None = None,
) -> dict[str, Any] | None:
    """Build an index-compatible anomaly alert, or None when below threshold."""

    if not bool(score_result.get("is_anomaly")):
        return None

    if score_result.get("score", 0) < score_result.get("threshold", 0):
        return None

    event_meta = event.get("event")
    if not isinstance(event_meta, dict):
        raise ProcessAnomalyAlertError("Anomaly alert event must contain event metadata.")

    process = event.get("process")
    if not isinstance(process, dict):
        raise ProcessAnomalyAlertError("Anomaly alert event must contain process metadata.")

    alert = {
        "alert": {
            "id": _build_alert_id(event=event, features=features, score_result=score_result, source=source),
            "kind": "signal",
            "status": "open",
            "created": _format_created_at(created_at),
            "severity": "medium",
            "confidence": "medium",
        },
        "rule": {
            "id": "ml.process_anomaly",
            "name": "ML-style Process Anomaly",
            "version": 1,
            "description": "Deterministic heuristic anomaly detection for process creation events.",
        },
        "event": _selected_event_fields(event_meta),
        "process": copy.deepcopy(process),
        "host": _copy_mapping(event.get("host")),
        "user": _copy_mapping(event.get("user")),
        "detection": {
            "engine": "ml-anomaly",
        },
        "ml": {
            "score": score_result["score"],
            "threshold": score_result["threshold"],
            "features": copy.deepcopy(features),
            "reasons": list(score_result.get("reasons", [])),
        },
        "source": _selected_source_fields(source),
    }

    return _omit_empty(alert)


def _build_alert_id(
    *,
    event: dict[str, Any],
    features: dict[str, Any],
    score_result: dict[str, Any],
    source: dict[str, str] | None,
) -> str:
    material = {
        "event_created": _get_field(event, "event.created") or event.get("@timestamp"),
        "host_name": _get_field(event, "host.name"),
        "process_entity_id": _get_field(event, "process.entity_id"),
        "process_pid": _get_field(event, "process.pid"),
        "process_executable": _get_field(event, "process.executable"),
        "process_command_line": _get_field(event, "process.command_line"),
        "source_document_id": (source or {}).get("document_id"),
        "features": features,
        "score": score_result.get("score"),
        "reasons": score_result.get("reasons", []),
    }
    digest = hashlib.sha256(json.dumps(material, sort_keys=True).encode("utf-8")).hexdigest()[:16]
    return f"det-ml-anomaly-process-{digest}"


def _format_created_at(created_at: datetime | str | None) -> str:
    if created_at is None:
        return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    if isinstance(created_at, str):
        return created_at
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=UTC)
    return created_at.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _selected_event_fields(event_meta: dict[str, Any]) -> dict[str, Any]:
    return {
        "dataset": event_meta.get("dataset"),
        "code": event_meta.get("code"),
        "kind": event_meta.get("kind"),
        "category": copy.deepcopy(event_meta.get("category")),
        "type": copy.deepcopy(event_meta.get("type")),
        "created": event_meta.get("created"),
    }


def _selected_source_fields(source: dict[str, str] | None) -> dict[str, str]:
    if not source:
        return {}
    return {
        "index": source.get("index"),
        "document_id": source.get("document_id"),
    }


def _copy_mapping(value: Any) -> dict[str, Any]:
    return copy.deepcopy(value) if isinstance(value, dict) else {}


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
