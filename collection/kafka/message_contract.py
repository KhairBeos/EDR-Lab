"""Kafka message contract for normalized ECS events."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any


SCHEMA_VERSION = "1.0"
DEFAULT_PRODUCER = "edr-live-telemetry-pipeline"
PIPELINE_PHASE = "phase-4-kafka-mvp"
SUPPORTED_SOURCES = {"fixture", "xml"}
SYSMON_DATASET = "windows.sysmon_operational"
SYSMON_PROCESS_CREATE_EVENT_CODE = 1


class KafkaMessageContractError(ValueError):
    """Raised when a normalized event Kafka message is malformed."""


def build_normalized_event_message(
    event: dict[str, Any],
    source: str,
    event_id: str | None = None,
    created_at: str | datetime | None = None,
) -> dict[str, Any]:
    """Build and validate a Kafka message for one normalized ECS event."""

    message = {
        "schema_version": SCHEMA_VERSION,
        "event_id": event_id or _derive_event_id(event),
        "event": event,
        "metadata": {
            "producer": DEFAULT_PRODUCER,
            "created_at": _format_created_at(created_at),
            "source": source,
            "pipeline_phase": PIPELINE_PHASE,
        },
    }
    validate_normalized_event_message(message)
    return message


def validate_normalized_event_message(message: dict[str, Any]) -> None:
    """Validate the Phase 4 normalized event Kafka message contract."""

    if not isinstance(message, dict):
        raise KafkaMessageContractError("Kafka message must be a JSON object.")

    schema_version = message.get("schema_version")
    if schema_version != SCHEMA_VERSION:
        raise KafkaMessageContractError(
            f"schema_version must be exactly {SCHEMA_VERSION!r}, got {schema_version!r}."
        )

    event_id = message.get("event_id")
    if not isinstance(event_id, str) or not event_id:
        raise KafkaMessageContractError("event_id is required and must be a non-empty string.")

    event = message.get("event")
    if not isinstance(event, dict):
        raise KafkaMessageContractError("event is required and must be a normalized ECS event object.")

    metadata = message.get("metadata")
    if not isinstance(metadata, dict):
        raise KafkaMessageContractError("metadata is required and must be an object.")

    event_meta = event.get("event")
    if not isinstance(event_meta, dict):
        raise KafkaMessageContractError("event.event is required and must be an object.")

    dataset = event_meta.get("dataset")
    if dataset != SYSMON_DATASET:
        raise KafkaMessageContractError(f"event.event.dataset must be {SYSMON_DATASET!r}, got {dataset!r}.")

    event_code = event_meta.get("code")
    if event_code not in {SYSMON_PROCESS_CREATE_EVENT_CODE, str(SYSMON_PROCESS_CREATE_EVENT_CODE)}:
        raise KafkaMessageContractError("event.event.code must be Sysmon Event ID 1.")

    producer = metadata.get("producer")
    if producer != DEFAULT_PRODUCER:
        raise KafkaMessageContractError(f"metadata.producer must be {DEFAULT_PRODUCER!r}, got {producer!r}.")

    source = metadata.get("source")
    if source not in SUPPORTED_SOURCES:
        raise KafkaMessageContractError(f"metadata.source must be one of {sorted(SUPPORTED_SOURCES)}, got {source!r}.")

    pipeline_phase = metadata.get("pipeline_phase")
    if pipeline_phase != PIPELINE_PHASE:
        raise KafkaMessageContractError(
            f"metadata.pipeline_phase must be {PIPELINE_PHASE!r}, got {pipeline_phase!r}."
        )

    created_at = metadata.get("created_at")
    if not isinstance(created_at, str) or not created_at:
        raise KafkaMessageContractError("metadata.created_at is required and must be a non-empty string.")


def serialize_message(message: dict[str, Any]) -> bytes:
    """Validate and serialize a normalized event Kafka message to JSON bytes."""

    validate_normalized_event_message(message)
    return json.dumps(message, sort_keys=True, separators=(",", ":")).encode("utf-8")


def deserialize_message(payload: bytes) -> dict[str, Any]:
    """Deserialize JSON bytes and validate the normalized event Kafka message."""

    try:
        parsed = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise KafkaMessageContractError(f"Kafka message payload must be valid UTF-8 JSON: {exc}") from exc

    if not isinstance(parsed, dict):
        raise KafkaMessageContractError("Kafka message payload must decode to a JSON object.")

    validate_normalized_event_message(parsed)
    return parsed


def _derive_event_id(event: dict[str, Any]) -> str:
    explicit_event_id = _get_field(event, "event.id")
    if isinstance(explicit_event_id, str) and explicit_event_id:
        return explicit_event_id

    process_guid = _get_field(event, "sysmon.event_data.ProcessGuid")
    if isinstance(process_guid, str) and process_guid:
        return process_guid

    process_entity_id = _get_field(event, "process.entity_id")
    if isinstance(process_entity_id, str) and process_entity_id:
        return process_entity_id

    raise KafkaMessageContractError("event_id is required when normalized event has no stable event.id or ProcessGuid.")


def _format_created_at(created_at: str | datetime | None) -> str:
    if created_at is None:
        return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")

    if isinstance(created_at, str):
        return created_at

    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=UTC)

    return created_at.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _get_field(event: dict[str, Any], field_path: str) -> Any:
    current: Any = event
    for part in field_path.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current
