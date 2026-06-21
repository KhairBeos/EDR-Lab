"""Index normalized ECS event documents into Elasticsearch."""

from __future__ import annotations

import hashlib
import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import UTC, date, datetime
from typing import Any


@dataclass(frozen=True)
class EventIndexingConfig:
    """Configuration for writing normalized events to Elasticsearch."""

    base_url: str = "http://localhost:9200"
    timeout_seconds: int = 10
    index_prefix: str = "edr-normalized-events"


@dataclass(frozen=True)
class EventIndexResult:
    """Result of indexing one normalized event."""

    index: str
    document_id: str
    result: str
    status: int


class EventIndexingError(RuntimeError):
    """Raised when normalized event indexing fails predictably."""


def build_event_index_name(index_date: date | str | None = None, prefix: str = "edr-normalized-events") -> str:
    """Build the daily normalized event index name."""

    if index_date is None:
        parsed_date = datetime.now(UTC).date()
    elif isinstance(index_date, date):
        parsed_date = index_date
    elif isinstance(index_date, str):
        try:
            parsed_date = date.fromisoformat(index_date)
        except ValueError as exc:
            raise EventIndexingError(f"Event index date must use YYYY-MM-DD format, got {index_date!r}.") from exc
    else:
        raise EventIndexingError(f"Event index date must be a date, string, or None, got {type(index_date).__name__}.")

    return f"{prefix}-{parsed_date:%Y.%m.%d}"


def build_event_document_id(event: dict[str, Any]) -> str:
    """Build a deterministic document ID for a normalized event."""

    if not isinstance(event, dict) or not event:
        raise EventIndexingError("Normalized event document must be a non-empty mapping.")

    event_id = event.get("event", {}).get("id") if isinstance(event.get("event"), dict) else None
    if isinstance(event_id, str) and event_id:
        return event_id

    sysmon_data = event.get("sysmon", {}).get("event_data") if isinstance(event.get("sysmon"), dict) else None
    process_guid = sysmon_data.get("ProcessGuid") if isinstance(sysmon_data, dict) else None
    if isinstance(process_guid, str) and process_guid:
        return process_guid

    material = {
        "dataset": _get_field(event, "event.dataset"),
        "event_code": _get_field(event, "event.code"),
        "event_created": _get_field(event, "event.created") or event.get("@timestamp"),
        "host_name": _get_field(event, "host.name"),
        "process_entity_id": _get_field(event, "process.entity_id"),
        "process_pid": _get_field(event, "process.pid"),
        "process_executable": _get_field(event, "process.executable"),
        "process_command_line": _get_field(event, "process.command_line"),
    }
    digest = hashlib.sha256(json.dumps(material, sort_keys=True).encode("utf-8")).hexdigest()[:32]
    return f"event-{digest}"


def index_event(
    event: dict[str, Any],
    config: EventIndexingConfig,
    *,
    index_date: date | str | None = None,
) -> EventIndexResult:
    """Index one normalized ECS event document."""

    document_id = build_event_document_id(event)
    index = build_event_index_name(index_date=index_date, prefix=config.index_prefix)
    url = _event_document_url(config=config, index=index, document_id=document_id)
    body = json.dumps(event).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="PUT",
    )

    try:
        with urllib.request.urlopen(request, timeout=config.timeout_seconds) as response:
            status = getattr(response, "status", response.getcode())
            payload = response.read()
    except (TimeoutError, urllib.error.URLError, OSError) as exc:
        raise EventIndexingError(f"Event indexing failed: {exc}") from exc

    if status not in {200, 201}:
        raise EventIndexingError(f"Event indexing failed with HTTP status {status}.")

    result = _parse_index_response(payload)
    return EventIndexResult(index=index, document_id=document_id, result=result, status=status)


def index_events(
    events: list[dict[str, Any]],
    config: EventIndexingConfig,
    *,
    index_date: date | str | None = None,
) -> list[EventIndexResult]:
    """Index multiple normalized ECS event documents."""

    return [index_event(event, config, index_date=index_date) for event in events]


def _event_document_url(*, config: EventIndexingConfig, index: str, document_id: str) -> str:
    base_url = config.base_url.rstrip("/")
    return f"{base_url}/{index}/_doc/{document_id}"


def _parse_index_response(payload: bytes) -> str:
    try:
        parsed = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EventIndexingError(f"Elasticsearch returned malformed JSON for event indexing: {exc}") from exc

    if not isinstance(parsed, dict):
        raise EventIndexingError("Elasticsearch event indexing response must be a JSON object.")

    result = parsed.get("result")
    if not isinstance(result, str) or not result:
        raise EventIndexingError("Elasticsearch event indexing response is missing result.")

    return result


def _get_field(event: dict[str, Any], field_path: str) -> Any:
    current: Any = event
    for part in field_path.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current
