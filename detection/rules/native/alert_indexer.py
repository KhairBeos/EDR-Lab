"""Index native detection alert documents into Elasticsearch."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import UTC, date, datetime
from typing import Any


@dataclass(frozen=True)
class AlertIndexingConfig:
    """Configuration for writing native alert documents to Elasticsearch."""

    base_url: str = "http://localhost:9200"
    timeout_seconds: int = 10
    index_prefix: str = "edr-alerts-native"


@dataclass(frozen=True)
class AlertIndexResult:
    """Result of indexing one alert document."""

    index: str
    document_id: str
    result: str
    status: int


class AlertIndexingError(RuntimeError):
    """Raised when native alert indexing fails predictably."""


def build_alert_index_name(index_date: date | str | None = None, prefix: str = "edr-alerts-native") -> str:
    """Build the daily native alert index name."""

    if index_date is None:
        parsed_date = datetime.now(UTC).date()
    elif isinstance(index_date, date):
        parsed_date = index_date
    elif isinstance(index_date, str):
        try:
            parsed_date = date.fromisoformat(index_date)
        except ValueError as exc:
            raise AlertIndexingError(f"Alert index date must use YYYY-MM-DD format, got {index_date!r}.") from exc
    else:
        raise AlertIndexingError(f"Alert index date must be a date, string, or None, got {type(index_date).__name__}.")

    return f"{prefix}-{parsed_date:%Y.%m.%d}"


def index_alert(
    alert: dict[str, Any],
    config: AlertIndexingConfig,
    *,
    index_date: date | str | None = None,
) -> AlertIndexResult:
    """Index one alert document using alert.alert.id as the document ID."""

    document_id = _alert_document_id(alert)
    index = build_alert_index_name(index_date=index_date, prefix=config.index_prefix)
    url = _alert_document_url(config=config, index=index, document_id=document_id)
    body = json.dumps(alert).encode("utf-8")
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
        raise AlertIndexingError(f"Alert indexing failed: {exc}") from exc

    if status not in {200, 201}:
        raise AlertIndexingError(f"Alert indexing failed with HTTP status {status}.")

    result = _parse_index_response(payload)
    return AlertIndexResult(index=index, document_id=document_id, result=result, status=status)


def index_alerts(
    alerts: list[dict[str, Any]],
    config: AlertIndexingConfig,
    *,
    index_date: date | str | None = None,
) -> list[AlertIndexResult]:
    """Index multiple alert documents."""

    return [index_alert(alert, config, index_date=index_date) for alert in alerts]


def _alert_document_id(alert: dict[str, Any]) -> str:
    alert_meta = alert.get("alert")
    if not isinstance(alert_meta, dict):
        raise AlertIndexingError("Alert document must contain alert metadata.")

    document_id = alert_meta.get("id")
    if not isinstance(document_id, str) or not document_id:
        raise AlertIndexingError("Alert document must contain non-empty alert.id.")

    return document_id


def _alert_document_url(*, config: AlertIndexingConfig, index: str, document_id: str) -> str:
    base_url = config.base_url.rstrip("/")
    return f"{base_url}/{index}/_doc/{document_id}"


def _parse_index_response(payload: bytes) -> str:
    try:
        parsed = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AlertIndexingError(f"Elasticsearch returned malformed JSON for alert indexing: {exc}") from exc

    if not isinstance(parsed, dict):
        raise AlertIndexingError("Elasticsearch alert indexing response must be a JSON object.")

    result = parsed.get("result")
    if not isinstance(result, str) or not result:
        raise AlertIndexingError("Elasticsearch alert indexing response is missing result.")

    return result
