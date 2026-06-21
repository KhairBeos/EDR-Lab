"""Index dry-run SOAR response records into Elasticsearch."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import UTC, date, datetime
from typing import Any


@dataclass(frozen=True)
class ResponseIndexingConfig:
    """Configuration for writing SOAR response records to Elasticsearch."""

    base_url: str = "http://localhost:9200"
    timeout_seconds: int = 10
    index_prefix: str = "edr-response-actions"


@dataclass(frozen=True)
class ResponseIndexResult:
    """Result of indexing one SOAR response record."""

    index: str
    document_id: str
    result: str
    status: int


class ResponseIndexingError(RuntimeError):
    """Raised when SOAR response indexing fails predictably."""


def build_response_index_name(index_date: date | str | None = None, prefix: str = "edr-response-actions") -> str:
    """Build the daily SOAR response action index name."""

    if index_date is None:
        parsed_date = datetime.now(UTC).date()
    elif isinstance(index_date, date):
        parsed_date = index_date
    elif isinstance(index_date, str):
        try:
            parsed_date = date.fromisoformat(index_date)
        except ValueError as exc:
            raise ResponseIndexingError(
                f"Response index date must use YYYY-MM-DD format, got {index_date!r}."
            ) from exc
    else:
        raise ResponseIndexingError(
            f"Response index date must be a date, string, or None, got {type(index_date).__name__}."
        )

    return f"{prefix}-{parsed_date:%Y.%m.%d}"


def index_response(
    response_record: dict[str, Any],
    config: ResponseIndexingConfig,
    *,
    index_date: date | str | None = None,
) -> ResponseIndexResult:
    """Index one response record using response.response.id as document ID."""

    document_id = _response_document_id(response_record)
    index = build_response_index_name(index_date=index_date, prefix=config.index_prefix)
    url = _response_document_url(config=config, index=index, document_id=document_id)
    body = json.dumps(response_record).encode("utf-8")
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
        raise ResponseIndexingError(f"Response indexing failed: {exc}") from exc

    if status not in {200, 201}:
        raise ResponseIndexingError(f"Response indexing failed with HTTP status {status}.")

    result = _parse_index_response(payload)
    return ResponseIndexResult(index=index, document_id=document_id, result=result, status=status)


def index_responses(
    response_records: list[dict[str, Any]],
    config: ResponseIndexingConfig,
    *,
    index_date: date | str | None = None,
) -> list[ResponseIndexResult]:
    """Index multiple SOAR response records."""

    return [index_response(record, config, index_date=index_date) for record in response_records]


def _response_document_id(response_record: dict[str, Any]) -> str:
    response_meta = response_record.get("response")
    if not isinstance(response_meta, dict):
        raise ResponseIndexingError("Response record must contain response metadata.")

    document_id = response_meta.get("id")
    if not isinstance(document_id, str) or not document_id:
        raise ResponseIndexingError("Response record must contain non-empty response.id.")

    return document_id


def _response_document_url(*, config: ResponseIndexingConfig, index: str, document_id: str) -> str:
    base_url = config.base_url.rstrip("/")
    return f"{base_url}/{index}/_doc/{document_id}"


def _parse_index_response(payload: bytes) -> str:
    try:
        parsed = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ResponseIndexingError(f"Elasticsearch returned malformed JSON for response indexing: {exc}") from exc

    if not isinstance(parsed, dict):
        raise ResponseIndexingError("Elasticsearch response indexing response must be a JSON object.")

    result = parsed.get("result")
    if not isinstance(result, str) or not result:
        raise ResponseIndexingError("Elasticsearch response indexing response is missing result.")

    return result
