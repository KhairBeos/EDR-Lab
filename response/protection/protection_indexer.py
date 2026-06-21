"""Index protection action records into Elasticsearch."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import UTC, date, datetime
from typing import Any


@dataclass(frozen=True)
class ProtectionIndexingConfig:
    """Configuration for writing protection action records to Elasticsearch."""

    base_url: str = "http://localhost:9200"
    timeout_seconds: int = 10
    index_prefix: str = "edr-protection-actions"


@dataclass(frozen=True)
class ProtectionIndexResult:
    """Result of indexing one protection action record."""

    index: str
    document_id: str
    result: str
    status: int


class ProtectionIndexingError(RuntimeError):
    """Raised when protection action indexing fails predictably."""


def build_protection_index_name(
    index_date: date | str | None = None,
    prefix: str = "edr-protection-actions",
) -> str:
    """Build the daily protection action index name."""

    if index_date is None:
        parsed_date = datetime.now(UTC).date()
    elif isinstance(index_date, date):
        parsed_date = index_date
    elif isinstance(index_date, str):
        try:
            parsed_date = date.fromisoformat(index_date)
        except ValueError as exc:
            raise ProtectionIndexingError(
                f"Protection index date must use YYYY-MM-DD format, got {index_date!r}."
            ) from exc
    else:
        raise ProtectionIndexingError(
            f"Protection index date must be a date, string, or None, got {type(index_date).__name__}."
        )
    return f"{prefix}-{parsed_date:%Y.%m.%d}"


def index_protection_record(
    protection_record: dict[str, Any],
    config: ProtectionIndexingConfig,
    *,
    index_date: date | str | None = None,
) -> ProtectionIndexResult:
    """Index one protection record using protection.protection.id as document ID."""

    document_id = _protection_document_id(protection_record)
    index = build_protection_index_name(index_date=index_date, prefix=config.index_prefix)
    url = _protection_document_url(config=config, index=index, document_id=document_id)
    body = json.dumps(protection_record).encode("utf-8")
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
        raise ProtectionIndexingError(f"Protection indexing failed: {exc}") from exc

    if status not in {200, 201}:
        raise ProtectionIndexingError(f"Protection indexing failed with HTTP status {status}.")

    result = _parse_index_response(payload)
    return ProtectionIndexResult(index=index, document_id=document_id, result=result, status=status)


def index_protection_records(
    protection_records: list[dict[str, Any]],
    config: ProtectionIndexingConfig,
    *,
    index_date: date | str | None = None,
) -> list[ProtectionIndexResult]:
    """Index multiple protection action records."""

    return [index_protection_record(record, config, index_date=index_date) for record in protection_records]


def _protection_document_id(protection_record: dict[str, Any]) -> str:
    protection = protection_record.get("protection")
    if not isinstance(protection, dict):
        raise ProtectionIndexingError("Protection record must contain protection metadata.")
    document_id = protection.get("id")
    if not isinstance(document_id, str) or not document_id:
        raise ProtectionIndexingError("Protection record must contain non-empty protection.id.")
    return document_id


def _protection_document_url(*, config: ProtectionIndexingConfig, index: str, document_id: str) -> str:
    return f"{config.base_url.rstrip('/')}/{index}/_doc/{document_id}"


def _parse_index_response(payload: bytes) -> str:
    try:
        parsed = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtectionIndexingError(f"Elasticsearch returned malformed JSON for protection indexing: {exc}") from exc
    if not isinstance(parsed, dict):
        raise ProtectionIndexingError("Elasticsearch protection indexing response must be a JSON object.")
    result = parsed.get("result")
    if not isinstance(result, str) or not result:
        raise ProtectionIndexingError("Elasticsearch protection indexing response is missing result.")
    return result
