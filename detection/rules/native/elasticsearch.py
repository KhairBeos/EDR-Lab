"""Read normalized PowerShell detection candidates from Elasticsearch."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ElasticsearchConfig:
    """Configuration for the local Elasticsearch detection query seam."""

    base_url: str = "http://localhost:9200"
    index_pattern: str = "edr-raw-events-*"
    timeout_seconds: int = 10
    size: int = 100


@dataclass(frozen=True)
class SearchCandidate:
    """One normalized event candidate plus its Elasticsearch source identity."""

    event: dict[str, Any]
    source: dict[str, str]


class ElasticsearchQueryError(RuntimeError):
    """Raised when Elasticsearch candidate search fails predictably."""


def build_powershell_candidate_query(size: int = 100) -> dict[str, Any]:
    """Build the query DSL for normalized Sysmon Event ID 1 PowerShell candidates."""

    return {
        "size": size,
        "sort": [
            {
                "@timestamp": {
                    "order": "desc",
                    "unmapped_type": "date",
                },
            },
        ],
        "query": {
            "bool": {
                "filter": [
                    {
                        "term": {
                            "event.dataset": "windows.sysmon_operational",
                        },
                    },
                    {
                        "term": {
                            "event.code": 1,
                        },
                    },
                ],
                "should": [
                    {
                        "term": {
                            "process.name": "powershell.exe",
                        },
                    },
                    {
                        "wildcard": {
                            "process.executable": {
                                "value": "*\\powershell.exe",
                                "case_insensitive": True,
                            },
                        },
                    },
                    {
                        "wildcard": {
                            "process.command_line": {
                                "value": "*powershell.exe*",
                                "case_insensitive": True,
                            },
                        },
                    },
                ],
                "minimum_should_match": 1,
            },
        },
    }


def parse_search_hits(response: dict[str, Any]) -> list[SearchCandidate]:
    """Convert an Elasticsearch search response into native search candidates."""

    try:
        hits = response["hits"]["hits"]
    except KeyError as exc:
        raise ElasticsearchQueryError("Malformed Elasticsearch response: missing hits.hits.") from exc

    if not isinstance(hits, list):
        raise ElasticsearchQueryError("Malformed Elasticsearch response: hits.hits must be a list.")

    candidates: list[SearchCandidate] = []
    for index, hit in enumerate(hits):
        if not isinstance(hit, dict):
            raise ElasticsearchQueryError(f"Malformed Elasticsearch response: hits.hits[{index}] must be a mapping.")

        source_event = hit.get("_source")
        if not isinstance(source_event, dict):
            raise ElasticsearchQueryError(f"Malformed Elasticsearch response: hits.hits[{index}] missing _source.")

        candidates.append(
            SearchCandidate(
                event=source_event,
                source={
                    "index": str(hit.get("_index", "")),
                    "document_id": str(hit.get("_id", "")),
                },
            )
        )

    return candidates


def search_powershell_candidates(config: ElasticsearchConfig = ElasticsearchConfig()) -> list[SearchCandidate]:
    """Search Elasticsearch for normalized PowerShell detection candidates."""

    url = _search_url(config)
    body = json.dumps(build_powershell_candidate_query(size=config.size)).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=config.timeout_seconds) as response:
            status = getattr(response, "status", response.getcode())
            payload = response.read()
    except (TimeoutError, urllib.error.URLError, OSError) as exc:
        raise ElasticsearchQueryError(f"Elasticsearch query failed: {exc}") from exc

    if status < 200 or status >= 300:
        raise ElasticsearchQueryError(f"Elasticsearch query failed with HTTP status {status}.")

    try:
        parsed = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ElasticsearchQueryError(f"Elasticsearch returned invalid JSON: {exc}") from exc

    return parse_search_hits(parsed)


def _search_url(config: ElasticsearchConfig) -> str:
    base_url = config.base_url.rstrip("/")
    index_pattern = config.index_pattern.strip("/")
    return f"{base_url}/{index_pattern}/_search"
