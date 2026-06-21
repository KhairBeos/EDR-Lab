"""Run the Phase 5 SOAR dry-run response planning pipeline."""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from dataclasses import asdict
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from response.soar.engine import SoarResponseError, plan_responses
from response.soar.loader import SoarPlaybookValidationError, load_playbook
from response.soar.response_indexer import (
    ResponseIndexingConfig,
    ResponseIndexingError,
    index_responses,
)
from scripts.detection.run_native_detection import run_native_detection
from scripts.lab_config import default_elasticsearch_url


class SoarResponseCommandError(RuntimeError):
    """Raised for predictable SOAR response command input failures."""


def run_soar_response(
    *,
    input_mode: str = "fixture-alert",
    alert_path: Path | None = None,
    elasticsearch_url: str = "http://localhost:9200",
    alert_index_pattern: str = "edr-alerts-native-*",
    write_response: bool = False,
    response_index_prefix: str = "edr-response-actions",
    response_index_date: str | None = None,
) -> dict[str, Any]:
    """Load alerts, plan dry-run responses, and optionally index response records."""

    alerts = _load_alerts(
        input_mode=input_mode,
        alert_path=alert_path,
        elasticsearch_url=elasticsearch_url,
        alert_index_pattern=alert_index_pattern,
    )
    for alert in alerts:
        _validate_alert_document(alert)

    playbook = load_playbook()
    response_records = plan_responses(alerts, [playbook])

    index_results = []
    if write_response and response_records:
        index_results = index_responses(
            response_records,
            ResponseIndexingConfig(base_url=elasticsearch_url, index_prefix=response_index_prefix),
            index_date=response_index_date,
        )

    result: dict[str, Any] = {
        "mode": input_mode,
        "alert_count": len(alerts),
        "response_count": len(response_records),
        "indexed_count": len(index_results),
        "responses": response_records,
        "indexed_responses": [asdict(indexed) for indexed in index_results],
    }

    if not response_records:
        result["message"] = "No SOAR playbook matched the provided alerts."

    return result


def render_result(result: dict[str, Any], output: str) -> str:
    """Render SOAR response results as JSON or summary."""

    if output == "json":
        return json.dumps(result, indent=2, sort_keys=True)

    if output != "summary":
        raise ValueError(f"Unsupported output format: {output!r}.")

    lines = [
        "SOAR dry-run response pipeline",
        f"Mode: {result['mode']}",
        f"Alerts: {result['alert_count']}",
        f"Responses: {result['response_count']}",
        f"Indexed: {result['indexed_count']}",
    ]

    for record in result["responses"]:
        response = record["response"]
        alert = record["alert"]
        playbook = record["playbook"]
        lines.append(
            "- "
            f"{response['id']} "
            f"{response['status']} "
            f"{response['mode']} "
            f"{alert['id']} "
            f"{alert.get('rule_id') or ''} "
            f"{playbook['id']}".rstrip()
        )

    if result["response_count"] == 0:
        lines.append(result.get("message", "No SOAR playbook matched the provided alerts."))

    return "\n".join(lines)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the SOAR dry-run response planning pipeline.")
    parser.add_argument("--input", choices=("fixture-alert", "alert-json", "elasticsearch"), default="fixture-alert")
    parser.add_argument("--alert-path", type=Path)
    parser.add_argument("--elasticsearch-url", default=default_elasticsearch_url())
    parser.add_argument("--alert-index-pattern", default="edr-alerts-native-*")
    parser.add_argument("--write-response", action="store_true")
    parser.add_argument("--response-index-prefix", default="edr-response-actions")
    parser.add_argument("--response-index-date")
    parser.add_argument("--output", choices=("json", "summary"), default="json")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or [])

    try:
        result = run_soar_response(
            input_mode=args.input,
            alert_path=args.alert_path,
            elasticsearch_url=args.elasticsearch_url,
            alert_index_pattern=args.alert_index_pattern,
            write_response=args.write_response,
            response_index_prefix=args.response_index_prefix,
            response_index_date=args.response_index_date,
        )
    except (SoarResponseCommandError, ResponseIndexingError, OSError) as exc:
        print(f"Operational failure: {exc}", file=sys.stderr)
        return 2
    except (SoarPlaybookValidationError, SoarResponseError, ValueError, KeyError, TypeError) as exc:
        print(f"SOAR response failed: {exc}", file=sys.stderr)
        return 3

    print(render_result(result, args.output))
    return 0 if result["response_count"] > 0 else 1


def query_alert_documents(
    *,
    base_url: str,
    index_pattern: str,
    timeout_seconds: int = 10,
) -> list[dict[str, Any]]:
    """Fetch alert documents from Elasticsearch. Kept small for monkeypatchable tests."""

    url = f"{base_url.rstrip('/')}/{index_pattern}/_search"
    body = json.dumps({"query": {"match_all": {}}, "size": 25}).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            status = getattr(response, "status", response.getcode())
            payload = response.read()
    except (TimeoutError, urllib.error.URLError, OSError) as exc:
        raise SoarResponseCommandError(f"Elasticsearch alert query failed: {exc}") from exc

    if status not in {200, 201}:
        raise SoarResponseCommandError(f"Elasticsearch alert query failed with HTTP status {status}.")

    try:
        parsed = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SoarResponseCommandError(f"Elasticsearch returned malformed alert query JSON: {exc}") from exc

    hits = parsed.get("hits", {}).get("hits") if isinstance(parsed, dict) else None
    if not isinstance(hits, list):
        raise SoarResponseCommandError("Elasticsearch alert query response is missing hits.hits.")

    alerts: list[dict[str, Any]] = []
    for hit in hits:
        if not isinstance(hit, dict) or not isinstance(hit.get("_source"), dict):
            continue
        alerts.append(hit["_source"])
    return alerts


def _load_alerts(
    *,
    input_mode: str,
    alert_path: Path | None,
    elasticsearch_url: str,
    alert_index_pattern: str,
) -> list[dict[str, Any]]:
    if input_mode == "fixture-alert":
        result = run_native_detection()
        return list(result["alerts"])

    if input_mode == "alert-json":
        if alert_path is None:
            raise SoarResponseCommandError("--alert-path is required when --input alert-json.")
        try:
            parsed = json.loads(alert_path.read_text(encoding="utf-8"))
        except OSError as exc:
            raise SoarResponseCommandError(f"Could not read alert JSON path {alert_path}: {exc}") from exc
        except json.JSONDecodeError as exc:
            raise SoarResponseCommandError(f"Alert JSON is malformed: {exc}") from exc
        if not isinstance(parsed, dict):
            raise SoarResponseCommandError("Alert JSON input must be one alert object.")
        return [parsed]

    if input_mode == "elasticsearch":
        return query_alert_documents(base_url=elasticsearch_url, index_pattern=alert_index_pattern)

    raise SoarResponseCommandError(f"Unsupported input mode: {input_mode!r}.")


def _validate_alert_document(alert: dict[str, Any]) -> None:
    alert_meta = alert.get("alert")
    if not isinstance(alert_meta, dict) or not isinstance(alert_meta.get("id"), str) or not alert_meta["id"]:
        raise SoarResponseCommandError("Alert document must contain non-empty alert.id.")

    rule = alert.get("rule")
    attack = alert.get("attack")
    art = alert.get("art")
    has_rule_id = isinstance(rule, dict) and isinstance(rule.get("id"), str) and bool(rule["id"])
    has_attack_id = (
        isinstance(attack, dict)
        and isinstance(attack.get("technique"), dict)
        and isinstance(attack["technique"].get("id"), str)
        and bool(attack["technique"]["id"])
    )
    has_art_technique_id = isinstance(art, dict) and isinstance(art.get("technique_id"), str) and bool(art["technique_id"])

    if not has_rule_id and not has_attack_id and not has_art_technique_id:
        raise SoarResponseCommandError("Alert document must contain rule.id or ATT&CK technique id.")


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
