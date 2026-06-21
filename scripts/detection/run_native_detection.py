"""Production-shaped local native detection runner."""

from __future__ import annotations

import argparse
import copy
import json
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from detection.rules.native.alert_indexer import (
    AlertIndexingConfig,
    AlertIndexingError,
    index_alerts,
)
from detection.rules.native.alerts import AlertDocumentError, build_alert_document
from detection.rules.native.elasticsearch import (
    ElasticsearchConfig,
    ElasticsearchQueryError,
    SearchCandidate,
    search_powershell_candidates,
)
from detection.rules.native.evaluator import evaluate_rule
from detection.rules.native.loader import load_rule
from scripts.lab_config import default_elasticsearch_url
from scripts.smoke.end_to_end_art_telemetry_smoke import build_smoke_payloads, load_fixture


def run_fixture_input(*, force_no_alert: bool = False) -> list[SearchCandidate]:
    """Build fixture input candidates for the real detection runner."""

    _, normalized_payload = build_smoke_payloads(load_fixture())
    event = copy.deepcopy(normalized_payload)

    if not force_no_alert:
        event["process"]["name"] = "powershell.exe"
        event["process"]["executable"] = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
        event["process"]["command_line"] = "powershell.exe -NoLogo"
        event["process"]["args"] = ["powershell.exe", "-NoLogo"]

    return [SearchCandidate(event=event, source={})]


def run_native_detection(
    *,
    input_mode: str = "fixture",
    elasticsearch_config: ElasticsearchConfig | None = None,
    write_alerts: bool = False,
    alert_indexing_config: AlertIndexingConfig | None = None,
    alert_index_date: str | None = None,
    force_no_alert: bool = False,
) -> dict[str, Any]:
    """Run the native detection pipeline."""

    candidates = _load_candidates(
        input_mode=input_mode,
        elasticsearch_config=elasticsearch_config or ElasticsearchConfig(),
        force_no_alert=force_no_alert,
    )
    rule = load_rule()
    alerts: list[dict[str, Any]] = []

    for candidate in candidates:
        match = evaluate_rule(rule, candidate.event)
        if not match.matched:
            continue

        alerts.append(
            build_alert_document(
                match=match,
                rule=rule,
                event=candidate.event,
                source=candidate.source,
            )
        )

    indexed_results = []
    if write_alerts and alerts:
        index_config = alert_indexing_config or AlertIndexingConfig(
            base_url=(elasticsearch_config or ElasticsearchConfig()).base_url,
            timeout_seconds=(elasticsearch_config or ElasticsearchConfig()).timeout_seconds,
        )
        indexed_results = index_alerts(alerts, index_config, index_date=alert_index_date)

    result: dict[str, Any] = {
        "mode": input_mode,
        "rule_id": rule["id"],
        "candidate_count": len(candidates),
        "alert_count": len(alerts),
        "indexed_count": len(indexed_results),
        "alerts": alerts,
        "indexed_alerts": [asdict(indexed) for indexed in indexed_results],
    }

    if not alerts:
        result["message"] = "No matching PowerShell alerts produced."

    return result


def render_result(result: dict[str, Any], output: str) -> str:
    """Render detection results as JSON or summary."""

    if output == "json":
        return json.dumps(result, indent=2, sort_keys=True)

    if output != "summary":
        raise ValueError(f"Unsupported output format: {output!r}.")

    lines = [
        "Native detection pipeline",
        f"Mode: {result['mode']}",
        f"Rule: {result['rule_id']}",
        f"Candidates: {result['candidate_count']}",
        f"Alerts: {result['alert_count']}",
        f"Indexed: {result['indexed_count']}",
    ]

    for alert in result["alerts"]:
        alert_meta = alert["alert"]
        host_name = alert.get("host", {}).get("name", "")
        process_name = alert.get("process", {}).get("name", "")
        lines.append(
            "- "
            f"{alert_meta['id']} "
            f"{alert_meta['severity']} "
            f"{alert_meta['confidence']} "
            f"{host_name} "
            f"{process_name}".rstrip()
        )

    if result["alert_count"] == 0:
        lines.append(result.get("message", "No matching PowerShell alerts produced."))

    return "\n".join(lines)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the local native detection pipeline.")
    parser.add_argument("--input", choices=("fixture", "elasticsearch"), default="fixture")
    parser.add_argument("--output", choices=("json", "summary"), default="json")
    parser.add_argument("--elasticsearch-url", default=default_elasticsearch_url())
    parser.add_argument("--index-pattern", default="edr-raw-events-*")
    parser.add_argument("--size", type=int, default=100)
    parser.add_argument("--timeout-seconds", type=int, default=10)
    parser.add_argument("--write-alerts", action="store_true")
    parser.add_argument("--alert-index-date")
    parser.add_argument("--fixture-no-match", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or [])
    elasticsearch_config = ElasticsearchConfig(
        base_url=args.elasticsearch_url,
        index_pattern=args.index_pattern,
        timeout_seconds=args.timeout_seconds,
        size=args.size,
    )
    alert_indexing_config = AlertIndexingConfig(
        base_url=args.elasticsearch_url,
        timeout_seconds=args.timeout_seconds,
    )

    try:
        result = run_native_detection(
            input_mode=args.input,
            elasticsearch_config=elasticsearch_config,
            write_alerts=args.write_alerts,
            alert_indexing_config=alert_indexing_config,
            alert_index_date=args.alert_index_date,
            force_no_alert=args.fixture_no_match,
        )
    except (ElasticsearchQueryError, AlertIndexingError) as exc:
        print(f"Operational failure: {exc}", file=sys.stderr)
        return 2
    except (AlertDocumentError, ValueError, KeyError, TypeError) as exc:
        print(f"Native detection failed: {exc}", file=sys.stderr)
        return 3

    print(render_result(result, args.output))
    return 0 if result["alert_count"] > 0 else 1


def _load_candidates(
    *,
    input_mode: str,
    elasticsearch_config: ElasticsearchConfig,
    force_no_alert: bool,
) -> list[SearchCandidate]:
    if input_mode == "fixture":
        return run_fixture_input(force_no_alert=force_no_alert)

    if input_mode == "elasticsearch":
        return search_powershell_candidates(elasticsearch_config)

    raise ValueError(f"Unsupported input mode: {input_mode!r}.")


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
