"""Phase 2 detection smoke command for the native PowerShell rule.

Default fixture mode does not require Docker, Elasticsearch, Logstash, Kibana,
Kafka, or a Windows VM. Elasticsearch mode is read-only and never writes alerts.
"""

from __future__ import annotations

import argparse
import copy
import json
import sys
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from detection.rules.native import (
    AlertDocumentError,
    ElasticsearchConfig,
    ElasticsearchQueryError,
    SearchCandidate,
    build_alert_document,
    evaluate_rule,
    load_rule,
    search_powershell_candidates,
)
from scripts.lab_config import default_elasticsearch_url
from scripts.smoke.end_to_end_art_telemetry_smoke import build_smoke_payloads, load_fixture


def run_fixture_detection(*, created_at: str | None = None, force_no_alert: bool = False) -> dict[str, Any]:
    """Run detection against the existing Phase 1 fixture-derived normalized payload."""

    _, normalized_payload = build_smoke_payloads(load_fixture())
    event = copy.deepcopy(normalized_payload)

    if not force_no_alert:
        event["process"]["name"] = "powershell.exe"
        event["process"]["executable"] = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
        event["process"]["command_line"] = "powershell.exe -NoLogo"
        event["process"]["args"] = ["powershell.exe", "-NoLogo"]

    return _build_detection_result(
        mode="fixture",
        candidates=[SearchCandidate(event=event, source={})],
        created_at=created_at,
    )


def run_elasticsearch_detection(
    config: ElasticsearchConfig,
    *,
    created_at: str | None = None,
) -> dict[str, Any]:
    """Run detection against normalized candidates read from Elasticsearch."""

    candidates = search_powershell_candidates(config)
    return _build_detection_result(mode="elasticsearch", candidates=candidates, created_at=created_at)


def render_result(result: dict[str, Any], output: str) -> str:
    """Render a detection result as JSON or a compact text summary."""

    if output == "json":
        return json.dumps(result, indent=2, sort_keys=True)

    if output != "summary":
        raise ValueError(f"Unsupported output format: {output!r}.")

    lines = [
        "Phase 2 detection smoke",
        f"Mode: {result['mode']}",
        f"Rule: {result['rule_id']}",
        f"Candidates: {result['candidate_count']}",
        f"Alerts: {result['alert_count']}",
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
    parser = argparse.ArgumentParser(description="Run the Phase 2 native PowerShell detection smoke path.")
    parser.add_argument("--from-elasticsearch", action="store_true", help="Read candidates from Elasticsearch.")
    parser.add_argument("--elasticsearch-url", default=default_elasticsearch_url())
    parser.add_argument("--index-pattern", default="edr-raw-events-*")
    parser.add_argument("--size", type=int, default=100)
    parser.add_argument("--timeout-seconds", type=int, default=10)
    parser.add_argument("--output", choices=("json", "summary"), default="json")
    parser.add_argument(
        "--fixture-no-match",
        action="store_true",
        help="Use the unmodified fixture payload to exercise the no-alert path.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or [])

    try:
        if args.from_elasticsearch:
            result = run_elasticsearch_detection(
                ElasticsearchConfig(
                    base_url=args.elasticsearch_url,
                    index_pattern=args.index_pattern,
                    timeout_seconds=args.timeout_seconds,
                    size=args.size,
                )
            )
        else:
            result = run_fixture_detection(force_no_alert=args.fixture_no_match)
    except ElasticsearchQueryError as exc:
        print(f"Operational failure: {exc}", file=sys.stderr)
        return 2
    except (AlertDocumentError, ValueError, KeyError, TypeError) as exc:
        print(f"Detection smoke failed: {exc}", file=sys.stderr)
        return 3

    print(render_result(result, args.output))
    return 0 if result["alert_count"] > 0 else 1


def _build_detection_result(
    *,
    mode: str,
    candidates: list[SearchCandidate],
    created_at: str | None,
) -> dict[str, Any]:
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
                created_at=created_at,
                source=candidate.source,
            )
        )

    result: dict[str, Any] = {
        "mode": mode,
        "rule_id": rule["id"],
        "candidate_count": len(candidates),
        "alert_count": len(alerts),
        "alerts": alerts,
    }

    if not alerts:
        result["message"] = "No matching PowerShell alerts produced."

    return result


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
