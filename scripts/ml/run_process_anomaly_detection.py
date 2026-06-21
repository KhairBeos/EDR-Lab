"""Run deterministic ML-style process anomaly detection."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from detection.ml.alerts import ProcessAnomalyAlertError, build_process_anomaly_alert
from detection.ml.baseline import ProcessBaselineError, load_process_baseline
from detection.ml.features import ProcessFeatureExtractionError, extract_process_features
from detection.ml.scorer import DEFAULT_THRESHOLD, score_process_features
from detection.rules.native.alert_indexer import AlertIndexingConfig, AlertIndexingError, index_alerts
from normalization.sysmon.process_create_normalizer import (
    SysmonNormalizationError,
    UnsupportedSysmonEventError,
    normalize_sysmon_event_1,
)
from scripts.lab_config import default_elasticsearch_url


FIXTURE_PATH = REPO_ROOT / "collection" / "sysmon" / "fixtures" / "sysmon_event_1_process_create.xml"


class ProcessAnomalyCommandError(RuntimeError):
    """Raised for predictable command input failures."""


def run_process_anomaly_detection(
    *,
    input_mode: str = "fixture",
    event_path: Path | None = None,
    threshold: float = DEFAULT_THRESHOLD,
    write_alerts: bool = False,
    elasticsearch_url: str = "http://localhost:9200",
    alert_index_prefix: str = "edr-alerts-native",
) -> dict[str, Any]:
    """Run feature extraction, scoring, alert creation, and optional indexing."""

    event = _load_event(input_mode=input_mode, event_path=event_path)
    baseline = load_process_baseline()
    features = extract_process_features(event)
    score_result = score_process_features(features, baseline, threshold=threshold)
    alert = build_process_anomaly_alert(event, features, score_result)
    alerts = [alert] if alert is not None else []

    alert_index_results = []
    if write_alerts and alerts:
        alert_index_results = index_alerts(
            alerts,
            AlertIndexingConfig(base_url=elasticsearch_url, index_prefix=alert_index_prefix),
        )

    result: dict[str, Any] = {
        "mode": input_mode,
        "event_count": 1,
        "anomaly_count": 1 if score_result["is_anomaly"] else 0,
        "alert_count": len(alerts),
        "score_results": [score_result],
        "alerts": alerts,
        "indexed_alert_count": len(alert_index_results),
        "alert_index_results": [asdict(indexed) for indexed in alert_index_results],
    }

    if not alerts:
        result["message"] = "No process anomaly alert produced."

    return result


def render_result(result: dict[str, Any], output: str) -> str:
    """Render command result as JSON or summary."""

    if output == "json":
        return json.dumps(result, indent=2, sort_keys=True)

    if output != "summary":
        raise ValueError(f"Unsupported output format: {output!r}.")

    score_result = result["score_results"][0]
    lines = [
        "ML-style process anomaly detection",
        f"Mode: {result['mode']}",
        f"Events: {result['event_count']}",
        f"Score: {score_result['score']}",
        f"Threshold: {score_result['threshold']}",
        f"Anomalies: {result['anomaly_count']}",
        f"Alerts: {result['alert_count']}",
        f"Indexed: {result['indexed_alert_count']}",
    ]

    if score_result["reasons"]:
        lines.append("Reasons:")
        for reason in score_result["reasons"]:
            lines.append(f"- {reason}")

    if result["alert_count"] == 0:
        lines.append(result.get("message", "No process anomaly alert produced."))

    return "\n".join(lines)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run deterministic process anomaly detection.")
    parser.add_argument("--input", choices=("fixture", "json"), default="fixture")
    parser.add_argument("--event-path", type=Path)
    parser.add_argument("--threshold", type=float, default=DEFAULT_THRESHOLD)
    parser.add_argument("--write-alerts", action="store_true")
    parser.add_argument("--elasticsearch-url", default=default_elasticsearch_url())
    parser.add_argument("--alert-index-prefix", default="edr-alerts-native")
    parser.add_argument("--output", choices=("json", "summary"), default="json")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or [])

    try:
        result = run_process_anomaly_detection(
            input_mode=args.input,
            event_path=args.event_path,
            threshold=args.threshold,
            write_alerts=args.write_alerts,
            elasticsearch_url=args.elasticsearch_url,
            alert_index_prefix=args.alert_index_prefix,
        )
    except (
        ProcessAnomalyCommandError,
        ProcessFeatureExtractionError,
        ProcessBaselineError,
        SysmonNormalizationError,
        UnsupportedSysmonEventError,
        AlertIndexingError,
        OSError,
    ) as exc:
        print(f"Operational failure: {exc}", file=sys.stderr)
        return 2
    except (ProcessAnomalyAlertError, ValueError, KeyError, TypeError) as exc:
        print(f"Process anomaly detection failed: {exc}", file=sys.stderr)
        return 3

    print(render_result(result, args.output))
    return 0


def _load_event(*, input_mode: str, event_path: Path | None) -> dict[str, Any]:
    if input_mode == "fixture":
        return normalize_sysmon_event_1(FIXTURE_PATH.read_text(encoding="utf-8"))

    if input_mode == "json":
        if event_path is None:
            raise ProcessAnomalyCommandError("--event-path is required when --input json.")
        try:
            parsed = json.loads(event_path.read_text(encoding="utf-8"))
        except OSError as exc:
            raise ProcessAnomalyCommandError(f"Could not read event JSON path {event_path}: {exc}") from exc
        except json.JSONDecodeError as exc:
            raise ProcessAnomalyCommandError(f"Event JSON is malformed: {exc}") from exc
        if not isinstance(parsed, dict):
            raise ProcessAnomalyCommandError("Event JSON input must be one normalized event object.")
        return parsed

    raise ProcessAnomalyCommandError(f"Unsupported input mode: {input_mode!r}.")


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
