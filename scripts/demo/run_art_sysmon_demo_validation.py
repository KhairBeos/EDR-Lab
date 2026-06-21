"""Run the Phase 8 Atomic Red Team Sysmon demo validation pack."""

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

from collection.elasticsearch.event_indexer import EventIndexingConfig, EventIndexingError
from detection.ml.alerts import ProcessAnomalyAlertError
from detection.ml.baseline import ProcessBaselineError
from detection.ml.features import ProcessFeatureExtractionError
from detection.rules.native.alert_indexer import AlertIndexingConfig, AlertIndexingError
from detection.rules.native.alert_indexer import index_alerts
from detection.rules.native.alerts import AlertDocumentError
from detection.rules.engine import run_detection_engines
from detection.rules.sigma_like.alerts import SigmaLikeAlertError
from normalization.sysmon.process_create_normalizer import SysmonNormalizationError, UnsupportedSysmonEventError
from response.soar.engine import SoarResponseError, plan_responses
from response.soar.loader import SoarPlaybookValidationError, load_playbook
from response.soar.response_indexer import ResponseIndexingConfig, ResponseIndexingError, index_responses
from scripts.lab_config import default_elasticsearch_url
from scripts.ml.run_process_anomaly_detection import ProcessAnomalyCommandError, run_process_anomaly_detection
from scripts.pipeline.run_live_telemetry_pipeline import LiveTelemetryPipelineError, run_live_telemetry_pipeline


DEFAULT_XML_SAMPLE = REPO_ROOT / "samples" / "sysmon" / "art_t1059_001_powershell_event.xml"
DEFAULT_ML_SAMPLE = REPO_ROOT / "samples" / "sysmon" / "ml_suspicious_process_event.json"


class ArtSysmonDemoValidationError(RuntimeError):
    """Raised for predictable Phase 8 demo validation failures."""


def run_art_sysmon_demo_validation(
    *,
    input_mode: str = "fixture",
    xml_path: Path | None = None,
    event_path: Path | None = None,
    engine: str = "all",
    write_events: bool = False,
    write_alerts: bool = False,
    write_response: bool = False,
    elasticsearch_url: str = "http://localhost:9200",
) -> dict[str, Any]:
    """Run deterministic demo validation using existing EDR pipeline components."""

    if input_mode in {"fixture", "xml"}:
        return _run_sysmon_validation(
            input_mode=input_mode,
            xml_path=xml_path,
            engine=engine,
            write_events=write_events,
            write_alerts=write_alerts,
            write_response=write_response,
            elasticsearch_url=elasticsearch_url,
        )

    if input_mode == "json":
        if engine in {"native", "sigma-like", "all"}:
            return _run_normalized_json_validation(
                event_path=event_path,
                engine=engine,
                write_alerts=write_alerts,
                write_response=write_response,
                elasticsearch_url=elasticsearch_url,
            )
        return _run_ml_validation(
            event_path=event_path,
            engine=engine,
            write_alerts=write_alerts,
            elasticsearch_url=elasticsearch_url,
        )

    raise ArtSysmonDemoValidationError(f"Unsupported input mode: {input_mode!r}.")


def render_result(result: dict[str, Any], output: str) -> str:
    """Render Phase 8 result as JSON or an operator summary."""

    if output == "json":
        return json.dumps(result, indent=2, sort_keys=True)

    if output != "summary":
        raise ValueError(f"Unsupported output format: {output!r}.")

    lines = [
        "Atomic Red Team Sysmon demo validation",
        f"Input: {result['input']}",
        f"Engine: {result['engine']}",
        f"Normalized events: {result['normalized_event_count']}",
        f"Native alerts: {result['native_alert_count']}",
        f"Sigma-like alerts: {result['sigma_like_alert_count']}",
        f"ML alerts: {result['ml_alert_count']}",
        f"Responses: {result['response_count']}",
        f"Indexed events: {result['indexed_event_count']}",
        f"Indexed alerts: {result['indexed_alert_count']}",
        f"Indexed responses: {result['indexed_response_count']}",
    ]

    for alert in result.get("alerts", []):
        rule_id = alert.get("rule", {}).get("id", "")
        engine_name = alert.get("detection", {}).get("engine", "native")
        alert_id = alert.get("alert", {}).get("id", "")
        lines.append(f"- alert {alert_id} {engine_name} {rule_id}".rstrip())

    if result.get("responses"):
        for response_record in result["responses"]:
            response = response_record.get("response", {})
            playbook = response_record.get("playbook", {})
            lines.append(f"- response {response.get('id', '')} {response.get('status', '')} {playbook.get('id', '')}".rstrip())

    return "\n".join(lines)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the Atomic Red Team Sysmon demo validation pack.")
    parser.add_argument("--input", choices=("fixture", "xml", "json"), default="fixture")
    parser.add_argument("--xml-path", type=Path)
    parser.add_argument("--event-path", type=Path)
    parser.add_argument("--engine", choices=("native", "sigma-like", "all", "ml-anomaly"), default="all")
    parser.add_argument("--write-events", action="store_true")
    parser.add_argument("--write-alerts", action="store_true")
    parser.add_argument("--write-response", action="store_true")
    parser.add_argument("--elasticsearch-url", default=default_elasticsearch_url())
    parser.add_argument("--output", choices=("json", "summary"), default="json")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])

    try:
        result = run_art_sysmon_demo_validation(
            input_mode=args.input,
            xml_path=args.xml_path,
            event_path=args.event_path,
            engine=args.engine,
            write_events=args.write_events,
            write_alerts=args.write_alerts,
            write_response=args.write_response,
            elasticsearch_url=args.elasticsearch_url,
        )
    except (
        ArtSysmonDemoValidationError,
        LiveTelemetryPipelineError,
        ProcessAnomalyCommandError,
        SysmonNormalizationError,
        UnsupportedSysmonEventError,
        ProcessFeatureExtractionError,
        ProcessBaselineError,
        EventIndexingError,
        AlertIndexingError,
        ResponseIndexingError,
        OSError,
    ) as exc:
        print(f"Operational failure: {exc}", file=sys.stderr)
        return 2
    except (
        AlertDocumentError,
        SigmaLikeAlertError,
        ProcessAnomalyAlertError,
        SoarPlaybookValidationError,
        SoarResponseError,
        ValueError,
        KeyError,
        TypeError,
    ) as exc:
        print(f"Phase 8 demo validation failed: {exc}", file=sys.stderr)
        return 3

    print(render_result(result, args.output))
    return 0


def _run_sysmon_validation(
    *,
    input_mode: str,
    xml_path: Path | None,
    engine: str,
    write_events: bool,
    write_alerts: bool,
    write_response: bool,
    elasticsearch_url: str,
) -> dict[str, Any]:
    if engine == "ml-anomaly":
        raise ArtSysmonDemoValidationError("--engine ml-anomaly requires --input json.")

    if input_mode == "xml" and xml_path is None:
        xml_path = DEFAULT_XML_SAMPLE

    pipeline_result = run_live_telemetry_pipeline(
        input_mode=input_mode,
        xml_path=xml_path,
        write_events=write_events,
        write_alerts=write_alerts,
        event_indexing_config=EventIndexingConfig(base_url=elasticsearch_url),
        alert_indexing_config=AlertIndexingConfig(base_url=elasticsearch_url),
        fixture_detectable_powershell=input_mode == "fixture",
        engine=engine,
    )
    alerts = list(pipeline_result["alerts"])

    response_records: list[dict[str, Any]] = []
    response_index_results = []
    if write_response and alerts:
        response_records = plan_responses(alerts, [load_playbook()])
        if response_records:
            response_index_results = index_responses(
                response_records,
                ResponseIndexingConfig(base_url=elasticsearch_url),
            )

    return {
        "input": input_mode,
        "engine": engine,
        "normalized_event_count": pipeline_result["normalized_event_count"],
        "native_alert_count": _count_alerts(alerts, "det.t1059_001.powershell_process_start"),
        "sigma_like_alert_count": _count_alerts(alerts, "sigma_like.t1059_001.powershell_process_start"),
        "ml_alert_count": 0,
        "response_count": len(response_records),
        "indexed_event_count": pipeline_result["event_indexed_count"],
        "indexed_alert_count": pipeline_result["alert_indexed_count"],
        "indexed_response_count": len(response_index_results),
        "normalized_events": pipeline_result["normalized_events"],
        "alerts": alerts,
        "responses": response_records,
        "event_index_results": pipeline_result["event_index_results"],
        "alert_index_results": pipeline_result["alert_index_results"],
        "response_index_results": [asdict(indexed) for indexed in response_index_results],
    }


def _run_ml_validation(
    *,
    event_path: Path | None,
    engine: str,
    write_alerts: bool,
    elasticsearch_url: str,
) -> dict[str, Any]:
    if engine not in {"ml-anomaly", "all"}:
        raise ArtSysmonDemoValidationError("--input json supports --engine ml-anomaly or --engine all.")

    result = run_process_anomaly_detection(
        input_mode="json",
        event_path=event_path or DEFAULT_ML_SAMPLE,
        write_alerts=write_alerts,
        elasticsearch_url=elasticsearch_url,
    )

    return {
        "input": "json",
        "engine": "ml-anomaly",
        "normalized_event_count": result["event_count"],
        "native_alert_count": 0,
        "sigma_like_alert_count": 0,
        "ml_alert_count": result["alert_count"],
        "response_count": 0,
        "indexed_event_count": 0,
        "indexed_alert_count": result["indexed_alert_count"],
        "indexed_response_count": 0,
        "normalized_events": [],
        "alerts": result["alerts"],
        "responses": [],
        "event_index_results": [],
        "alert_index_results": result["alert_index_results"],
        "response_index_results": [],
        "score_results": result["score_results"],
    }


def _run_normalized_json_validation(
    *,
    event_path: Path | None,
    engine: str,
    write_alerts: bool,
    write_response: bool,
    elasticsearch_url: str,
) -> dict[str, Any]:
    if event_path is None:
        raise ArtSysmonDemoValidationError("--input json requires --event-path for native or Sigma-like detection.")

    event = json.loads(event_path.read_text(encoding="utf-8"))
    if not isinstance(event, dict):
        raise ArtSysmonDemoValidationError("Normalized JSON sample must be an object.")

    alerts = run_detection_engines(engine=engine, event=event, source={})
    alert_index_results = []
    if write_alerts and alerts:
        alert_index_results = index_alerts(alerts, AlertIndexingConfig(base_url=elasticsearch_url))

    response_records: list[dict[str, Any]] = []
    response_index_results = []
    if write_response and alerts:
        response_records = plan_responses(alerts, [load_playbook()])
        if response_records:
            response_index_results = index_responses(
                response_records,
                ResponseIndexingConfig(base_url=elasticsearch_url),
            )

    return {
        "input": "json",
        "engine": engine,
        "normalized_event_count": 1,
        "native_alert_count": _count_alerts_by_engine(alerts, "native"),
        "sigma_like_alert_count": _count_alerts_by_engine(alerts, "sigma-like"),
        "ml_alert_count": 0,
        "response_count": len(response_records),
        "indexed_event_count": 0,
        "indexed_alert_count": len(alert_index_results),
        "indexed_response_count": len(response_index_results),
        "normalized_events": [event],
        "alerts": alerts,
        "responses": response_records,
        "event_index_results": [],
        "alert_index_results": [asdict(indexed) for indexed in alert_index_results],
        "response_index_results": [asdict(indexed) for indexed in response_index_results],
    }


def _count_alerts(alerts: list[dict[str, Any]], rule_id: str) -> int:
    return sum(1 for alert in alerts if alert.get("rule", {}).get("id") == rule_id)


def _count_alerts_by_engine(alerts: list[dict[str, Any]], engine: str) -> int:
    return sum(1 for alert in alerts if (alert.get("detection", {}).get("engine") or "native") == engine)


if __name__ == "__main__":
    raise SystemExit(main())
