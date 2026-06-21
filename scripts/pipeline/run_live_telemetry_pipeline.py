"""Production-shaped live telemetry to native detection pipeline."""

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

from collection.elasticsearch.event_indexer import (
    EventIndexingConfig,
    EventIndexingError,
    index_event,
)
from detection.rules.native.alert_indexer import AlertIndexingConfig, AlertIndexingError, index_alerts
from detection.rules.engine import run_detection_engines
from detection.rules.native.alerts import AlertDocumentError
from detection.rules.sigma_like.alerts import SigmaLikeAlertError
from normalization.sysmon.process_create_normalizer import (
    SysmonNormalizationError,
    UnsupportedSysmonEventError,
    normalize_sysmon_event_1,
)
from scripts.lab_config import default_elasticsearch_url


FIXTURE_PATH = REPO_ROOT / "collection" / "sysmon" / "fixtures" / "sysmon_event_1_process_create.xml"


class LiveTelemetryPipelineError(RuntimeError):
    """Raised for predictable live telemetry pipeline input failures."""


def run_live_telemetry_pipeline(
    *,
    input_mode: str = "fixture",
    xml_path: Path | None = None,
    write_events: bool = False,
    write_alerts: bool = False,
    event_indexing_config: EventIndexingConfig | None = None,
    alert_indexing_config: AlertIndexingConfig | None = None,
    event_index_date: str | None = None,
    alert_index_date: str | None = None,
    fixture_detectable_powershell: bool = False,
    engine: str = "native",
) -> dict[str, Any]:
    """Run the live telemetry pipeline for one Sysmon Event ID 1 XML event."""

    xml_event = _load_xml_input(input_mode=input_mode, xml_path=xml_path)
    normalized_event = normalize_sysmon_event_1(xml_event)

    if fixture_detectable_powershell and input_mode == "fixture":
        normalized_event = _make_fixture_detectable_powershell(normalized_event)

    event_index_results = []
    event_source: dict[str, str] = {}
    if write_events:
        event_result = index_event(
            normalized_event,
            event_indexing_config or EventIndexingConfig(),
            index_date=event_index_date,
        )
        event_index_results.append(event_result)
        event_source = {
            "index": event_result.index,
            "document_id": event_result.document_id,
        }

    alerts = _run_detection_engines(engine=engine, event=normalized_event, source=event_source)

    alert_index_results = []
    if write_alerts and alerts:
        alert_index_results = index_alerts(
            alerts,
            alert_indexing_config or AlertIndexingConfig(),
            index_date=alert_index_date,
        )

    result: dict[str, Any] = {
        "mode": input_mode,
        "engine": engine,
        "normalized_event_count": 1,
        "event_indexed_count": len(event_index_results),
        "alert_count": len(alerts),
        "alert_indexed_count": len(alert_index_results),
        "normalized_events": [normalized_event],
        "event_index_results": [asdict(indexed) for indexed in event_index_results],
        "alerts": alerts,
        "alert_index_results": [asdict(indexed) for indexed in alert_index_results],
    }

    if not alerts:
        result["message"] = "No matching PowerShell alerts produced."

    return result


def render_result(result: dict[str, Any], output: str) -> str:
    """Render pipeline results as JSON or summary."""

    if output == "json":
        return json.dumps(result, indent=2, sort_keys=True)

    if output != "summary":
        raise ValueError(f"Unsupported output format: {output!r}.")

    lines = [
        "Live telemetry pipeline",
        f"Mode: {result['mode']}",
        f"Normalized events: {result['normalized_event_count']}",
        f"Events indexed: {result['event_indexed_count']}",
        f"Alerts: {result['alert_count']}",
        f"Alerts indexed: {result['alert_indexed_count']}",
    ]

    for alert in result["alerts"]:
        alert_meta = alert["alert"]
        detection_engine = alert.get("detection", {}).get("engine", "native")
        host_name = alert.get("host", {}).get("name", "")
        process_name = alert.get("process", {}).get("name", "")
        lines.append(
            "- "
            f"{alert_meta['id']} "
            f"{detection_engine} "
            f"{alert_meta['severity']} "
            f"{alert_meta['confidence']} "
            f"{host_name} "
            f"{process_name}".rstrip()
        )

    if result["alert_count"] == 0:
        lines.append(result.get("message", "No matching PowerShell alerts produced."))

    return "\n".join(lines)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the live telemetry to native detection pipeline.")
    parser.add_argument("--input", choices=("fixture", "xml"), default="fixture")
    parser.add_argument("--xml-path", type=Path)
    parser.add_argument("--write-events", action="store_true")
    parser.add_argument("--write-alerts", action="store_true")
    parser.add_argument("--elasticsearch-url", default=default_elasticsearch_url())
    parser.add_argument("--event-index-prefix", default="edr-normalized-events")
    parser.add_argument("--alert-index-prefix", default="edr-alerts-native")
    parser.add_argument("--event-index-date")
    parser.add_argument("--alert-index-date")
    parser.add_argument("--output", choices=("json", "summary"), default="json")
    parser.add_argument("--fixture-detectable-powershell", action="store_true")
    parser.add_argument("--engine", choices=("native", "sigma-like", "all"), default="native")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or [])

    try:
        result = run_live_telemetry_pipeline(
            input_mode=args.input,
            xml_path=args.xml_path,
            write_events=args.write_events,
            write_alerts=args.write_alerts,
            event_indexing_config=EventIndexingConfig(
                base_url=args.elasticsearch_url,
                index_prefix=args.event_index_prefix,
            ),
            alert_indexing_config=AlertIndexingConfig(
                base_url=args.elasticsearch_url,
                index_prefix=args.alert_index_prefix,
            ),
            event_index_date=args.event_index_date,
            alert_index_date=args.alert_index_date,
            fixture_detectable_powershell=args.fixture_detectable_powershell,
            engine=args.engine,
        )
    except (
        LiveTelemetryPipelineError,
        SysmonNormalizationError,
        UnsupportedSysmonEventError,
        EventIndexingError,
        AlertIndexingError,
        OSError,
    ) as exc:
        print(f"Operational failure: {exc}", file=sys.stderr)
        return 2
    except (AlertDocumentError, SigmaLikeAlertError, ValueError, KeyError, TypeError) as exc:
        print(f"Live telemetry pipeline failed: {exc}", file=sys.stderr)
        return 3

    print(render_result(result, args.output))

    if args.fixture_detectable_powershell and result["alert_count"] == 0:
        return 1
    return 0


def _load_xml_input(*, input_mode: str, xml_path: Path | None) -> str:
    if input_mode == "fixture":
        return FIXTURE_PATH.read_text(encoding="utf-8")

    if input_mode == "xml":
        if xml_path is None:
            raise LiveTelemetryPipelineError("--xml-path is required when --input xml.")
        return xml_path.read_text(encoding="utf-8")

    raise LiveTelemetryPipelineError(f"Unsupported input mode: {input_mode!r}.")


def _make_fixture_detectable_powershell(normalized_event: dict[str, Any]) -> dict[str, Any]:
    event = copy.deepcopy(normalized_event)
    event["process"]["name"] = "powershell.exe"
    event["process"]["executable"] = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    event["process"]["command_line"] = "powershell.exe -NoLogo"
    event["process"]["args"] = ["powershell.exe", "-NoLogo"]
    return event


def _run_detection_engines(*, engine: str, event: dict[str, Any], source: dict[str, str]) -> list[dict[str, Any]]:
    return run_detection_engines(engine=engine, event=event, source=source)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
