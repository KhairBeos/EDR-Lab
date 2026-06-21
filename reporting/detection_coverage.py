"""Detection coverage report generation for the local EDR demo."""

from __future__ import annotations

import json
import socket
import urllib.error
import urllib.parse
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from detection.behavioral.correlation import detect_behavioral_sequences
from detection.behavioral.sequences import BEHAVIORAL_SEQUENCES, SequenceDefinition, sequence_rule_metadata
from detection.rules.native.loader import load_rule
from detection.rules.native.registry import load_native_rules
from detection.rules.sigma_like.loader import load_sigma_like_rule, load_sigma_like_rules
from scripts.pipeline.run_live_telemetry_pipeline import LiveTelemetryPipelineError, run_live_telemetry_pipeline


PROJECT_PHASE = "Phase 14 Behavioral Correlation Detection"
FIXTURE_NAME = "sysmon_event_1_process_create.xml"
REPO_ROOT = Path(__file__).resolve().parents[1]
BEHAVIORAL_VALIDATION_SAMPLE_PATHS = (
    REPO_ROOT / "samples" / "demo_cases" / "behavioral_t1105_sequence.json",
    REPO_ROOT / "samples" / "demo_cases" / "behavioral_t1547_sequence.json",
    REPO_ROOT / "samples" / "demo_cases" / "t1218_rundll32_process_event.json",
)
EXPECTED_ALERT_COUNTS = {
    "native": 1,
    "sigma-like": 1,
    "all": 2,
}


class DetectionCoverageReportError(RuntimeError):
    """Raised for predictable coverage report failures."""


def build_detection_coverage_report(
    *,
    engine: str = "all",
    include_elasticsearch: bool = False,
    elasticsearch_url: str = "http://localhost:9200",
    alert_index_pattern: str = "edr-alerts-native-*",
    generated_at: datetime | str | None = None,
) -> dict[str, Any]:
    """Build a JSON-compatible detection coverage report."""

    if engine not in EXPECTED_ALERT_COUNTS:
        raise DetectionCoverageReportError(f"Unsupported detection engine: {engine!r}.")

    try:
        rule_inventory = build_rule_inventory()
        report = {
            "generated_at": _format_timestamp(generated_at),
            "project_phase": PROJECT_PHASE,
            "covered_techniques": build_covered_techniques(),
            "rule_inventory": rule_inventory,
            "validation_results": [
                run_fixture_validation(engine=engine),
                run_behavioral_sequence_validation(),
            ],
            "engine_coverage_summary": build_engine_coverage_summary(rule_inventory),
        }

        if include_elasticsearch:
            report["elasticsearch"] = query_elasticsearch_alert_counts(
                base_url=elasticsearch_url,
                alert_index_pattern=alert_index_pattern,
            )

        return report
    except DetectionCoverageReportError:
        raise
    except (OSError, ValueError, TypeError, KeyError, LiveTelemetryPipelineError) as exc:
        raise DetectionCoverageReportError(f"Failed to build detection coverage report: {exc}") from exc


def build_rule_inventory(
    *,
    native_rule: dict[str, Any] | None = None,
    sigma_like_rule: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Build rule inventory entries from local native and Sigma-like rules."""

    native_rules = [native_rule or load_rule()] if native_rule is not None else load_native_rules()
    sigma_like_rules = [sigma_like_rule or load_sigma_like_rule()] if sigma_like_rule is not None else load_sigma_like_rules()

    inventory: list[dict[str, Any]] = []
    for native in native_rules:
        inventory.append(
            {
                "rule_id": native["id"],
                "engine": "native",
                "name": native["name"],
                "severity": native["severity"],
                "confidence": native["confidence"],
                "attack": _copy_attack(native["attack"]),
                "supported_datasource": _native_supported_datasource(native),
            }
        )

    for sigma_like in sigma_like_rules:
        inventory.append(
            {
                "rule_id": sigma_like["id"],
                "engine": "sigma-like",
                "name": sigma_like.get("title") or sigma_like["name"],
                "severity": sigma_like["level"],
                "confidence": sigma_like["confidence"],
                "attack": _copy_attack(sigma_like["attack"]),
                "supported_datasource": _sigma_like_supported_datasource(sigma_like),
            }
        )

    for definition in BEHAVIORAL_SEQUENCES:
        metadata = sequence_rule_metadata(definition)
        inventory.append(
            {
                "rule_id": definition.rule_id,
                "engine": "behavioral",
                "name": metadata["name"],
                "severity": definition.severity,
                "confidence": definition.confidence,
                "attack": _copy_attack(metadata["attack"]),
                "supported_datasource": _behavioral_supported_datasource(definition),
            }
        )

    return inventory


def build_covered_techniques() -> list[dict[str, Any]]:
    """Build the current covered technique summary."""

    return [
        {
            "technique_id": "T1059.001",
            "technique_name": "PowerShell",
            "tactic": ["Execution"],
            "datasource": {
                "event_dataset": "windows.sysmon_operational",
                "event_code": 1,
                "event_type": "process_creation",
            },
            "engines": ["native", "sigma-like"],
        },
        {
            "technique_id": "T1105",
            "technique_name": "Ingress Tool Transfer",
            "tactic": ["Command and Control"],
            "datasource": {
                "event_dataset": "windows.sysmon_operational",
                "event_code": "1/3/11",
                "event_type": "process_creation, network_connection, file_creation",
            },
            "engines": ["native", "sigma-like", "behavioral"],
        },
        {
            "technique_id": "T1547.001",
            "technique_name": "Registry Run Keys / Startup Folder",
            "tactic": ["Persistence"],
            "datasource": {
                "event_dataset": "windows.sysmon_operational",
                "event_code": "1/13",
                "event_type": "process_creation, registry_value_set",
            },
            "engines": ["native", "sigma-like", "behavioral"],
        },
        {
            "technique_id": "T1218",
            "technique_name": "System Binary Proxy Execution",
            "tactic": ["Defense Evasion"],
            "datasource": {
                "event_dataset": "windows.sysmon_operational",
                "event_code": 1,
                "event_type": "process_creation",
            },
            "engines": ["native", "sigma-like", "behavioral"],
        },
    ]


def build_engine_coverage_summary(rule_inventory: list[dict[str, Any]]) -> dict[str, int]:
    """Summarize rule counts by detection engine."""

    native_count = sum(1 for rule in rule_inventory if rule.get("engine") == "native")
    sigma_like_count = sum(1 for rule in rule_inventory if rule.get("engine") == "sigma-like")
    behavioral_count = sum(1 for rule in rule_inventory if rule.get("engine") == "behavioral")
    return {
        "native_rule_count": native_count,
        "sigma_like_rule_count": sigma_like_count,
        "behavioral_rule_count": behavioral_count,
        "total_rule_count": native_count + sigma_like_count + behavioral_count,
    }


def run_fixture_validation(*, engine: str) -> dict[str, Any]:
    """Run deterministic fixture validation through the live telemetry pipeline."""

    if engine not in EXPECTED_ALERT_COUNTS:
        raise DetectionCoverageReportError(f"Unsupported detection engine: {engine!r}.")

    result = run_live_telemetry_pipeline(
        input_mode="fixture",
        fixture_detectable_powershell=True,
        write_events=False,
        write_alerts=False,
        engine=engine,
    )

    alerts = result.get("alerts", [])
    expected_alert_count = EXPECTED_ALERT_COUNTS[engine]
    normalized_event_count = result.get("normalized_event_count")
    actual_alert_count = result.get("alert_count")
    attack_covered = _alerts_cover_technique(alerts, "T1059.001")
    engines_present = _alert_engines(alerts)
    engine_covered = _expected_engines_present(engine=engine, engines_present=engines_present)

    passed = (
        normalized_event_count == 1
        and actual_alert_count == expected_alert_count
        and attack_covered
        and engine_covered
    )

    return {
        "fixture_name": FIXTURE_NAME,
        "engine": engine,
        "normalized_event_count": normalized_event_count,
        "expected_alert_count": expected_alert_count,
        "actual_alert_count": actual_alert_count,
        "passed": passed,
    }


def run_behavioral_sequence_validation() -> dict[str, Any]:
    """Validate deterministic behavioral sequence samples without live infrastructure."""

    events: list[dict[str, Any]] = []
    for path in BEHAVIORAL_VALIDATION_SAMPLE_PATHS:
        parsed = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(parsed, list):
            events.extend(parsed)
        elif isinstance(parsed, dict):
            events.append(parsed)
        else:
            raise DetectionCoverageReportError(f"Behavioral validation sample {path} must be an object or array.")

    alerts = detect_behavioral_sequences(events)
    actual_rule_ids = {alert.get("rule", {}).get("id") for alert in alerts}
    expected_rule_ids = {
        "det.behavioral.t1105_download_sequence",
        "det.behavioral.t1547_001_registry_persistence_sequence",
        "det.behavioral.t1218_lolbin_sequence",
    }
    passed = (
        len(alerts) == len(expected_rule_ids)
        and expected_rule_ids.issubset(actual_rule_ids)
        and all(alert.get("detection", {}).get("engine") == "behavioral" for alert in alerts)
    )

    return {
        "fixture_name": "behavioral_sequence_samples",
        "engine": "behavioral",
        "normalized_event_count": len(events),
        "expected_alert_count": len(expected_rule_ids),
        "actual_alert_count": len(alerts),
        "correlated_sequence_count": len(alerts),
        "passed": passed,
    }


def query_elasticsearch_alert_counts(
    *,
    base_url: str = "http://localhost:9200",
    alert_index_pattern: str = "edr-alerts-native-*",
    timeout_seconds: int = 10,
) -> dict[str, Any]:
    """Query Elasticsearch alert indexes for T1059.001 alert counts."""

    query = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    {
                        "term": {
                            "attack.technique.id": "T1059.001",
                        }
                    }
                ]
            }
        },
        "aggs": {
            "native": {
                "filter": {
                    "bool": {
                        "must_not": [
                            {
                                "exists": {
                                    "field": "detection.engine",
                                }
                            }
                        ]
                    }
                }
            },
            "sigma_like": {
                "filter": {
                    "term": {
                        "detection.engine": "sigma-like",
                    }
                }
            },
        },
    }

    url = _build_elasticsearch_search_url(base_url=base_url, alert_index_pattern=alert_index_pattern)
    body = json.dumps(query).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="GET",
    )

    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            status = getattr(response, "status", response.getcode())
            response_body = response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        raise DetectionCoverageReportError(f"Elasticsearch alert count query failed with HTTP {exc.code}.") from exc
    except (urllib.error.URLError, TimeoutError, socket.timeout) as exc:
        raise DetectionCoverageReportError(f"Elasticsearch alert count query failed: {exc}") from exc

    if status < 200 or status >= 300:
        raise DetectionCoverageReportError(f"Elasticsearch alert count query returned HTTP {status}.")

    try:
        parsed = json.loads(response_body)
    except json.JSONDecodeError as exc:
        raise DetectionCoverageReportError("Elasticsearch alert count response was not valid JSON.") from exc

    try:
        total_matching_alerts = _parse_total_hits(parsed["hits"]["total"])
        native_alert_count = parsed["aggregations"]["native"]["doc_count"]
        sigma_like_alert_count = parsed["aggregations"]["sigma_like"]["doc_count"]
    except (KeyError, TypeError) as exc:
        raise DetectionCoverageReportError("Elasticsearch alert count response was missing expected fields.") from exc

    if not all(isinstance(value, int) for value in (total_matching_alerts, native_alert_count, sigma_like_alert_count)):
        raise DetectionCoverageReportError("Elasticsearch alert counts must be integers.")

    return {
        "alert_index_pattern": alert_index_pattern,
        "total_matching_alerts": total_matching_alerts,
        "native_alert_count": native_alert_count,
        "sigma_like_alert_count": sigma_like_alert_count,
    }


def render_json_report(report: dict[str, Any]) -> str:
    """Render a detection coverage report as stable JSON."""

    return json.dumps(report, indent=2, sort_keys=True)


def render_markdown_report(report: dict[str, Any]) -> str:
    """Render a detection coverage report as Markdown."""

    validation_passed = all(result.get("passed") for result in report.get("validation_results", []))
    summary = report["engine_coverage_summary"]
    lines = [
        "# Detection Coverage Report",
        "",
        f"Generated: {report['generated_at']}",
        f"Project phase: {report['project_phase']}",
        "",
        "## Coverage Summary",
        "",
        f"- Native rules: {summary['native_rule_count']}",
        f"- Sigma-like rules: {summary['sigma_like_rule_count']}",
        f"- Behavioral rules: {summary['behavioral_rule_count']}",
        f"- Total rules: {summary['total_rule_count']}",
        "",
        "## Covered Techniques",
        "",
        "| Technique | Name | Tactic | Dataset | Event ID | Event Type | Engines |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]

    for technique in report.get("covered_techniques", []):
        datasource = technique["datasource"]
        lines.append(
            "| "
            f"{technique['technique_id']} | "
            f"{technique['technique_name']} | "
            f"{', '.join(technique['tactic'])} | "
            f"{datasource['event_dataset']} | "
            f"{datasource['event_code']} | "
            f"{datasource['event_type']} | "
            f"{', '.join(technique['engines'])} |"
        )

    lines.extend(
        [
            "",
            "## Rule Inventory",
            "",
            "| Rule ID | Engine | Name | Severity | Confidence | Technique | Datasource |",
            "| --- | --- | --- | --- | --- | --- | --- |",
        ]
    )

    for rule in report.get("rule_inventory", []):
        datasource = rule["supported_datasource"]
        lines.append(
            "| "
            f"{rule['rule_id']} | "
            f"{rule['engine']} | "
            f"{rule['name']} | "
            f"{rule['severity']} | "
            f"{rule['confidence']} | "
            f"{rule['attack']['technique_id']} {rule['attack']['technique_name']} | "
            f"{datasource['event_dataset']} / {datasource['event_code']} |"
        )

    lines.extend(
        [
            "",
            "## Deterministic Fixture Validation",
            "",
            "| Fixture | Engine | Normalized Events | Expected Alerts | Actual Alerts | Passed |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
    )

    for result in report.get("validation_results", []):
        lines.append(
            "| "
            f"{result['fixture_name']} | "
            f"{result['engine']} | "
            f"{result['normalized_event_count']} | "
            f"{result['expected_alert_count']} | "
            f"{result['actual_alert_count']} | "
            f"{str(result['passed']).lower()} |"
        )

    if "elasticsearch" in report:
        elasticsearch = report["elasticsearch"]
        lines.extend(
            [
                "",
                "## Elasticsearch Alert Counts",
                "",
                "| Alert Index Pattern | Total T1059.001 Alerts | Native Alerts | Sigma-like Alerts |",
                "| --- | --- | --- | --- |",
                "| "
                f"{elasticsearch['alert_index_pattern']} | "
                f"{elasticsearch['total_matching_alerts']} | "
                f"{elasticsearch['native_alert_count']} | "
                f"{elasticsearch['sigma_like_alert_count']} |",
            ]
        )

    lines.extend(
        [
            "",
            "## Acceptance Result",
            "",
            f"Deterministic validation passed: {str(validation_passed).lower()}",
            "",
            "## Scope Boundaries",
            "",
            "- Fixture validation covers `T1059.001` single-event native and Sigma-like rules.",
            "- Behavioral validation covers deterministic local `T1105`, `T1547.001`, and `T1218-lite` sequences.",
            "- The report command does not write normalized events.",
            "- The report command does not write alerts.",
            "- Elasticsearch alert counts are optional.",
            "- Kafka, ML, SOAR, TheHive, graph analytics, streaming state, full SigmaHQ import, and production containment are out of scope.",
        ]
    )

    return "\n".join(lines) + "\n"


def report_validation_passed(report: dict[str, Any]) -> bool:
    """Return whether all deterministic validation results passed."""

    return all(result.get("passed") is True for result in report.get("validation_results", []))


def _copy_attack(attack: dict[str, Any]) -> dict[str, Any]:
    return {
        "technique_id": attack["technique_id"],
        "technique_name": attack["technique_name"],
        "tactic": list(attack["tactic"]),
    }


def _native_supported_datasource(rule: dict[str, Any]) -> dict[str, Any]:
    if isinstance(rule.get("data_source"), dict):
        data_source = rule["data_source"]
        return {
            "event_dataset": data_source["event_dataset"],
            "event_code": data_source["event_code"],
        }

    data_sources = rule.get("data_sources")
    if isinstance(data_sources, list) and data_sources:
        return {
            "event_dataset": data_sources[0].get("event_dataset"),
            "event_code": "/".join(str(item.get("event_code")) for item in data_sources),
            "event_types": [item.get("event_type") for item in data_sources if item.get("event_type")],
        }

    return {"event_dataset": "windows.sysmon_operational", "event_code": "unknown"}


def _sigma_like_supported_datasource(rule: dict[str, Any]) -> dict[str, Any]:
    selection = rule["detection"]["selection"]
    return {
        "event_dataset": selection["event.dataset"],
        "event_code": selection["event.code"],
        "logsource": {
            "product": rule["logsource"]["product"],
            "service": rule["logsource"]["service"],
            "category": rule["logsource"]["category"],
        },
    }


def _behavioral_supported_datasource(definition: SequenceDefinition) -> dict[str, Any]:
    event_codes_by_rule = {
        "det.behavioral.t1105_download_sequence": "1/3/11",
        "det.behavioral.t1547_001_registry_persistence_sequence": "1/13",
        "det.behavioral.t1218_lolbin_sequence": "1/3/11",
    }
    event_types_by_rule = {
        "det.behavioral.t1105_download_sequence": [
            "process_creation",
            "network_connection",
            "file_creation",
        ],
        "det.behavioral.t1547_001_registry_persistence_sequence": [
            "process_creation",
            "registry_value_set",
        ],
        "det.behavioral.t1218_lolbin_sequence": [
            "process_creation",
            "network_connection",
            "file_creation",
        ],
    }
    return {
        "event_dataset": "windows.sysmon_operational",
        "event_code": event_codes_by_rule[definition.rule_id],
        "event_types": event_types_by_rule[definition.rule_id],
        "correlation_window_seconds": definition.window_seconds,
    }


def _format_timestamp(value: datetime | str | None) -> str:
    if value is None:
        return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    if isinstance(value, str):
        return value
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _alerts_cover_technique(alerts: list[dict[str, Any]], technique_id: str) -> bool:
    if not alerts:
        return False
    return all(alert.get("attack", {}).get("technique", {}).get("id") == technique_id for alert in alerts)


def _alert_engines(alerts: list[dict[str, Any]]) -> set[str]:
    return {alert.get("detection", {}).get("engine", "native") for alert in alerts}


def _expected_engines_present(*, engine: str, engines_present: set[str]) -> bool:
    if engine == "all":
        return engines_present == {"native", "sigma-like"}
    return engines_present == {engine}


def _build_elasticsearch_search_url(*, base_url: str, alert_index_pattern: str) -> str:
    base = base_url.rstrip("/")
    encoded_pattern = urllib.parse.quote(alert_index_pattern, safe="*")
    return f"{base}/{encoded_pattern}/_search"


def _parse_total_hits(total: Any) -> int:
    if isinstance(total, int):
        return total
    if isinstance(total, dict) and isinstance(total.get("value"), int):
        return total["value"]
    raise DetectionCoverageReportError("Elasticsearch hits.total was missing an integer value.")
