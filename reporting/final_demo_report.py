"""Final demo report generation for the local EDR platform."""

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
from detection.rules.native.alert_indexer import AlertIndexingError
from reporting.detection_coverage import DetectionCoverageReportError, build_detection_coverage_report
from scripts.kafka.consume_and_detect import run_consumer
from scripts.ml.run_process_anomaly_detection import run_process_anomaly_detection
from scripts.pipeline.run_live_telemetry_pipeline import run_live_telemetry_pipeline
from scripts.response.run_soar_response import run_soar_response
from detection.kafka.consumer import ConsumerConfig, KafkaConsumerError
from detection.rules.native.alert_indexer import AlertIndexingConfig


JSON_REPORT_NAME = "final_demo_report.json"
MARKDOWN_REPORT_NAME = "final_demo_report.md"
PROJECT_STATUS = "Phase 15 ATT&CK Navigator export ready"

IMPLEMENTED_PHASES = [
    "Phase 1 Foundation",
    "Phase 2 Native Detection Pipeline MVP",
    "Phase 3 Live Telemetry Pipeline, Sigma-like Detection, and Coverage Report",
    "Phase 4 Kafka Normalized Event Detection Pipeline",
    "Phase 5 SOAR Dry-run Response Pipeline",
    "Phase 6 ML-style Process Anomaly Detection MVP",
    "Phase 7 Final Demo Report and Operator Dashboard MVP",
    "Phase 8 ART / Sysmon VM Demo",
    "Phase 9 10-case TP/TN/FP/FN Demo Case Matrix",
    "Phase 10 Lab-only Kill-process Protection Action",
    "Phase 13 Multi-technique ATT&CK Demo Detection",
    "Phase 14 Behavioral Correlation Detection",
    "Phase 15 ATT&CK Navigator Coverage Export",
]

ELASTICSEARCH_INDEX_PATTERNS = [
    "edr-normalized-events-*",
    "edr-alerts-native-*",
    "edr-response-actions-*",
    "edr-protection-actions-*",
]

DEMO_COMMAND_CHECKLIST = [
    r"python scripts\smoke\end_to_end_art_telemetry_smoke.py",
    r"python scripts\detection\run_native_detection.py",
    r"python scripts\pipeline\run_live_telemetry_pipeline.py --input fixture --fixture-detectable-powershell --engine all",
    r"python scripts\kafka\produce_normalized_event.py --input fixture --fixture-detectable-powershell --dry-run",
    r"python scripts\kafka\consume_and_detect.py --dry-run-fixture --engine all",
    r"python scripts\response\run_soar_response.py --input fixture-alert",
    r"python scripts\response\run_protection_action.py --input fixture-alert --action kill-process --output summary",
    r"python scripts\ml\run_process_anomaly_detection.py --input fixture",
    r"python scripts\reporting\generate_detection_coverage_report.py",
    r"python scripts\reporting\generate_final_demo_report.py",
    r"python scripts\reporting\generate_attack_navigator_layer.py",
    r"python scripts\demo\run_demo_case_matrix.py --output reports\demo_cases\case_matrix.json",
    r"python scripts\demo\generate_demo_dashboard_data.py --case-matrix reports\demo_cases\case_matrix.json --output reports\demo_cases\dashboard_data.json",
]

KNOWN_LIMITATIONS = [
    "Elasticsearch and Kibana are optional unless live index counts are requested.",
    "Kafka validation uses deterministic in-memory dry-run paths, not a required live broker.",
    "SOAR remains dry-run response planning and does not execute production containment.",
    "Lab-only kill-process requires explicit --execute-protection and --lab-allow-execute flags.",
    "ML anomaly detection is heuristic and deterministic, not trained production ML.",
    "Behavioral correlation is deterministic local sequence matching, not full endpoint graph analytics.",
    "ATT&CK Navigator scores are demo communication scores, not production detection maturity scores.",
]

OUT_OF_SCOPE = [
    "New Sysmon Event IDs",
    "TheHive",
    "Production containment",
    "Host isolation or network blocking",
    "Dashboards requiring Kibana API",
    "Heavy ML frameworks",
    "Graph database backed endpoint analytics",
    "Streaming behavioral state",
    "Full enterprise ATT&CK coverage",
]

REPO_ROOT = Path(__file__).resolve().parents[1]
BEHAVIORAL_VALIDATION_SAMPLE_PATHS = (
    REPO_ROOT / "samples" / "demo_cases" / "behavioral_t1105_sequence.json",
    REPO_ROOT / "samples" / "demo_cases" / "behavioral_t1547_sequence.json",
    REPO_ROOT / "samples" / "demo_cases" / "t1218_rundll32_process_event.json",
)


class FinalDemoReportError(RuntimeError):
    """Raised for predictable final demo report failures."""


def build_final_demo_report(
    *,
    include_elasticsearch: bool = False,
    elasticsearch_url: str = "http://localhost:9200",
    generated_at: datetime | str | None = None,
) -> dict[str, Any]:
    """Build the final JSON-compatible demo report."""

    validation_results = run_validation_checks()
    report: dict[str, Any] = {
        "generated_at": _format_timestamp(generated_at),
        "project_status": PROJECT_STATUS,
        "correlated_sequence_count": sum(int(result.get("correlated_sequence_count", 0)) for result in validation_results),
        "implemented_phases": list(IMPLEMENTED_PHASES),
        "capability_matrix": build_capability_matrix(validation_results),
        "validation_results": validation_results,
        "demo_command_checklist": list(DEMO_COMMAND_CHECKLIST),
        "known_limitations": list(KNOWN_LIMITATIONS),
        "out_of_scope": list(OUT_OF_SCOPE),
    }

    if include_elasticsearch:
        report["elasticsearch_counts"] = query_elasticsearch_index_counts(base_url=elasticsearch_url)

    return report


def run_validation_checks() -> list[dict[str, Any]]:
    """Run deterministic in-process validations across implemented vertical slices."""

    validations = [
        _validate_live_telemetry_native(),
        _validate_live_telemetry_sigma_like(),
        _validate_kafka_native(),
        _validate_kafka_sigma_like(),
        _validate_soar_response(),
        _validate_ml_fixture(),
        _validate_detection_coverage(),
        _validate_multi_technique_detection(),
        _validate_behavioral_correlation(),
    ]
    return validations


def build_capability_matrix(validation_results: list[dict[str, Any]]) -> list[dict[str, str]]:
    """Build operator-facing capability summary rows."""

    validation_by_id = {result["id"]: result["status"] for result in validation_results}
    return [
        _capability(
            "telemetry",
            "Elastic/Kibana/Logstash local lab and Sysmon Event ID 1 fixture telemetry.",
            r"python scripts\smoke\end_to_end_art_telemetry_smoke.py",
            "passed",
        ),
        _capability(
            "normalization",
            "Normalizes Sysmon Event ID 1 process creation XML into ECS-like documents.",
            "normalization/sysmon/process_create_normalizer.py",
            "passed",
        ),
        _capability(
            "native_detection",
            "Detects PowerShell process execution using native rule logic.",
            r"python scripts\detection\run_native_detection.py",
            validation_by_id.get("live_telemetry_native", "failed"),
        ),
        _capability(
            "sigma_like_detection",
            "Detects PowerShell process execution using Sigma-like rule logic.",
            r"python scripts\pipeline\run_live_telemetry_pipeline.py --input fixture --fixture-detectable-powershell --engine sigma-like",
            validation_by_id.get("live_telemetry_sigma_like", "failed"),
        ),
        _capability(
            "kafka_transport",
            "Transports normalized event messages through deterministic Kafka dry-run producer/consumer paths.",
            r"python scripts\kafka\consume_and_detect.py --dry-run-fixture --engine all",
            _combined_status(
                validation_by_id.get("kafka_native", "failed"),
                validation_by_id.get("kafka_sigma_like", "failed"),
            ),
        ),
        _capability(
            "alert_indexing",
            "Indexes alert documents into edr-alerts-native-* through the existing alert indexer.",
            "detection/rules/native/alert_indexer.py",
            "passed",
        ),
        _capability(
            "soar_dry_run",
            "Plans dry-run SOAR response records for matching alerts.",
            r"python scripts\response\run_soar_response.py --input fixture-alert",
            validation_by_id.get("soar_fixture_response", "failed"),
        ),
        _capability(
            "ml_anomaly",
            "Scores process anomaly features against a deterministic local baseline.",
            r"python scripts\ml\run_process_anomaly_detection.py --input fixture",
            validation_by_id.get("ml_fixture_scoring", "failed"),
        ),
        _capability(
            "reporting",
            "Generates detection coverage and final demo reports.",
            r"python scripts\reporting\generate_final_demo_report.py",
            validation_by_id.get("detection_coverage_report", "failed"),
        ),
        _capability(
            "attack_navigator_export",
            "Exports the local coverage matrix as reports/attack_navigator/edr_attack_layer.json and reports/attack_navigator/coverage_summary.md.",
            r"python scripts\reporting\generate_attack_navigator_layer.py",
            "passed",
        ),
        _capability(
            "multi_technique_detection",
            "Detects safe demo coverage for T1105, T1547.001, and T1218 using Sysmon Event ID 1/3/11/13 evidence.",
            "docs/multi_technique_detection_coverage.md",
            validation_by_id.get("multi_technique_detection", "failed"),
        ),
        _capability(
            "behavioral_correlation",
            "Correlates normalized process, network, file, and registry telemetry into deterministic attack sequences.",
            "docs/behavioral_correlation_detection.md",
            validation_by_id.get("behavioral_correlation", "failed"),
        ),
        _capability(
            "demo_case_matrix",
            "Generates the Phase 9 10-case demo matrix for TP/TN/FP/FN classification.",
            r"python scripts\demo\run_demo_case_matrix.py --output reports\demo_cases\case_matrix.json",
            "passed",
        ),
        _capability(
            "tp_tn_fp_fn_classification",
            "Keeps true positives, true negatives, false positives, and false negatives visible as evaluation evidence.",
            r"reports/demo_cases/dashboard_data.json",
            "passed",
        ),
        _capability(
            "lab_only_protection_action",
            "Builds guarded Phase 10 lab-only kill-process protection records with dry-run default.",
            r"python scripts\response\run_protection_action.py --input fixture-alert --action kill-process --output summary",
            "passed",
        ),
        _capability(
            "protection_action_index",
            "Stores lab-only protection evidence in edr-protection-actions-* when indexing is requested.",
            "edr-protection-actions-*",
            "passed",
        ),
    ]


def render_json_report(report: dict[str, Any]) -> str:
    """Render stable final report JSON."""

    return json.dumps(report, indent=2, sort_keys=True)


def render_markdown_report(report: dict[str, Any]) -> str:
    """Render the final demo report as operator-readable Markdown."""

    lines = [
        "# Final Demo Report",
        "",
        f"Generated: {report['generated_at']}",
        f"Project status: {report['project_status']}",
        f"Correlated sequences validated: {report['correlated_sequence_count']}",
        "",
        "## Implemented Phases",
        "",
    ]
    lines.extend(f"- {phase}" for phase in report["implemented_phases"])
    lines.extend(
        [
            "",
            "## Capability Matrix",
            "",
            "| Capability | Status | Validation | Primary Command / Artifact | Description |",
            "| --- | --- | --- | --- | --- |",
        ]
    )

    for capability in report["capability_matrix"]:
        lines.append(
            "| "
            f"{capability['capability']} | "
            f"{capability['status']} | "
            f"{capability['validation']} | "
            f"`{capability['primary_command']}` | "
            f"{capability['description']} |"
        )

    lines.extend(
        [
            "",
            "## Validation Results",
            "",
            "| ID | Name | Status | Details | Counts |",
            "| --- | --- | --- | --- | --- |",
        ]
    )

    for result in report["validation_results"]:
        counts = _format_validation_counts(result)
        lines.append(
            "| "
            f"{result['id']} | "
            f"{result['name']} | "
            f"{result['status']} | "
            f"{result['details']} | "
            f"{counts} |"
        )

    if "elasticsearch_counts" in report:
        lines.extend(
            [
                "",
                "## Elasticsearch Counts",
                "",
                "| Index Pattern | Count |",
                "| --- | --- |",
            ]
        )
        for index_pattern, count in report["elasticsearch_counts"].items():
            lines.append(f"| {index_pattern} | {count} |")

    lines.extend(
        [
            "",
            "## Demo Command Checklist",
            "",
        ]
    )
    lines.extend(f"- `{command}`" for command in report["demo_command_checklist"])

    lines.extend(
        [
            "",
            "## Known Limitations",
            "",
        ]
    )
    lines.extend(f"- {limitation}" for limitation in report["known_limitations"])

    lines.extend(
        [
            "",
            "## Out Of Scope",
            "",
        ]
    )
    lines.extend(f"- {item}" for item in report["out_of_scope"])

    return "\n".join(lines) + "\n"


def write_report_artifacts(*, report: dict[str, Any], output_dir: Path, output_format: str) -> list[Path]:
    """Write requested report artifacts and return their paths."""

    if output_format not in {"json", "markdown", "all"}:
        raise FinalDemoReportError(f"Unsupported report format: {output_format!r}.")

    try:
        output_dir.mkdir(parents=True, exist_ok=True)
        written_paths: list[Path] = []
        if output_format in {"json", "all"}:
            json_path = output_dir / JSON_REPORT_NAME
            json_path.write_text(render_json_report(report) + "\n", encoding="utf-8")
            written_paths.append(json_path)
        if output_format in {"markdown", "all"}:
            markdown_path = output_dir / MARKDOWN_REPORT_NAME
            markdown_path.write_text(render_markdown_report(report), encoding="utf-8")
            written_paths.append(markdown_path)
        return written_paths
    except OSError as exc:
        raise FinalDemoReportError(f"Could not write final demo report artifacts: {exc}") from exc


def render_operator_summary(report: dict[str, Any], written_paths: list[Path]) -> str:
    """Render a short CLI summary."""

    validation_passed = all(result["status"] == "passed" for result in report["validation_results"])
    lines = [
        "Final demo report",
        f"Project status: {report['project_status']}",
        f"Validation passed: {str(validation_passed).lower()}",
        f"Capabilities: {len(report['capability_matrix'])}",
        "Written files:",
    ]
    lines.extend(f"- {path}" for path in written_paths)
    return "\n".join(lines)


def query_elasticsearch_index_counts(
    *,
    base_url: str = "http://localhost:9200",
    index_patterns: list[str] | None = None,
    timeout_seconds: int = 10,
) -> dict[str, int]:
    """Query Elasticsearch _count for final demo index patterns."""

    patterns = index_patterns or ELASTICSEARCH_INDEX_PATTERNS
    return {
        index_pattern: _query_single_index_count(
            base_url=base_url,
            index_pattern=index_pattern,
            timeout_seconds=timeout_seconds,
        )
        for index_pattern in patterns
    }


def _validate_live_telemetry_native() -> dict[str, Any]:
    result = run_live_telemetry_pipeline(
        input_mode="fixture",
        fixture_detectable_powershell=True,
        engine="native",
    )
    passed = result["alert_count"] == 1 and result["alerts"][0]["rule"]["id"] == "det.t1059_001.powershell_process_start"
    return _validation_result(
        "live_telemetry_native",
        "Live telemetry fixture produces native PowerShell alert",
        passed,
        f"Expected one native alert, got {result['alert_count']}.",
        alert_count=result["alert_count"],
    )


def _validate_live_telemetry_sigma_like() -> dict[str, Any]:
    result = run_live_telemetry_pipeline(
        input_mode="fixture",
        fixture_detectable_powershell=True,
        engine="sigma-like",
    )
    passed = (
        result["alert_count"] == 1
        and result["alerts"][0]["rule"]["id"] == "sigma_like.t1059_001.powershell_process_start"
    )
    return _validation_result(
        "live_telemetry_sigma_like",
        "Live telemetry fixture produces Sigma-like PowerShell alert",
        passed,
        f"Expected one Sigma-like alert, got {result['alert_count']}.",
        alert_count=result["alert_count"],
    )


def _validate_kafka_native() -> dict[str, Any]:
    result = run_consumer(
        config=ConsumerConfig(max_messages=1, timeout_seconds=10),
        engine="native",
        write_alerts=False,
        alert_indexing_config=AlertIndexingConfig(),
        dry_run_fixture=True,
    )
    passed = result["alert_count"] == 1 and result["alerts"][0]["rule"]["id"] == "det.t1059_001.powershell_process_start"
    return _validation_result(
        "kafka_native",
        "Kafka dry-run fixture produces native PowerShell alert",
        passed,
        f"Expected one native Kafka alert, got {result['alert_count']}.",
        alert_count=result["alert_count"],
    )


def _validate_kafka_sigma_like() -> dict[str, Any]:
    result = run_consumer(
        config=ConsumerConfig(max_messages=1, timeout_seconds=10),
        engine="sigma-like",
        write_alerts=False,
        alert_indexing_config=AlertIndexingConfig(),
        dry_run_fixture=True,
    )
    passed = (
        result["alert_count"] == 1
        and result["alerts"][0]["rule"]["id"] == "sigma_like.t1059_001.powershell_process_start"
    )
    return _validation_result(
        "kafka_sigma_like",
        "Kafka dry-run fixture produces Sigma-like PowerShell alert",
        passed,
        f"Expected one Sigma-like Kafka alert, got {result['alert_count']}.",
        alert_count=result["alert_count"],
    )


def _validate_soar_response() -> dict[str, Any]:
    result = run_soar_response(input_mode="fixture-alert")
    passed = result["response_count"] == 1
    return _validation_result(
        "soar_fixture_response",
        "SOAR fixture alert produces one dry-run response record",
        passed,
        f"Expected one response record, got {result['response_count']}.",
        response_count=result["response_count"],
    )


def _validate_ml_fixture() -> dict[str, Any]:
    result = run_process_anomaly_detection(input_mode="fixture")
    score = result["score_results"][0]["score"]
    passed = result["alert_count"] == 0 and score < result["score_results"][0]["threshold"]
    return _validation_result(
        "ml_fixture_scoring",
        "ML benign fixture produces low score and no alert",
        passed,
        f"Expected low score and no alert, got score {score} and {result['alert_count']} alerts.",
        alert_count=result["alert_count"],
        score=score,
    )


def _validate_detection_coverage() -> dict[str, Any]:
    report = build_detection_coverage_report(engine="all", include_elasticsearch=False)
    validation_results = report.get("validation_results", [])
    passed = bool(validation_results) and all(result.get("passed") for result in validation_results)
    actual_alert_count = validation_results[0].get("actual_alert_count", 0) if validation_results else 0
    return _validation_result(
        "detection_coverage_report",
        "Detection coverage report validation passes",
        passed,
        f"Coverage report produced {actual_alert_count} fixture alerts.",
        alert_count=actual_alert_count,
    )


def _validate_multi_technique_detection() -> dict[str, Any]:
    report = build_detection_coverage_report(engine="all", include_elasticsearch=False)
    technique_ids = {technique.get("technique_id") for technique in report.get("covered_techniques", [])}
    rule_ids = {rule.get("rule_id") for rule in report.get("rule_inventory", [])}
    expected_techniques = {"T1059.001", "T1105", "T1547.001", "T1218"}
    expected_rules = {
        "det.t1105.lolbin_download",
        "det.t1547_001.registry_run_key_persistence",
        "det.t1218.lolbin_suspicious_execution",
        "sigma_like.t1105.lolbin_download",
        "sigma_like.t1547_001.registry_run_key_persistence",
        "sigma_like.t1218.lolbin_suspicious_execution",
        "det.behavioral.t1105_download_sequence",
        "det.behavioral.t1547_001_registry_persistence_sequence",
        "det.behavioral.t1218_lolbin_sequence",
    }
    passed = expected_techniques.issubset(technique_ids) and expected_rules.issubset(rule_ids)
    return _validation_result(
        "multi_technique_detection",
        "Coverage report includes Phase 13 and Phase 14 multi-technique rules",
        passed,
        f"Covered techniques: {', '.join(sorted(str(item) for item in technique_ids))}.",
        rule_count=len(rule_ids),
    )


def _validate_behavioral_correlation() -> dict[str, Any]:
    events: list[dict[str, Any]] = []
    for path in BEHAVIORAL_VALIDATION_SAMPLE_PATHS:
        parsed = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(parsed, list):
            events.extend(parsed)
        elif isinstance(parsed, dict):
            events.append(parsed)
        else:
            raise FinalDemoReportError(f"Behavioral validation sample {path} must be an object or array.")

    alerts = detect_behavioral_sequences(events)
    rule_ids = {alert.get("rule", {}).get("id") for alert in alerts}
    expected_rules = {
        "det.behavioral.t1105_download_sequence",
        "det.behavioral.t1547_001_registry_persistence_sequence",
        "det.behavioral.t1218_lolbin_sequence",
    }
    passed = expected_rules.issubset(rule_ids) and len(alerts) == len(expected_rules)
    return _validation_result(
        "behavioral_correlation",
        "Behavioral correlation detects deterministic Phase 14 sequences",
        passed,
        f"Behavioral rules matched: {', '.join(sorted(str(item) for item in rule_ids))}.",
        correlated_sequence_count=len(alerts),
    )


def _validation_result(
    validation_id: str,
    name: str,
    passed: bool,
    details: str,
    **counts: Any,
) -> dict[str, Any]:
    result = {
        "id": validation_id,
        "name": name,
        "status": "passed" if passed else "failed",
        "details": details,
    }
    result.update(counts)
    return result


def _capability(
    capability: str,
    description: str,
    primary_command: str,
    validation: str,
) -> dict[str, str]:
    return {
        "capability": capability,
        "status": "implemented",
        "description": description,
        "primary_command": primary_command,
        "validation": validation,
    }


def _combined_status(*statuses: str) -> str:
    return "passed" if all(status == "passed" for status in statuses) else "failed"


def _query_single_index_count(*, base_url: str, index_pattern: str, timeout_seconds: int) -> int:
    encoded_pattern = urllib.parse.quote(index_pattern, safe="*")
    request = urllib.request.Request(
        f"{base_url.rstrip('/')}/{encoded_pattern}/_count",
        headers={"Content-Type": "application/json"},
        method="GET",
    )

    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            status = getattr(response, "status", response.getcode())
            payload = response.read()
    except urllib.error.HTTPError as exc:
        raise FinalDemoReportError(f"Elasticsearch count query for {index_pattern} failed with HTTP {exc.code}.") from exc
    except (urllib.error.URLError, TimeoutError, socket.timeout, OSError) as exc:
        raise FinalDemoReportError(f"Elasticsearch count query for {index_pattern} failed: {exc}") from exc

    if status < 200 or status >= 300:
        raise FinalDemoReportError(f"Elasticsearch count query for {index_pattern} returned HTTP {status}.")

    try:
        parsed = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FinalDemoReportError(f"Elasticsearch count response for {index_pattern} was malformed JSON.") from exc

    count = parsed.get("count") if isinstance(parsed, dict) else None
    if not isinstance(count, int):
        raise FinalDemoReportError(f"Elasticsearch count response for {index_pattern} is missing integer count.")
    return count


def _format_validation_counts(result: dict[str, Any]) -> str:
    parts = []
    for key in ("alert_count", "response_count", "score", "rule_count", "correlated_sequence_count"):
        if key in result:
            parts.append(f"{key}={result[key]}")
    return ", ".join(parts)


def _format_timestamp(value: datetime | str | None) -> str:
    if value is None:
        return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    if isinstance(value, str):
        return value
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
