"""Run and render the Phase 9 demo case matrix."""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from collection.elasticsearch.event_indexer import EventIndexingConfig
from detection.behavioral.correlation import detect_behavioral_sequences
from detection.demo.case_catalog import DemoCase, load_demo_cases, validate_demo_cases
from detection.demo.classification import summarize_classifications, classify_case
from detection.rules.native.alert_indexer import AlertIndexingConfig
from response.soar.engine import plan_responses
from response.soar.loader import load_playbook
from response.soar.response_indexer import ResponseIndexingConfig, index_responses
from scripts.demo.run_art_sysmon_demo_validation import run_art_sysmon_demo_validation
from scripts.pipeline.run_live_telemetry_pipeline import run_live_telemetry_pipeline


DEFAULT_OUTPUT = Path("reports") / "demo_cases" / "case_matrix.json"


class DemoCaseRunnerError(RuntimeError):
    """Raised for predictable case matrix failures."""


def run_case_matrix(
    *,
    cases: list[DemoCase] | None = None,
    case_ids: list[str] | None = None,
    write_events: bool = False,
    write_alerts: bool = False,
    write_response: bool = False,
    elasticsearch_url: str = "http://localhost:9200",
    include_failures: bool = True,
) -> dict[str, Any]:
    """Run selected cases and return the full matrix document."""

    selected_cases = list(cases or load_demo_cases())
    validate_demo_cases(selected_cases)
    if case_ids:
        wanted = set(case_ids)
        selected_cases = [case for case in selected_cases if case.case_id in wanted]
        missing = sorted(wanted - {case.case_id for case in selected_cases})
        if missing:
            raise DemoCaseRunnerError(f"Unknown case_id filter(s): {', '.join(missing)}.")

    rows = [
        run_demo_case(
            case,
            write_events=write_events,
            write_alerts=write_alerts,
            write_response=write_response,
            elasticsearch_url=elasticsearch_url,
        )
        for case in selected_cases
    ]
    if not include_failures:
        rows = [row for row in rows if row["status"] != "failed"]

    classification_counts = summarize_classifications(rows)
    return {
        "generated_at": _now(),
        "case_count": len(rows),
        **classification_counts,
        "cases": rows,
    }


def run_demo_case(
    case: DemoCase,
    *,
    write_events: bool = False,
    write_alerts: bool = False,
    write_response: bool = False,
    elasticsearch_url: str = "http://localhost:9200",
) -> dict[str, Any]:
    """Run one demo case and classify the result."""

    try:
        result = _run_case_pipeline(
            case,
            write_events=write_events,
            write_alerts=write_alerts,
            write_response=write_response,
            elasticsearch_url=elasticsearch_url,
        )
        return _build_case_row(case, result, status="completed", error=None)
    except Exception as exc:  # noqa: BLE001 - per-case failures are preserved in the matrix.
        empty = {
            "normalized_event_count": 0,
            "alerts": [],
            "responses": [],
            "indexed_event_count": 0,
            "indexed_alert_count": 0,
            "indexed_response_count": 0,
        }
        return _build_case_row(case, empty, status="failed", error=str(exc))


def write_case_matrix(matrix: dict[str, Any], *, output: Path, markdown_output: Path | None = None) -> None:
    """Write JSON and Markdown case matrix artifacts."""

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(matrix, indent=2, sort_keys=True), encoding="utf-8")
    md_path = markdown_output or output.with_suffix(".md")
    md_path.parent.mkdir(parents=True, exist_ok=True)
    md_path.write_text(render_case_matrix_markdown(matrix), encoding="utf-8")


def render_case_matrix_markdown(matrix: dict[str, Any]) -> str:
    """Render an operator-readable Markdown matrix."""

    lines = [
        "# Demo Case Matrix",
        "",
        f"Generated at: `{matrix['generated_at']}`",
        "",
        "## Summary",
        "",
        f"- Total cases: {matrix['case_count']}",
        f"- True positives: {matrix['true_positive_count']}",
        f"- True negatives: {matrix['true_negative_count']}",
        f"- False positives: {matrix['false_positive_count']}",
        f"- False negatives: {matrix['false_negative_count']}",
        "",
        "## Cases",
        "",
        "| Case | Category | Expected | Actual | Classification | Alerts | Responses | Notes |",
        "| --- | --- | --- | --- | --- | ---: | ---: | --- |",
    ]
    for row in matrix["cases"]:
        lines.append(
            "| "
            f"`{row['case_id']}` | "
            f"{row['category']} | "
            f"{row['expected_alert']} | "
            f"{row['actual_alert']} | "
            f"{row['classification']} | "
            f"{row['alert_count']} | "
            f"{row['response_count']} | "
            f"{row['teacher_demo_notes']} |"
        )
    return "\n".join(lines) + "\n"


def build_dashboard_data(matrix: dict[str, Any]) -> dict[str, Any]:
    """Build dashboard-ready aggregate data from a case matrix."""

    rows = list(matrix.get("cases", []))
    alert_count_by_rule: dict[str, int] = {}
    alert_count_by_engine: dict[str, int] = {}
    alert_count_by_technique: dict[str, int] = {}
    event_count_by_code: dict[str, int] = {}
    protection_count: dict[str, int] = {}
    response_count = 0
    correlated_sequence_count = 0
    sequence_count_by_name: dict[str, int] = {}
    case_rows = []

    for row in rows:
        response_count += int(row.get("response_count", 0))
        correlated_sequence_count += int(row.get("correlated_sequence_count", 0))
        protection = row.get("expected_protection", "none")
        protection_count[protection] = protection_count.get(protection, 0) + 1
        for rule_id in row.get("actual_rule_ids", []):
            alert_count_by_rule[rule_id] = alert_count_by_rule.get(rule_id, 0) + 1
        for engine in row.get("actual_engines", []):
            alert_count_by_engine[engine] = alert_count_by_engine.get(engine, 0) + 1
        for sequence_name in row.get("actual_sequence_names", []):
            sequence_count_by_name[sequence_name] = sequence_count_by_name.get(sequence_name, 0) + 1
        technique_id = row.get("technique_id")
        if row.get("actual_alert") and isinstance(technique_id, str) and technique_id:
            alert_count_by_technique[technique_id] = alert_count_by_technique.get(technique_id, 0) + int(
                row.get("alert_count", 0)
            )
        event_code = row.get("event_code")
        if event_code is not None:
            key = str(event_code)
            event_count_by_code[key] = event_count_by_code.get(key, 0) + 1
        case_rows.append(
            {
                "case_id": row.get("case_id"),
                "name": row.get("name"),
                "category": row.get("category"),
                "technique_id": row.get("technique_id"),
                "runner_mode": row.get("runner_mode"),
                "classification": row.get("classification"),
                "expected_alert": row.get("expected_alert"),
                "actual_alert": row.get("actual_alert"),
                "alert_count": row.get("alert_count"),
                "correlated_sequence_count": row.get("correlated_sequence_count", 0),
                "event_code": row.get("event_code"),
                "actual_rule_ids": row.get("actual_rule_ids", []),
                "actual_engines": row.get("actual_engines", []),
                "actual_sequence_names": row.get("actual_sequence_names", []),
                "response_count": row.get("response_count"),
                "expected_protection": row.get("expected_protection"),
                "teacher_demo_notes": row.get("teacher_demo_notes"),
            }
        )

    return {
        "generated_at": _now(),
        "total_cases": len(rows),
        "true_positive_count": int(matrix.get("true_positive_count", 0)),
        "true_negative_count": int(matrix.get("true_negative_count", 0)),
        "false_positive_count": int(matrix.get("false_positive_count", 0)),
        "false_negative_count": int(matrix.get("false_negative_count", 0)),
        "alert_count_by_rule": alert_count_by_rule,
        "alert_count_by_engine": alert_count_by_engine,
        "alert_count_by_technique": alert_count_by_technique,
        "event_count_by_code": event_count_by_code,
        "response_count": response_count,
        "correlated_sequence_count": correlated_sequence_count,
        "sequence_count_by_name": sequence_count_by_name,
        "protection_count": protection_count,
        "case_rows": case_rows,
    }


def write_dashboard_data(*, case_matrix_path: Path, output: Path) -> dict[str, Any]:
    """Read a matrix JSON file and write dashboard data JSON."""

    try:
        matrix = json.loads(case_matrix_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise DemoCaseRunnerError(f"Could not read case matrix {case_matrix_path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise DemoCaseRunnerError(f"Case matrix JSON is malformed: {exc}") from exc
    data = build_dashboard_data(matrix)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
    return data


def _run_case_pipeline(
    case: DemoCase,
    *,
    write_events: bool,
    write_alerts: bool,
    write_response: bool,
    elasticsearch_url: str,
) -> dict[str, Any]:
    if case.runner_mode == "phase8":
        return run_art_sysmon_demo_validation(
            input_mode=case.input_type,
            xml_path=case.input_path if case.input_type == "xml" else None,
            event_path=case.input_path if case.input_type == "json" else None,
            engine=case.engine,
            write_events=write_events,
            write_alerts=write_alerts,
            write_response=write_response,
            elasticsearch_url=elasticsearch_url,
        )

    if case.runner_mode == "ml":
        return run_art_sysmon_demo_validation(
            input_mode="json",
            event_path=case.input_path,
            engine="ml-anomaly",
            write_alerts=write_alerts,
            elasticsearch_url=elasticsearch_url,
        )

    if case.runner_mode == "live":
        pipeline_result = run_live_telemetry_pipeline(
            input_mode=case.input_type,
            xml_path=case.input_path if case.input_type == "xml" else None,
            write_events=write_events,
            write_alerts=write_alerts,
            event_indexing_config=EventIndexingConfig(base_url=elasticsearch_url),
            alert_indexing_config=AlertIndexingConfig(base_url=elasticsearch_url),
            fixture_detectable_powershell=False,
            engine=case.engine if case.engine != "ml-anomaly" else "all",
        )
        alerts = list(pipeline_result["alerts"])
        responses = []
        response_index_results = []
        if write_response and alerts:
            responses = plan_responses(alerts, [load_playbook()])
            if responses:
                response_index_results = index_responses(
                    responses,
                    ResponseIndexingConfig(base_url=elasticsearch_url),
                )
        return {
            "input": case.input_type,
            "engine": case.engine,
            "normalized_event_count": pipeline_result["normalized_event_count"],
            "alerts": alerts,
            "responses": responses,
            "indexed_event_count": pipeline_result["event_indexed_count"],
            "indexed_alert_count": pipeline_result["alert_indexed_count"],
            "indexed_response_count": len(response_index_results),
            "event_index_results": pipeline_result["event_index_results"],
            "alert_index_results": pipeline_result["alert_index_results"],
            "response_index_results": [asdict(indexed) for indexed in response_index_results],
        }

    if case.runner_mode == "behavioral":
        return _run_behavioral_case(case)

    raise DemoCaseRunnerError(f"Unsupported runner mode: {case.runner_mode!r}.")


def _run_behavioral_case(case: DemoCase) -> dict[str, Any]:
    if case.input_path is None:
        raise DemoCaseRunnerError(f"{case.case_id} requires an input_path.")

    events = json.loads(case.input_path.read_text(encoding="utf-8"))
    if not isinstance(events, list) or not all(isinstance(event, dict) for event in events):
        raise DemoCaseRunnerError(f"{case.case_id} behavioral sample must be a JSON array of events.")

    alerts = detect_behavioral_sequences(events)
    return {
        "input": "json",
        "engine": "behavioral",
        "normalized_event_count": len(events),
        "alerts": alerts,
        "responses": [],
        "indexed_event_count": 0,
        "indexed_alert_count": 0,
        "indexed_response_count": 0,
        "normalized_events": events,
        "event_index_results": [],
        "alert_index_results": [],
        "response_index_results": [],
        "behavioral_alert_count": len(alerts),
    }


def _build_case_row(case: DemoCase, result: dict[str, Any], *, status: str, error: str | None) -> dict[str, Any]:
    alerts = list(result.get("alerts", []))
    responses = list(result.get("responses", []))
    actual_rule_ids = _unique([alert.get("rule", {}).get("id") for alert in alerts])
    actual_engines = _unique([alert.get("detection", {}).get("engine") or "native" for alert in alerts])
    actual_sequence_names = _unique([alert.get("detection", {}).get("sequence_name") for alert in alerts])
    actual_alert = bool(alerts)
    correlated_sequence_count = sum(1 for alert in alerts if alert.get("detection", {}).get("engine") == "behavioral")
    return {
        "case_id": case.case_id,
        "name": case.name,
        "category": case.category,
        "technique_id": case.technique_id,
        "input_type": case.input_type,
        "input_path": str(case.input_path) if case.input_path else None,
        "runner_mode": case.runner_mode,
        "engine": case.engine,
        "expected_alert": case.expected_alert,
        "actual_alert": actual_alert,
        "classification": classify_case(expected_alert=case.expected_alert, actual_alert=actual_alert),
        "expected_engines": list(case.expected_engines),
        "expected_rule_ids": list(case.expected_rule_ids),
        "actual_engines": actual_engines,
        "actual_rule_ids": actual_rule_ids,
        "actual_sequence_names": actual_sequence_names,
        "expected_response": case.expected_response,
        "expected_protection": case.expected_protection,
        "normalized_event_count": int(result.get("normalized_event_count", 0)),
        "event_code": _first_event_code(result),
        "alert_count": len(alerts),
        "correlated_sequence_count": correlated_sequence_count,
        "response_count": len(responses),
        "indexed_event_count": int(result.get("indexed_event_count", 0)),
        "indexed_alert_count": int(result.get("indexed_alert_count", 0)),
        "indexed_response_count": int(result.get("indexed_response_count", 0)),
        "status": status,
        "error": error,
        "description": case.description,
        "teacher_demo_notes": case.teacher_demo_notes,
    }


def _unique(values: list[Any]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if not isinstance(value, str) or not value or value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


def _first_event_code(result: dict[str, Any]) -> Any:
    events = result.get("normalized_events")
    if not isinstance(events, list) or not events:
        return None
    codes: list[str] = []
    for event in events:
        if not isinstance(event, dict):
            continue
        event_meta = event.get("event")
        if not isinstance(event_meta, dict):
            continue
        code = event_meta.get("code")
        if code is None:
            continue
        code_text = str(code)
        if code_text not in codes:
            codes.append(code_text)
    if not codes:
        return None
    if len(codes) == 1:
        return codes[0]
    return "/".join(codes)


def _now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
