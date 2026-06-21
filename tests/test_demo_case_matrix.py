import json
from pathlib import Path

import pytest

from collection.elasticsearch.event_indexer import EventIndexResult
from detection.demo.case_catalog import (
    CATEGORIES,
    ENGINES,
    EXPECTED_PROTECTIONS,
    INPUT_TYPES,
    load_demo_cases,
    validate_demo_cases,
)
from detection.demo.case_runner import build_dashboard_data, run_case_matrix, write_case_matrix, write_dashboard_data
from detection.demo.classification import classify_case
from detection.rules.native.alert_indexer import AlertIndexResult
from response.soar.response_indexer import ResponseIndexResult
from scripts.demo import run_art_sysmon_demo_validation
from scripts.ml import run_process_anomaly_detection
from scripts.pipeline import run_live_telemetry_pipeline


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_catalog_returns_around_10_cases() -> None:
    cases = load_demo_cases()

    assert 18 <= len(cases) <= 21


def test_catalog_includes_at_least_5_attack_cases_with_expected_alert() -> None:
    cases = load_demo_cases()

    attack_expected = [case for case in cases if case.category == "attack" and case.expected_alert]
    assert len(attack_expected) >= 5


def test_catalog_includes_at_least_2_benign_true_negative_expected_cases() -> None:
    cases = load_demo_cases()

    benign_no_alert = [case for case in cases if case.category == "benign" and not case.expected_alert]
    assert len(benign_no_alert) >= 2


def test_catalog_includes_expected_false_positive_analysis_case() -> None:
    cases = load_demo_cases()

    assert any(case.case_id == "analysis_fp_admin_powershell_inventory" for case in cases)


def test_catalog_includes_known_limitation_false_negative_case() -> None:
    cases = load_demo_cases()

    assert any(case.case_id == "limitation_fn_non_powershell_execution" for case in cases)


def test_case_ids_are_unique() -> None:
    cases = load_demo_cases()
    ids = [case.case_id for case in cases]

    assert len(ids) == len(set(ids))


def test_case_fields_validate_allowed_enums() -> None:
    cases = load_demo_cases()

    validate_demo_cases(cases)
    assert all(case.category in CATEGORIES for case in cases)
    assert all(case.input_type in INPUT_TYPES for case in cases)
    assert all(case.engine in ENGINES for case in cases)
    assert all(case.expected_protection in EXPECTED_PROTECTIONS for case in cases)


def test_classify_case_returns_true_positive() -> None:
    assert classify_case(expected_alert=True, actual_alert=True) == "true_positive"


def test_classify_case_returns_true_negative() -> None:
    assert classify_case(expected_alert=False, actual_alert=False) == "true_negative"


def test_classify_case_returns_false_positive() -> None:
    assert classify_case(expected_alert=False, actual_alert=True) == "false_positive"


def test_classify_case_returns_false_negative() -> None:
    assert classify_case(expected_alert=True, actual_alert=False) == "false_negative"


def test_matrix_runner_generates_rows_for_all_cases_without_live_infrastructure(monkeypatch: pytest.MonkeyPatch) -> None:
    _fail_if_indexers_called(monkeypatch)

    matrix = run_case_matrix()

    assert matrix["case_count"] == len(load_demo_cases())
    assert len(matrix["cases"]) == len(load_demo_cases())
    assert all(row["status"] == "completed" for row in matrix["cases"])


def test_matrix_runner_writes_json_and_markdown_outputs(tmp_path) -> None:
    matrix = run_case_matrix()
    output = tmp_path / "case_matrix.json"
    markdown = tmp_path / "case_matrix.md"

    write_case_matrix(matrix, output=output, markdown_output=markdown)

    assert output.exists()
    assert markdown.exists()
    assert json.loads(output.read_text(encoding="utf-8"))["case_count"] == len(load_demo_cases())
    assert "Demo Case Matrix" in markdown.read_text(encoding="utf-8")


def test_matrix_includes_tp_tn_fp_fn_counts() -> None:
    matrix = run_case_matrix()

    assert matrix["true_positive_count"] >= 5
    assert matrix["true_negative_count"] >= 2
    assert matrix["false_positive_count"] >= 1
    assert matrix["false_negative_count"] >= 1


def test_matrix_includes_actual_alert_rule_ids_and_engines() -> None:
    matrix = run_case_matrix()
    rows = {row["case_id"]: row for row in matrix["cases"]}

    attack_row = rows["attack_t1059_001_art_powershell_xml"]
    assert "det.t1059_001.powershell_process_start" in attack_row["actual_rule_ids"]
    assert "sigma_like.t1059_001.powershell_process_start" in attack_row["actual_rule_ids"]
    assert "native" in attack_row["actual_engines"]
    assert "sigma-like" in attack_row["actual_engines"]


def test_matrix_includes_response_counts_for_matching_alert_cases(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_indexers(monkeypatch)

    matrix = run_case_matrix(write_events=True, write_alerts=True, write_response=True)
    rows = {row["case_id"]: row for row in matrix["cases"]}

    assert rows["attack_t1059_001_art_powershell_xml"]["response_count"] >= 1
    assert rows["attack_t1059_001_art_powershell_xml"]["indexed_response_count"] >= 1


def test_write_flags_call_monkeypatched_indexers(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = {"events": 0, "alerts": 0, "responses": 0}

    def fake_index_event(event: dict, config: object, *, index_date: str | None = None) -> EventIndexResult:
        calls["events"] += 1
        return EventIndexResult(index="edr-normalized-events-2026.06.17", document_id="event-1", result="created", status=201)

    def fake_index_alerts(alerts: list[dict], config: object, *, index_date: str | None = None) -> list[AlertIndexResult]:
        calls["alerts"] += len(alerts)
        return [
            AlertIndexResult(
                index="edr-alerts-native-2026.06.17",
                document_id=alert["alert"]["id"],
                result="created",
                status=201,
            )
            for alert in alerts
        ]

    def fake_index_responses(
        records: list[dict], config: object, *, index_date: str | None = None
    ) -> list[ResponseIndexResult]:
        calls["responses"] += len(records)
        return [
            ResponseIndexResult(
                index="edr-response-actions-2026.06.17",
                document_id=record["response"]["id"],
                result="created",
                status=201,
            )
            for record in records
        ]

    monkeypatch.setattr(run_live_telemetry_pipeline, "index_event", fake_index_event)
    monkeypatch.setattr(run_live_telemetry_pipeline, "index_alerts", fake_index_alerts)
    monkeypatch.setattr(run_process_anomaly_detection, "index_alerts", fake_index_alerts)
    monkeypatch.setattr(run_art_sysmon_demo_validation, "index_responses", fake_index_responses)

    matrix = run_case_matrix(write_events=True, write_alerts=True, write_response=True)

    assert matrix["case_count"] == len(load_demo_cases())
    assert calls["events"] > 0
    assert calls["alerts"] > 0
    assert calls["responses"] > 0


def test_without_write_flags_indexers_are_not_called(monkeypatch: pytest.MonkeyPatch) -> None:
    _fail_if_indexers_called(monkeypatch)

    matrix = run_case_matrix()

    assert matrix["case_count"] == len(load_demo_cases())


def test_dashboard_data_generator_reads_matrix_file_and_writes_json(tmp_path) -> None:
    matrix = run_case_matrix()
    case_matrix_path = tmp_path / "case_matrix.json"
    dashboard_path = tmp_path / "dashboard_data.json"
    case_matrix_path.write_text(json.dumps(matrix), encoding="utf-8")

    data = write_dashboard_data(case_matrix_path=case_matrix_path, output=dashboard_path)

    assert dashboard_path.exists()
    assert data["total_cases"] == len(load_demo_cases())
    assert data["case_rows"]


def test_dashboard_data_includes_counts_by_classification_rule_and_engine() -> None:
    matrix = run_case_matrix()
    data = build_dashboard_data(matrix)

    assert data["true_positive_count"] >= 5
    assert data["true_negative_count"] >= 2
    assert data["false_positive_count"] >= 1
    assert data["false_negative_count"] >= 1
    assert data["alert_count_by_rule"]["det.t1059_001.powershell_process_start"] >= 1
    assert data["alert_count_by_engine"]["native"] >= 1


def test_docs_exist_and_mention_dashboard_terms() -> None:
    catalog = (REPO_ROOT / "docs" / "demo_case_catalog_10_cases.md").read_text(encoding="utf-8")
    dashboard = (REPO_ROOT / "docs" / "demo_dashboard_design.md").read_text(encoding="utf-8")

    for term in ["true_positive", "true_negative", "false_positive", "false_negative"]:
        assert term in catalog
    assert "Kibana" in dashboard
    assert "rule.id" in dashboard
    assert "detection.engine" in dashboard
    assert "Response Actions" in dashboard


def _fail_if_indexers_called(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_index_event(*_: object, **__: object) -> EventIndexResult:
        raise AssertionError("event indexer should not be called")

    def fail_index_alerts(*_: object, **__: object) -> list[AlertIndexResult]:
        raise AssertionError("alert indexer should not be called")

    def fail_index_responses(*_: object, **__: object) -> list[ResponseIndexResult]:
        raise AssertionError("response indexer should not be called")

    monkeypatch.setattr(run_live_telemetry_pipeline, "index_event", fail_index_event)
    monkeypatch.setattr(run_live_telemetry_pipeline, "index_alerts", fail_index_alerts)
    monkeypatch.setattr(run_process_anomaly_detection, "index_alerts", fail_index_alerts)
    monkeypatch.setattr(run_art_sysmon_demo_validation, "index_responses", fail_index_responses)


def _fake_indexers(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_index_event(event: dict, config: object, *, index_date: str | None = None) -> EventIndexResult:
        return EventIndexResult(index="edr-normalized-events-2026.06.17", document_id="event-1", result="created", status=201)

    def fake_index_alerts(alerts: list[dict], config: object, *, index_date: str | None = None) -> list[AlertIndexResult]:
        return [
            AlertIndexResult(
                index="edr-alerts-native-2026.06.17",
                document_id=alert["alert"]["id"],
                result="created",
                status=201,
            )
            for alert in alerts
        ]

    def fake_index_responses(
        records: list[dict], config: object, *, index_date: str | None = None
    ) -> list[ResponseIndexResult]:
        return [
            ResponseIndexResult(
                index="edr-response-actions-2026.06.17",
                document_id=record["response"]["id"],
                result="created",
                status=201,
            )
            for record in records
        ]

    monkeypatch.setattr(run_live_telemetry_pipeline, "index_event", fake_index_event)
    monkeypatch.setattr(run_live_telemetry_pipeline, "index_alerts", fake_index_alerts)
    monkeypatch.setattr(run_process_anomaly_detection, "index_alerts", fake_index_alerts)
    monkeypatch.setattr(run_art_sysmon_demo_validation, "index_responses", fake_index_responses)
