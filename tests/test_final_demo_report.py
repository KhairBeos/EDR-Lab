import json

import pytest

from reporting import final_demo_report
from reporting.final_demo_report import FinalDemoReportError
from scripts.reporting import generate_final_demo_report


def build_report() -> dict:
    return final_demo_report.build_final_demo_report(generated_at="2026-06-17T00:00:00Z")


def validation_by_id(report: dict) -> dict:
    return {result["id"]: result for result in report["validation_results"]}


def capability_names(report: dict) -> set[str]:
    return {capability["capability"] for capability in report["capability_matrix"]}


def test_report_data_includes_generated_at() -> None:
    assert build_report()["generated_at"] == "2026-06-17T00:00:00Z"


def test_report_data_includes_project_status() -> None:
    assert build_report()["project_status"] == "Phase 15 ATT&CK Navigator export ready"


def test_report_data_includes_all_completed_phases() -> None:
    phases = build_report()["implemented_phases"]

    assert "Phase 1 Foundation" in phases
    assert "Phase 2 Native Detection Pipeline MVP" in phases
    assert "Phase 3 Live Telemetry Pipeline, Sigma-like Detection, and Coverage Report" in phases
    assert "Phase 4 Kafka Normalized Event Detection Pipeline" in phases
    assert "Phase 5 SOAR Dry-run Response Pipeline" in phases
    assert "Phase 6 ML-style Process Anomaly Detection MVP" in phases
    assert "Phase 7 Final Demo Report and Operator Dashboard MVP" in phases
    assert "Phase 8 ART / Sysmon VM Demo" in phases
    assert "Phase 9 10-case TP/TN/FP/FN Demo Case Matrix" in phases
    assert "Phase 10 Lab-only Kill-process Protection Action" in phases
    assert "Phase 13 Multi-technique ATT&CK Demo Detection" in phases
    assert "Phase 14 Behavioral Correlation Detection" in phases
    assert "Phase 15 ATT&CK Navigator Coverage Export" in phases


@pytest.mark.parametrize(
    "capability",
    [
        "telemetry",
        "normalization",
        "native_detection",
        "sigma_like_detection",
        "kafka_transport",
        "alert_indexing",
        "soar_dry_run",
        "ml_anomaly",
        "reporting",
        "demo_case_matrix",
        "tp_tn_fp_fn_classification",
        "lab_only_protection_action",
        "protection_action_index",
        "multi_technique_detection",
        "behavioral_correlation",
        "attack_navigator_export",
    ],
)
def test_capability_matrix_includes_required_capabilities(capability: str) -> None:
    assert capability in capability_names(build_report())


def test_live_telemetry_fixture_validation_passes_for_native_detection() -> None:
    result = validation_by_id(build_report())["live_telemetry_native"]

    assert result["status"] == "passed"
    assert result["alert_count"] == 1


def test_live_telemetry_fixture_validation_passes_for_sigma_like_detection() -> None:
    result = validation_by_id(build_report())["live_telemetry_sigma_like"]

    assert result["status"] == "passed"
    assert result["alert_count"] == 1


def test_kafka_dry_run_fixture_validation_passes_for_native_detection() -> None:
    result = validation_by_id(build_report())["kafka_native"]

    assert result["status"] == "passed"
    assert result["alert_count"] == 1


def test_kafka_dry_run_fixture_validation_passes_for_sigma_like_detection() -> None:
    result = validation_by_id(build_report())["kafka_sigma_like"]

    assert result["status"] == "passed"
    assert result["alert_count"] == 1


def test_soar_fixture_validation_produces_one_response_record() -> None:
    result = validation_by_id(build_report())["soar_fixture_response"]

    assert result["status"] == "passed"
    assert result["response_count"] == 1


def test_ml_fixture_validation_produces_low_score_no_alert() -> None:
    result = validation_by_id(build_report())["ml_fixture_scoring"]

    assert result["status"] == "passed"
    assert result["score"] < 0.7
    assert result["alert_count"] == 0


def test_detection_coverage_report_validation_passes() -> None:
    result = validation_by_id(build_report())["detection_coverage_report"]

    assert result["status"] == "passed"
    assert result["alert_count"] == 2


def test_behavioral_correlation_validation_passes() -> None:
    result = validation_by_id(build_report())["behavioral_correlation"]

    assert result["status"] == "passed"
    assert result["correlated_sequence_count"] == 3


def test_command_generates_json_report_without_elasticsearch(tmp_path) -> None:
    exit_code = generate_final_demo_report.main(["--output-dir", str(tmp_path), "--format", "json"])

    assert exit_code == 0
    report_path = tmp_path / "final_demo_report.json"
    assert report_path.exists()
    parsed = json.loads(report_path.read_text(encoding="utf-8"))
    assert "elasticsearch_counts" not in parsed


def test_command_generates_markdown_report_without_elasticsearch(tmp_path) -> None:
    exit_code = generate_final_demo_report.main(["--output-dir", str(tmp_path), "--format", "markdown"])

    assert exit_code == 0
    report_path = tmp_path / "final_demo_report.md"
    assert report_path.exists()
    rendered = report_path.read_text(encoding="utf-8")
    assert "# Final Demo Report" in rendered
    assert "## Capability Matrix" in rendered


def test_format_json_writes_only_json(tmp_path) -> None:
    exit_code = generate_final_demo_report.main(["--output-dir", str(tmp_path), "--format", "json"])

    assert exit_code == 0
    assert (tmp_path / "final_demo_report.json").exists()
    assert not (tmp_path / "final_demo_report.md").exists()


def test_format_markdown_writes_only_markdown(tmp_path) -> None:
    exit_code = generate_final_demo_report.main(["--output-dir", str(tmp_path), "--format", "markdown"])

    assert exit_code == 0
    assert not (tmp_path / "final_demo_report.json").exists()
    assert (tmp_path / "final_demo_report.md").exists()


def test_format_all_writes_both(tmp_path) -> None:
    exit_code = generate_final_demo_report.main(["--output-dir", str(tmp_path), "--format", "all"])

    assert exit_code == 0
    assert (tmp_path / "final_demo_report.json").exists()
    assert (tmp_path / "final_demo_report.md").exists()


def test_elasticsearch_counts_are_absent_unless_requested() -> None:
    assert "elasticsearch_counts" not in build_report()


def test_elasticsearch_count_helper_can_be_monkeypatched(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_query_elasticsearch_index_counts(**_: object) -> dict[str, int]:
        return {
            "edr-normalized-events-*": 10,
            "edr-alerts-native-*": 4,
            "edr-response-actions-*": 1,
            "edr-protection-actions-*": 1,
        }

    monkeypatch.setattr(final_demo_report, "query_elasticsearch_index_counts", fake_query_elasticsearch_index_counts)

    report = final_demo_report.build_final_demo_report(include_elasticsearch=True)

    assert report["elasticsearch_counts"] == {
        "edr-normalized-events-*": 10,
        "edr-alerts-native-*": 4,
        "edr-response-actions-*": 1,
        "edr-protection-actions-*": 1,
    }


def test_requested_elasticsearch_query_failure_maps_to_exit_code_2(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
    capsys,
) -> None:
    def fake_query_elasticsearch_index_counts(**_: object) -> dict[str, int]:
        raise FinalDemoReportError("Elasticsearch unavailable")

    monkeypatch.setattr(final_demo_report, "query_elasticsearch_index_counts", fake_query_elasticsearch_index_counts)

    exit_code = generate_final_demo_report.main(
        ["--output-dir", str(tmp_path), "--include-elasticsearch"]
    )

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "Final demo report failed" in captured.err


def test_tests_do_not_require_live_elasticsearch(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_query_elasticsearch_index_counts(**_: object) -> dict[str, int]:
        raise AssertionError("Elasticsearch should not be queried by default")

    monkeypatch.setattr(final_demo_report, "query_elasticsearch_index_counts", fail_query_elasticsearch_index_counts)

    report = final_demo_report.build_final_demo_report(include_elasticsearch=False)

    assert "elasticsearch_counts" not in report


def test_existing_pipeline_behavior_remains_unchanged() -> None:
    report = build_report()

    assert validation_by_id(report)["live_telemetry_native"]["alert_count"] == 1
    assert validation_by_id(report)["kafka_sigma_like"]["alert_count"] == 1
