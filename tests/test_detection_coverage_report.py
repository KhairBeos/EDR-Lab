import json
import urllib.error

import pytest

from reporting import detection_coverage
from reporting.detection_coverage import DetectionCoverageReportError
from scripts.reporting import generate_detection_coverage_report


def test_rule_inventory_includes_native_powershell_rule() -> None:
    inventory = detection_coverage.build_rule_inventory()

    native = next(rule for rule in inventory if rule["engine"] == "native")

    assert native["rule_id"] == "det.t1059_001.powershell_process_start"
    assert native["name"] == "PowerShell Process Execution"
    assert native["severity"] == "medium"
    assert native["confidence"] == "high"
    assert native["attack"]["technique_id"] == "T1059.001"
    assert native["supported_datasource"] == {
        "event_dataset": "windows.sysmon_operational",
        "event_code": 1,
    }


def test_rule_inventory_includes_sigma_like_powershell_rule() -> None:
    inventory = detection_coverage.build_rule_inventory()

    sigma_like = next(rule for rule in inventory if rule["engine"] == "sigma-like")

    assert sigma_like["rule_id"] == "sigma_like.t1059_001.powershell_process_start"
    assert sigma_like["name"] == "PowerShell Process Execution"
    assert sigma_like["severity"] == "medium"
    assert sigma_like["confidence"] == "high"
    assert sigma_like["attack"]["technique_id"] == "T1059.001"
    assert sigma_like["supported_datasource"]["event_dataset"] == "windows.sysmon_operational"
    assert sigma_like["supported_datasource"]["event_code"] == 1


def test_engine_coverage_summary_reports_rule_counts() -> None:
    inventory = detection_coverage.build_rule_inventory()

    summary = detection_coverage.build_engine_coverage_summary(inventory)

    assert summary == {
        "native_rule_count": 4,
        "sigma_like_rule_count": 4,
        "behavioral_rule_count": 3,
        "total_rule_count": 11,
    }


def test_report_includes_covered_technique_and_sysmon_event_id() -> None:
    report = detection_coverage.build_detection_coverage_report(generated_at="2026-06-17T00:00:00Z")

    technique = report["covered_techniques"][0]
    assert technique["technique_id"] == "T1059.001"
    assert technique["technique_name"] == "PowerShell"
    assert technique["datasource"]["event_code"] == 1
    assert technique["engines"] == ["native", "sigma-like"]


@pytest.mark.parametrize(
    ("engine", "expected_alert_count"),
    [
        ("all", 2),
        ("native", 1),
        ("sigma-like", 1),
    ],
)
def test_fixture_validation_passes_for_supported_engines(engine: str, expected_alert_count: int) -> None:
    result = detection_coverage.run_fixture_validation(engine=engine)

    assert result["passed"] is True
    assert result["normalized_event_count"] == 1
    assert result["actual_alert_count"] == expected_alert_count
    assert result["expected_alert_count"] == expected_alert_count


def test_json_report_renderer_outputs_valid_json() -> None:
    report = detection_coverage.build_detection_coverage_report(generated_at="2026-06-17T00:00:00Z")

    rendered = detection_coverage.render_json_report(report)
    parsed = json.loads(rendered)

    assert parsed["project_phase"] == "Phase 14 Behavioral Correlation Detection"


def test_markdown_report_renderer_includes_key_coverage_terms() -> None:
    report = detection_coverage.build_detection_coverage_report(generated_at="2026-06-17T00:00:00Z")

    rendered = detection_coverage.render_markdown_report(report)

    assert "# Detection Coverage Report" in rendered
    assert "T1059.001" in rendered
    assert "native" in rendered
    assert "sigma-like" in rendered


def test_cli_default_writes_json_and_markdown_reports(tmp_path) -> None:
    exit_code = generate_detection_coverage_report.main(["--output-dir", str(tmp_path)])

    assert exit_code == 0
    assert (tmp_path / "detection_coverage_report.json").exists()
    assert (tmp_path / "detection_coverage_report.md").exists()


def test_cli_format_json_writes_only_json_report(tmp_path) -> None:
    exit_code = generate_detection_coverage_report.main(
        ["--output-dir", str(tmp_path), "--format", "json"]
    )

    assert exit_code == 0
    assert (tmp_path / "detection_coverage_report.json").exists()
    assert not (tmp_path / "detection_coverage_report.md").exists()


def test_cli_format_markdown_writes_only_markdown_report(tmp_path) -> None:
    exit_code = generate_detection_coverage_report.main(
        ["--output-dir", str(tmp_path), "--format", "markdown"]
    )

    assert exit_code == 0
    assert not (tmp_path / "detection_coverage_report.json").exists()
    assert (tmp_path / "detection_coverage_report.md").exists()


def test_elasticsearch_section_is_omitted_by_default() -> None:
    report = detection_coverage.build_detection_coverage_report()

    assert "elasticsearch" not in report


def test_elasticsearch_section_appears_only_when_requested(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_query_elasticsearch_alert_counts(**_: object) -> dict:
        return {
            "alert_index_pattern": "edr-alerts-native-*",
            "total_matching_alerts": 3,
            "native_alert_count": 1,
            "sigma_like_alert_count": 2,
        }

    monkeypatch.setattr(detection_coverage, "query_elasticsearch_alert_counts", fake_query_elasticsearch_alert_counts)

    report = detection_coverage.build_detection_coverage_report(include_elasticsearch=True)

    assert report["elasticsearch"] == {
        "alert_index_pattern": "edr-alerts-native-*",
        "total_matching_alerts": 3,
        "native_alert_count": 1,
        "sigma_like_alert_count": 2,
    }


def test_elasticsearch_query_can_be_monkeypatched(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeResponse:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *_: object) -> None:
            return None

        def read(self) -> bytes:
            return json.dumps(
                {
                    "hits": {"total": {"value": 5}},
                    "aggregations": {
                        "native": {"doc_count": 2},
                        "sigma_like": {"doc_count": 3},
                    },
                }
            ).encode("utf-8")

        def getcode(self) -> int:
            return 200

    calls = []

    def fake_urlopen(request: object, timeout: int = 10) -> FakeResponse:
        calls.append({"request": request, "timeout": timeout})
        return FakeResponse()

    monkeypatch.setattr(detection_coverage.urllib.request, "urlopen", fake_urlopen)

    result = detection_coverage.query_elasticsearch_alert_counts(
        base_url="http://localhost:9200",
        alert_index_pattern="edr-alerts-native-*",
    )

    assert calls
    assert result == {
        "alert_index_pattern": "edr-alerts-native-*",
        "total_matching_alerts": 5,
        "native_alert_count": 2,
        "sigma_like_alert_count": 3,
    }


def test_elasticsearch_query_failure_maps_to_exit_code_2(monkeypatch: pytest.MonkeyPatch, tmp_path, capsys) -> None:
    def fake_urlopen(*_: object, **__: object) -> object:
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr(detection_coverage.urllib.request, "urlopen", fake_urlopen)

    exit_code = generate_detection_coverage_report.main(
        ["--output-dir", str(tmp_path), "--include-elasticsearch"]
    )

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "Detection coverage report failed" in captured.err


def test_validation_failure_maps_to_exit_code_1(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    report = detection_coverage.build_detection_coverage_report(generated_at="2026-06-17T00:00:00Z")
    report["validation_results"][0]["passed"] = False

    def fake_build_detection_coverage_report(**_: object) -> dict:
        return report

    monkeypatch.setattr(
        generate_detection_coverage_report,
        "build_detection_coverage_report",
        fake_build_detection_coverage_report,
    )

    exit_code = generate_detection_coverage_report.main(["--output-dir", str(tmp_path)])

    assert exit_code == 1
    assert (tmp_path / "detection_coverage_report.json").exists()


def test_malformed_elasticsearch_response_raises_report_error(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeResponse:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *_: object) -> None:
            return None

        def read(self) -> bytes:
            return b"{not-json"

        def getcode(self) -> int:
            return 200

    monkeypatch.setattr(detection_coverage.urllib.request, "urlopen", lambda *_args, **_kwargs: FakeResponse())

    with pytest.raises(DetectionCoverageReportError, match="not valid JSON"):
        detection_coverage.query_elasticsearch_alert_counts()
