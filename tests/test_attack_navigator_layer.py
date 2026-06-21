import json

from reporting import attack_navigator_layer, final_demo_report
from scripts.demo import build_demo_evidence_bundle
from scripts.reporting import generate_attack_navigator_layer


def sample_coverage_report() -> dict:
    return {
        "project_phase": "Phase 14 Behavioral Correlation Detection",
        "covered_techniques": [
            {
                "technique_id": "T1059.001",
                "technique_name": "PowerShell",
                "tactic": ["Execution"],
                "datasource": {"event_code": 1},
                "engines": ["native", "sigma-like"],
            },
            {
                "technique_id": "T1105",
                "technique_name": "Ingress Tool Transfer",
                "tactic": ["Command and Control"],
                "datasource": {"event_code": "1/3/11"},
                "engines": ["native", "sigma-like", "behavioral"],
            },
            {
                "technique_id": "T1547.001",
                "technique_name": "Registry Run Keys / Startup Folder",
                "tactic": ["Persistence"],
                "datasource": {"event_code": "1/13"},
                "engines": ["native", "sigma-like", "behavioral"],
            },
            {
                "technique_id": "T1218",
                "technique_name": "System Binary Proxy Execution",
                "tactic": ["Defense Evasion"],
                "datasource": {"event_code": 1},
                "engines": ["native", "sigma-like", "behavioral"],
            },
        ],
        "rule_inventory": [
            rule("det.t1059_001.powershell_process_start", "native", "T1059.001", 1),
            rule("sigma_like.t1059_001.powershell_process_start", "sigma-like", "T1059.001", 1),
            rule("det.t1105.lolbin_download", "native", "T1105", "1/3/11"),
            rule("sigma_like.t1105.lolbin_download", "sigma-like", "T1105", "1/3/11"),
            rule("det.behavioral.t1105_download_sequence", "behavioral", "T1105", "1/3/11"),
            rule("det.t1547_001.registry_run_key_persistence", "native", "T1547.001", "13"),
            rule("sigma_like.t1547_001.registry_run_key_persistence", "sigma-like", "T1547.001", "13"),
            rule("det.behavioral.t1547_001_registry_persistence_sequence", "behavioral", "T1547.001", "1/13"),
            rule("det.t1218.lolbin_suspicious_execution", "native", "T1218", "1"),
            rule("sigma_like.t1218.lolbin_suspicious_execution", "sigma-like", "T1218", "1"),
            rule("det.behavioral.t1218_lolbin_sequence", "behavioral", "T1218", "1/3/11"),
        ],
    }


def rule(rule_id: str, engine: str, technique_id: str, event_code: int | str) -> dict:
    return {
        "rule_id": rule_id,
        "engine": engine,
        "attack": {
            "technique_id": technique_id,
            "technique_name": technique_id,
            "tactic": [],
        },
        "supported_datasource": {
            "event_code": event_code,
            "event_dataset": "windows.sysmon_operational",
        },
    }


def sample_case_matrix() -> dict:
    return {
        "cases": [
            {
                "technique_id": "T1059.001",
                "classification": "true_positive",
                "actual_engines": ["ml-anomaly"],
                "actual_rule_ids": ["ml.process_anomaly"],
                "event_code": "1",
                "expected_response": True,
                "expected_protection": "dry-run",
            },
            {
                "technique_id": "T1059.001",
                "classification": "false_positive",
                "actual_engines": ["native", "sigma-like"],
                "actual_rule_ids": ["det.t1059_001.powershell_process_start"],
                "event_code": "1",
                "expected_response": False,
                "expected_protection": "none",
            },
            {
                "technique_id": "T1059",
                "classification": "false_negative",
                "actual_engines": [],
                "actual_rule_ids": [],
                "event_code": "1",
                "expected_response": False,
                "expected_protection": "none",
            },
            {
                "technique_id": "T1105",
                "classification": "true_positive",
                "actual_engines": ["native", "sigma-like", "behavioral"],
                "actual_rule_ids": ["det.behavioral.t1105_download_sequence"],
                "event_code": "1/3/11",
                "expected_response": False,
                "expected_protection": "none",
            },
            {
                "technique_id": "T1547.001",
                "classification": "true_positive",
                "actual_engines": ["behavioral"],
                "actual_rule_ids": ["det.behavioral.t1547_001_registry_persistence_sequence"],
                "event_code": "1/13",
                "expected_response": False,
                "expected_protection": "none",
            },
            {
                "technique_id": "T1218",
                "classification": "true_positive",
                "actual_engines": ["native", "sigma-like"],
                "actual_rule_ids": ["det.t1218.lolbin_suspicious_execution"],
                "event_code": "1",
                "expected_response": False,
                "expected_protection": "none",
            },
        ]
    }


def sample_dashboard_data() -> dict:
    return {
        "correlated_sequence_count": 2,
        "sequence_count_by_name": {
            "t1105_download_sequence": 1,
            "t1547_001_registry_persistence_sequence": 1,
        },
    }


def build_layer() -> dict:
    coverage_report = sample_coverage_report()
    coverage_report["case_matrix"] = sample_case_matrix()
    coverage_report["dashboard_data"] = sample_dashboard_data()
    return attack_navigator_layer.build_attack_navigator_layer(coverage_report)


def technique_by_id(layer: dict, technique_id: str) -> dict:
    return next(technique for technique in layer["techniques"] if technique["techniqueID"] == technique_id)


def metadata_by_name(technique: dict) -> dict[str, str]:
    return {entry["name"]: entry["value"] for entry in technique["metadata"]}


def test_layer_contains_enterprise_attack_domain() -> None:
    assert build_layer()["domain"] == "enterprise-attack"


def test_layer_contains_required_techniques() -> None:
    technique_ids = [technique["techniqueID"] for technique in build_layer()["techniques"]]

    assert technique_ids == ["T1059.001", "T1105", "T1547.001", "T1218"]


def test_technique_entries_contain_score_color_comment_and_metadata() -> None:
    for technique in build_layer()["techniques"]:
        assert technique["score"]
        assert technique["color"].startswith("#")
        assert technique["comment"]
        assert technique["metadata"]


def test_t1105_metadata_includes_native_sigma_like_and_behavioral_engines() -> None:
    metadata = metadata_by_name(technique_by_id(build_layer(), "T1105"))

    assert "native" in metadata["engines"]
    assert "Sigma-like" in metadata["engines"]
    assert "behavioral" in metadata["engines"]


def test_t1547_metadata_includes_behavioral_engine() -> None:
    metadata = metadata_by_name(technique_by_id(build_layer(), "T1547.001"))

    assert "behavioral" in metadata["engines"]


def test_t1218_comment_mentions_t1218_lite_or_constrained_coverage() -> None:
    comment = technique_by_id(build_layer(), "T1218")["comment"]

    assert "T1218-lite" in comment or "constrained" in comment


def test_score_calculation_is_deterministic_for_required_cases() -> None:
    assert attack_navigator_layer.score_technique(
        engines={"native"},
        demo_case_count=0,
        has_response_or_protection=False,
    ) == 1
    assert attack_navigator_layer.score_technique(
        engines={"native", "sigma-like"},
        demo_case_count=0,
        has_response_or_protection=False,
    ) == 2
    assert attack_navigator_layer.score_technique(
        engines={"native", "sigma-like", "behavioral"},
        demo_case_count=0,
        has_response_or_protection=False,
    ) == 3
    assert attack_navigator_layer.score_technique(
        engines={"native", "sigma-like", "behavioral"},
        demo_case_count=1,
        has_response_or_protection=False,
    ) == 4
    assert attack_navigator_layer.score_technique(
        engines={"native", "sigma-like", "behavioral"},
        demo_case_count=1,
        has_response_or_protection=True,
    ) == 5


def test_markdown_summary_includes_technique_table_and_limitations() -> None:
    markdown = attack_navigator_layer.build_coverage_summary_markdown(
        sample_coverage_report(),
        build_layer(),
        case_matrix=sample_case_matrix(),
        dashboard_data=sample_dashboard_data(),
        project_status="Phase 15 ATT&CK Navigator export ready",
    )

    assert "## Covered Techniques" in markdown
    assert "| Technique | Name | Tactic | Score | Color | Engines |" in markdown
    assert "## Demo Matrix Totals" in markdown
    assert "| 6 | 4 | 0 | 1 | 1 |" in markdown
    assert "## Limitations" in markdown
    assert "T1218-lite is constrained" in markdown
    assert "communication score" in markdown


def test_cli_writes_json_and_markdown_outputs_to_temp_directory(tmp_path) -> None:
    coverage_path = tmp_path / "coverage.json"
    case_matrix_path = tmp_path / "case_matrix.json"
    dashboard_path = tmp_path / "dashboard_data.json"
    output_path = tmp_path / "out" / "edr_attack_layer.json"
    markdown_path = tmp_path / "out" / "coverage_summary.md"

    coverage_path.write_text(json.dumps(sample_coverage_report()), encoding="utf-8")
    case_matrix_path.write_text(json.dumps(sample_case_matrix()), encoding="utf-8")
    dashboard_path.write_text(json.dumps(sample_dashboard_data()), encoding="utf-8")

    exit_code = generate_attack_navigator_layer.main(
        [
            "--coverage-report",
            str(coverage_path),
            "--case-matrix",
            str(case_matrix_path),
            "--dashboard-data",
            str(dashboard_path),
            "--output",
            str(output_path),
            "--markdown-output",
            str(markdown_path),
            "--project-status",
            "Phase 15 ATT&CK Navigator export ready",
            "--output-summary",
        ]
    )

    assert exit_code == 0
    assert json.loads(output_path.read_text(encoding="utf-8"))["domain"] == "enterprise-attack"
    assert "ATT&CK Navigator Coverage Summary" in markdown_path.read_text(encoding="utf-8")


def test_cli_missing_coverage_report_exits_2_with_clear_message(tmp_path, capsys) -> None:
    exit_code = generate_attack_navigator_layer.main(
        [
            "--coverage-report",
            str(tmp_path / "missing.json"),
            "--case-matrix",
            str(tmp_path / "missing_case_matrix.json"),
            "--dashboard-data",
            str(tmp_path / "missing_dashboard.json"),
            "--output",
            str(tmp_path / "layer.json"),
            "--markdown-output",
            str(tmp_path / "summary.md"),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "Required coverage report is missing" in captured.err


def test_cli_missing_optional_case_matrix_and_dashboard_data_does_not_fail(tmp_path) -> None:
    coverage_path = tmp_path / "coverage.json"
    coverage_path.write_text(json.dumps(sample_coverage_report()), encoding="utf-8")

    exit_code = generate_attack_navigator_layer.main(
        [
            "--coverage-report",
            str(coverage_path),
            "--case-matrix",
            str(tmp_path / "missing_case_matrix.json"),
            "--dashboard-data",
            str(tmp_path / "missing_dashboard.json"),
            "--output",
            str(tmp_path / "layer.json"),
            "--markdown-output",
            str(tmp_path / "summary.md"),
        ]
    )

    assert exit_code == 0
    assert (tmp_path / "layer.json").exists()
    assert (tmp_path / "summary.md").exists()


def test_evidence_bundle_lists_navigator_files_as_optional_reports() -> None:
    optional_paths = {path.as_posix() for path in build_demo_evidence_bundle.OPTIONAL_REPORTS}

    assert any(path.endswith("reports/attack_navigator/edr_attack_layer.json") for path in optional_paths)
    assert any(path.endswith("reports/attack_navigator/coverage_summary.md") for path in optional_paths)


def test_evidence_bundle_includes_navigator_files_when_present(monkeypatch, tmp_path) -> None:
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    layer_path = source_dir / "edr_attack_layer.json"
    summary_path = source_dir / "coverage_summary.md"
    layer_path.write_text("{}", encoding="utf-8")
    summary_path.write_text("# Summary\n", encoding="utf-8")

    monkeypatch.setattr(build_demo_evidence_bundle, "OPTIONAL_REPORTS", [layer_path, summary_path])

    manifest = build_demo_evidence_bundle.build_demo_evidence_bundle(output_dir=tmp_path / "bundle")

    assert "edr_attack_layer.json" in manifest["included_files"]
    assert "coverage_summary.md" in manifest["included_files"]


def test_final_report_references_attack_navigator_export() -> None:
    report = final_demo_report.build_final_demo_report(generated_at="2026-06-19T00:00:00Z")
    capabilities = {capability["capability"]: capability for capability in report["capability_matrix"]}
    rendered = final_demo_report.render_markdown_report(report)

    assert "attack_navigator_export" in capabilities
    assert "reports/attack_navigator/edr_attack_layer.json" in rendered
    assert "scripts\\reporting\\generate_attack_navigator_layer.py" in rendered
