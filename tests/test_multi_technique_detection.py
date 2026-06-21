import json
from pathlib import Path

from detection.demo.case_catalog import load_demo_cases
from detection.demo.case_runner import build_dashboard_data, run_case_matrix
from detection.rules.engine import run_detection_engines
from detection.rules.native.registry import build_native_alerts, load_native_rules
from detection.rules.sigma_like.loader import load_sigma_like_rules
from detection.rules.sigma_like.registry import build_sigma_like_alerts
from reporting.detection_coverage import build_detection_coverage_report


REPO_ROOT = Path(__file__).resolve().parents[1]
SAMPLES = REPO_ROOT / "samples" / "demo_cases"


def load_sample(name: str) -> dict:
    return json.loads((SAMPLES / name).read_text(encoding="utf-8"))


def rule_ids(alerts: list[dict]) -> set[str]:
    return {alert["rule"]["id"] for alert in alerts}


def test_native_t1105_matches_safe_process_marker() -> None:
    alerts = build_native_alerts(event=load_sample("t1105_certutil_process_event.json"))

    assert "det.t1105.lolbin_download" in rule_ids(alerts)


def test_native_t1105_matches_event_id_3_network_sample() -> None:
    alerts = build_native_alerts(event=load_sample("t1105_certutil_network_event.json"))

    assert "det.t1105.lolbin_download" in rule_ids(alerts)


def test_native_t1105_matches_event_id_11_file_sample() -> None:
    alerts = build_native_alerts(event=load_sample("t1105_file_create_event.json"))

    assert "det.t1105.lolbin_download" in rule_ids(alerts)


def test_native_t1547_matches_event_id_13_run_key_sample() -> None:
    alerts = build_native_alerts(event=load_sample("t1547_registry_run_key_event.json"))

    assert "det.t1547_001.registry_run_key_persistence" in rule_ids(alerts)


def test_native_t1218_matches_rundll32_marker() -> None:
    alerts = build_native_alerts(event=load_sample("t1218_rundll32_process_event.json"))

    assert "det.t1218.lolbin_suspicious_execution" in rule_ids(alerts)


def test_benign_network_event_does_not_alert() -> None:
    alerts = run_detection_engines(engine="all", event=load_sample("benign_network_event.json"))

    assert alerts == []


def test_benign_file_create_event_does_not_alert() -> None:
    alerts = run_detection_engines(engine="all", event=load_sample("benign_file_create_event.json"))

    assert alerts == []


def test_sigma_like_t1105_matches_deterministic_sample() -> None:
    alerts = build_sigma_like_alerts(event=load_sample("t1105_certutil_network_event.json"))

    assert "sigma_like.t1105.lolbin_download" in rule_ids(alerts)


def test_sigma_like_t1547_matches_deterministic_sample() -> None:
    alerts = build_sigma_like_alerts(event=load_sample("t1547_registry_run_key_event.json"))

    assert "sigma_like.t1547_001.registry_run_key_persistence" in rule_ids(alerts)


def test_sigma_like_t1218_matches_deterministic_sample() -> None:
    alerts = build_sigma_like_alerts(event=load_sample("t1218_rundll32_process_event.json"))

    assert "sigma_like.t1218.lolbin_suspicious_execution" in rule_ids(alerts)


def test_alert_docs_include_correct_attack_technique_ids() -> None:
    alerts = run_detection_engines(engine="all", event=load_sample("t1547_registry_run_key_event.json"))

    assert {alert["attack"]["technique"]["id"] for alert in alerts} == {"T1547.001"}
    assert {alert["attack"]["technique"]["name"] for alert in alerts} == {"Registry Run Keys / Startup Folder"}


def test_sigma_like_alert_docs_include_engine() -> None:
    alerts = build_sigma_like_alerts(event=load_sample("t1218_rundll32_process_event.json"))

    assert alerts
    assert all(alert["detection"]["engine"] == "sigma-like" for alert in alerts)


def test_alert_docs_include_relevant_context() -> None:
    network_alert = build_native_alerts(event=load_sample("t1105_certutil_network_event.json"))[0]
    registry_alert = build_native_alerts(event=load_sample("t1547_registry_run_key_event.json"))[0]
    file_alert = build_native_alerts(event=load_sample("t1105_file_create_event.json"))[0]

    assert network_alert["destination"]["ip"] == "127.0.0.1"
    assert network_alert["network"]["transport"] == "tcp"
    assert registry_alert["registry"]["value"] == "EDRDemo"
    assert file_alert["file"]["name"] == "EDR_DEMO_T1105_edr_demo.txt"


def test_rule_registries_include_phase13_rules() -> None:
    native_ids = {rule["id"] for rule in load_native_rules()}
    sigma_ids = {rule["id"] for rule in load_sigma_like_rules()}

    assert {
        "det.t1105.lolbin_download",
        "det.t1547_001.registry_run_key_persistence",
        "det.t1218.lolbin_suspicious_execution",
    }.issubset(native_ids)
    assert {
        "sigma_like.t1105.lolbin_download",
        "sigma_like.t1547_001.registry_run_key_persistence",
        "sigma_like.t1218.lolbin_suspicious_execution",
    }.issubset(sigma_ids)


def test_detection_coverage_report_includes_new_rules_and_techniques() -> None:
    report = build_detection_coverage_report(generated_at="2026-06-18T00:00:00Z")
    inventory_ids = {rule["rule_id"] for rule in report["rule_inventory"]}
    technique_ids = {technique["technique_id"] for technique in report["covered_techniques"]}

    assert "det.t1105.lolbin_download" in inventory_ids
    assert "sigma_like.t1547_001.registry_run_key_persistence" in inventory_ids
    assert {"T1105", "T1547.001", "T1218"}.issubset(technique_ids)


def test_case_matrix_includes_phase13_cases() -> None:
    cases = {case.case_id: case for case in load_demo_cases()}

    assert "attack_t1105_network_lolbin_download_json" in cases
    assert "attack_t1547_001_registry_run_key_json" in cases
    assert "attack_t1218_rundll32_lolbin_json" in cases
    assert "benign_phase13_network_json" in cases
    assert "benign_phase13_file_create_json" in cases


def test_case_matrix_runs_phase13_cases_without_live_infrastructure() -> None:
    matrix = run_case_matrix(
        case_ids=[
            "attack_t1105_network_lolbin_download_json",
            "attack_t1547_001_registry_run_key_json",
            "attack_t1218_rundll32_lolbin_json",
            "benign_phase13_network_json",
            "benign_phase13_file_create_json",
        ]
    )
    rows = {row["case_id"]: row for row in matrix["cases"]}

    assert rows["attack_t1105_network_lolbin_download_json"]["classification"] == "true_positive"
    assert rows["attack_t1547_001_registry_run_key_json"]["classification"] == "true_positive"
    assert rows["attack_t1218_rundll32_lolbin_json"]["classification"] == "true_positive"
    assert rows["benign_phase13_network_json"]["classification"] == "true_negative"
    assert rows["benign_phase13_file_create_json"]["classification"] == "true_negative"


def test_dashboard_data_includes_technique_and_event_code_counts() -> None:
    matrix = run_case_matrix(
        case_ids=[
            "attack_t1105_network_lolbin_download_json",
            "attack_t1547_001_registry_run_key_json",
            "attack_t1218_rundll32_lolbin_json",
        ]
    )
    data = build_dashboard_data(matrix)

    assert data["alert_count_by_technique"]["T1105"] == 2
    assert data["alert_count_by_technique"]["T1547.001"] == 2
    assert data["alert_count_by_technique"]["T1218"] == 2
    assert data["event_count_by_code"]["3"] == 1
    assert data["event_count_by_code"]["13"] == 1
