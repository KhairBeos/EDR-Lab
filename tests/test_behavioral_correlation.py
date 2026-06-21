import copy
import json
from pathlib import Path

from detection.behavioral.correlation import detect_behavioral_sequences
from detection.behavioral.sequence_detector import detect_sequences
from detection.demo.case_catalog import load_demo_cases
from detection.demo.case_runner import build_dashboard_data, run_case_matrix
from detection.rules.engine import run_detection_engines
from reporting.detection_coverage import build_detection_coverage_report


REPO_ROOT = Path(__file__).resolve().parents[1]
SAMPLES = REPO_ROOT / "samples" / "demo_cases"


def load_sample(name: str) -> dict | list[dict]:
    return json.loads((SAMPLES / name).read_text(encoding="utf-8"))


def rule_ids(alerts: list[dict]) -> set[str]:
    return {alert["rule"]["id"] for alert in alerts}


def test_t1105_sequence_matches_process_network_file() -> None:
    events = load_sample("behavioral_t1105_sequence.json")

    alerts = detect_behavioral_sequences(events)

    assert rule_ids(alerts) == {"det.behavioral.t1105_download_sequence"}
    alert = alerts[0]
    assert alert["detection"]["engine"] == "behavioral"
    assert alert["detection"]["sequence_steps"] == ["process", "network", "file"]
    assert alert["detection"]["correlated_event_count"] == 3
    assert alert["source"]["document_ids"] == [
        "demo-behavioral-t1105-process",
        "demo-behavioral-t1105-network",
        "demo-behavioral-t1105-file",
    ]


def test_t1105_sequence_does_not_match_outside_window() -> None:
    events = copy.deepcopy(load_sample("behavioral_t1105_sequence.json"))
    events[2]["@timestamp"] = "2026-06-18T01:10:00.000Z"
    events[2]["event"]["created"] = "2026-06-18T01:10:00.000Z"

    alerts = detect_behavioral_sequences(events)

    assert "det.behavioral.t1105_download_sequence" not in rule_ids(alerts)


def test_t1105_sequence_does_not_match_benign_unrelated_events() -> None:
    events = load_sample("behavioral_benign_unrelated_sequence.json")

    assert detect_behavioral_sequences(events) == []


def test_t1547_sequence_matches_process_registry_event() -> None:
    events = load_sample("behavioral_t1547_sequence.json")

    alerts = detect_behavioral_sequences(events)

    assert rule_ids(alerts) == {"det.behavioral.t1547_001_registry_persistence_sequence"}
    assert alerts[0]["detection"]["engine"] == "behavioral"
    assert alerts[0]["detection"]["correlated_event_count"] == 2
    assert alerts[0]["attack"]["technique"]["id"] == "T1547.001"


def test_t1218_sequence_matches_lolbin_chain() -> None:
    process_event = load_sample("t1218_rundll32_process_event.json")
    network_event = copy.deepcopy(process_event)
    network_event["@timestamp"] = "2026-06-18T01:05:00.000Z"
    network_event["event"] = {
        "id": "demo-behavioral-t1218-network",
        "kind": "event",
        "dataset": "windows.sysmon_operational",
        "code": 3,
        "category": ["network"],
        "type": ["connection"],
        "created": "2026-06-18T01:05:00.000Z",
    }
    network_event["destination"] = {"ip": "127.0.0.1", "domain": "example.test", "port": 8080}

    alerts = detect_behavioral_sequences([network_event, process_event])

    assert rule_ids(alerts) == {"det.behavioral.t1218_lolbin_sequence"}
    assert alerts[0]["detection"]["sequence_steps"] == ["process", "network"]
    assert alerts[0]["detection"]["correlated_event_count"] == 2


def test_input_events_are_not_mutated() -> None:
    events = load_sample("behavioral_t1105_sequence.json")
    before = copy.deepcopy(events)

    detect_behavioral_sequences(events)

    assert events == before


def test_events_are_sorted_by_timestamp_before_matching() -> None:
    events = list(reversed(load_sample("behavioral_t1105_sequence.json")))

    alerts = detect_behavioral_sequences(events)

    assert rule_ids(alerts) == {"det.behavioral.t1105_download_sequence"}


def test_host_grouping_prevents_cross_host_correlation() -> None:
    events = copy.deepcopy(load_sample("behavioral_t1105_sequence.json"))
    events[2]["host"]["name"] = "OTHER-HOST"

    assert detect_behavioral_sequences(events) == []


def test_process_entity_id_is_preferred_over_pid_name() -> None:
    events = copy.deepcopy(load_sample("behavioral_t1105_sequence.json"))
    events[1]["process"]["entity_id"] = "{different-entity-id}"

    assert detect_behavioral_sequences(events) == []


def test_pid_name_fallback_works_for_deterministic_samples() -> None:
    events = copy.deepcopy(load_sample("behavioral_t1105_sequence.json"))
    for event in events:
        event["process"].pop("entity_id", None)

    alerts = detect_behavioral_sequences(events)

    assert rule_ids(alerts) == {"det.behavioral.t1105_download_sequence"}


def test_sequence_detector_compatibility_wrapper_delegates_to_new_api() -> None:
    events = load_sample("behavioral_t1105_sequence.json")

    alerts = detect_sequences(events, window_seconds=300)

    assert rule_ids(alerts) == {"det.behavioral.t1105_download_sequence"}


def test_case_matrix_includes_and_runs_behavioral_cases() -> None:
    cases = {case.case_id: case for case in load_demo_cases()}

    assert "attack_behavioral_t1105_sequence_json" in cases
    assert "attack_behavioral_t1547_001_sequence_json" in cases
    assert "benign_behavioral_unrelated_sequence_json" in cases

    matrix = run_case_matrix(
        case_ids=[
            "attack_behavioral_t1105_sequence_json",
            "attack_behavioral_t1547_001_sequence_json",
            "benign_behavioral_unrelated_sequence_json",
        ]
    )
    rows = {row["case_id"]: row for row in matrix["cases"]}

    assert rows["attack_behavioral_t1105_sequence_json"]["classification"] == "true_positive"
    assert rows["attack_behavioral_t1547_001_sequence_json"]["classification"] == "true_positive"
    assert rows["benign_behavioral_unrelated_sequence_json"]["classification"] == "true_negative"

    dashboard = build_dashboard_data(matrix)
    assert dashboard["alert_count_by_engine"]["behavioral"] == 2
    assert dashboard["correlated_sequence_count"] == 2


def test_detection_coverage_report_includes_behavioral_rules() -> None:
    report = build_detection_coverage_report(generated_at="2026-06-18T00:00:00Z")
    inventory_ids = {rule["rule_id"] for rule in report["rule_inventory"]}
    techniques = {technique["technique_id"]: technique for technique in report["covered_techniques"]}

    assert {
        "det.behavioral.t1105_download_sequence",
        "det.behavioral.t1547_001_registry_persistence_sequence",
        "det.behavioral.t1218_lolbin_sequence",
    }.issubset(inventory_ids)
    assert report["engine_coverage_summary"]["behavioral_rule_count"] == 3
    assert "behavioral" in techniques["T1105"]["engines"]
    assert "behavioral" in techniques["T1547.001"]["engines"]
    assert "behavioral" in techniques["T1218"]["engines"]
    assert any(result["engine"] == "behavioral" and result["passed"] for result in report["validation_results"])


def test_existing_single_event_rules_and_demo_cases_remain_present() -> None:
    cases = {case.case_id for case in load_demo_cases()}
    assert "attack_t1105_network_lolbin_download_json" in cases
    assert "attack_t1547_001_registry_run_key_json" in cases
    assert "attack_t1218_rundll32_lolbin_json" in cases

    event = load_sample("t1105_certutil_network_event.json")
    alerts = run_detection_engines(engine="all", event=event)

    assert {
        "det.t1105.lolbin_download",
        "sigma_like.t1105.lolbin_download",
    }.issubset(rule_ids(alerts))
