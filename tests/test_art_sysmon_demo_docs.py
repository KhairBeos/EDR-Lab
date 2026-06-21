import json
from pathlib import Path

import pytest

from collection.elasticsearch.event_indexer import EventIndexResult
from detection.ml.baseline import load_process_baseline
from detection.ml.features import extract_process_features
from detection.ml.scorer import DEFAULT_THRESHOLD, score_process_features
from detection.rules.native.alert_indexer import AlertIndexResult
from normalization.sysmon.process_create_normalizer import normalize_sysmon_event_1
from response.soar.response_indexer import ResponseIndexResult
from scripts.demo import build_demo_evidence_bundle, run_art_sysmon_demo_validation
from scripts.pipeline import run_live_telemetry_pipeline


REPO_ROOT = Path(__file__).resolve().parents[1]


def read_doc(path: str) -> str:
    return (REPO_ROOT / path).read_text(encoding="utf-8")


def test_windows_vm_atomic_red_team_doc_exists_and_mentions_required_terms() -> None:
    text = read_doc("docs/windows_vm_atomic_red_team_demo.md")

    assert "Windows VM" in text
    assert "Sysmon" in text
    assert "Atomic Red Team" in text
    assert "Event ID 1" in text
    assert "lab-only" in text


def test_atomic_attack_case_catalog_mentions_primary_detection_case() -> None:
    text = read_doc("docs/atomic_attack_case_catalog.md")

    assert "T1059.001" in text
    assert "PowerShell" in text
    assert "det.t1059_001.powershell_process_start" in text
    assert "sigma_like.t1059_001.powershell_process_start" in text


def test_sysmon_event_export_doc_mentions_xml_export() -> None:
    text = read_doc("docs/sysmon_event_export.md")

    assert "XML" in text
    assert "export" in text.lower()


def test_kibana_validation_doc_mentions_indexes() -> None:
    text = read_doc("docs/kibana_dashboard_validation.md")

    assert "edr-normalized-events-*" in text
    assert "edr-alerts-native-*" in text
    assert "edr-response-actions-*" in text


def test_demo_evidence_checklist_mentions_required_evidence() -> None:
    text = read_doc("docs/demo_evidence_checklist.md")

    for term in ["Windows VM", "Sysmon", "Atomic Red Team", "alert", "SOAR response", "Final report", "Kibana"]:
        assert term in text


def test_demo_validation_fixture_mode_runs_without_live_infrastructure(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_index_event(*_: object, **__: object) -> list[EventIndexResult]:
        raise AssertionError("event indexer should not be called")

    def fail_index_alerts(*_: object, **__: object) -> list[AlertIndexResult]:
        raise AssertionError("alert indexer should not be called")

    def fail_index_responses(*_: object, **__: object) -> list[ResponseIndexResult]:
        raise AssertionError("response indexer should not be called")

    monkeypatch.setattr(run_live_telemetry_pipeline, "index_event", fail_index_event)
    monkeypatch.setattr(run_live_telemetry_pipeline, "index_alerts", fail_index_alerts)
    monkeypatch.setattr(run_art_sysmon_demo_validation, "index_responses", fail_index_responses)

    result = run_art_sysmon_demo_validation.run_art_sysmon_demo_validation(
        input_mode="fixture",
        engine="all",
    )

    assert result["normalized_event_count"] == 1
    assert result["native_alert_count"] == 1
    assert result["sigma_like_alert_count"] == 1
    assert result["indexed_event_count"] == 0
    assert result["indexed_alert_count"] == 0
    assert result["indexed_response_count"] == 0


def test_demo_validation_write_flags_are_monkeypatchable(monkeypatch: pytest.MonkeyPatch) -> None:
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
    monkeypatch.setattr(run_art_sysmon_demo_validation, "index_responses", fake_index_responses)

    result = run_art_sysmon_demo_validation.run_art_sysmon_demo_validation(
        input_mode="xml",
        xml_path=REPO_ROOT / "samples" / "sysmon" / "art_t1059_001_powershell_event.xml",
        engine="all",
        write_events=True,
        write_alerts=True,
        write_response=True,
    )

    assert result["indexed_event_count"] == 1
    assert result["indexed_alert_count"] == 2
    assert result["response_count"] == 2
    assert result["indexed_response_count"] == 2


def test_evidence_bundle_script_creates_manifest(tmp_path) -> None:
    manifest = build_demo_evidence_bundle.build_demo_evidence_bundle(output_dir=tmp_path)

    assert (tmp_path / "manifest.json").exists()
    assert manifest["generated_at"]
    assert "manifest.json" in manifest["included_files"]
    assert "command_log_template.md" in manifest["included_files"]


def test_sample_xml_exists_and_can_be_normalized() -> None:
    xml_path = REPO_ROOT / "samples" / "sysmon" / "art_t1059_001_powershell_event.xml"
    normalized = normalize_sysmon_event_1(xml_path.read_text(encoding="utf-8"))

    assert normalized["event"]["dataset"] == "windows.sysmon_operational"
    assert normalized["event"]["code"] == 1
    assert normalized["process"]["name"] == "powershell.exe"
    assert "EDR_DEMO_T1059_001" in normalized["process"]["command_line"]


def test_sample_ml_json_exists_and_can_be_scored() -> None:
    event_path = REPO_ROOT / "samples" / "sysmon" / "ml_suspicious_process_event.json"
    event = json.loads(event_path.read_text(encoding="utf-8"))
    features = extract_process_features(event)
    score = score_process_features(features, load_process_baseline())

    assert score["score"] >= DEFAULT_THRESHOLD
    assert score["is_anomaly"] is True


def test_demo_validation_json_mode_uses_existing_ml_path() -> None:
    result = run_art_sysmon_demo_validation.run_art_sysmon_demo_validation(
        input_mode="json",
        event_path=REPO_ROOT / "samples" / "sysmon" / "ml_suspicious_process_event.json",
        engine="ml-anomaly",
    )

    assert result["normalized_event_count"] == 1
    assert result["ml_alert_count"] == 1
    assert result["alerts"][0]["detection"]["engine"] == "ml-anomaly"
