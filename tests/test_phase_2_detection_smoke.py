import json

import pytest

from detection.rules.native import ElasticsearchQueryError, SearchCandidate
from scripts.smoke import phase_2_detection_smoke


FIXED_CREATED_AT = "2026-06-16T15:30:00Z"


def test_fixture_mode_produces_one_alert() -> None:
    result = phase_2_detection_smoke.run_fixture_detection(created_at=FIXED_CREATED_AT)

    assert result["mode"] == "fixture"
    assert result["candidate_count"] == 1
    assert result["alert_count"] == 1
    assert len(result["alerts"]) == 1


def test_fixture_mode_preserves_rule_metadata() -> None:
    result = phase_2_detection_smoke.run_fixture_detection(created_at=FIXED_CREATED_AT)
    alert = result["alerts"][0]

    assert alert["rule"]["id"] == "det.t1059_001.powershell_process_start"
    assert alert["rule"]["name"] == "PowerShell Process Execution"
    assert alert["rule"]["version"] == 1


def test_fixture_mode_preserves_attack_metadata() -> None:
    result = phase_2_detection_smoke.run_fixture_detection(created_at=FIXED_CREATED_AT)
    alert = result["alerts"][0]

    assert alert["attack"]["technique"]["id"] == "T1059.001"
    assert alert["attack"]["technique"]["name"] == "PowerShell"
    assert alert["attack"]["tactic"] == ["Execution"]


def test_fixture_mode_preserves_art_metadata() -> None:
    result = phase_2_detection_smoke.run_fixture_detection(created_at=FIXED_CREATED_AT)
    alert = result["alerts"][0]

    assert alert["art"]["technique_id"] == "T1059.001"
    assert alert["art"]["test_name"] == "PowerShell Command Execution"
    assert alert["art"]["executor"] == "powershell"


def test_json_output_is_valid() -> None:
    result = phase_2_detection_smoke.run_fixture_detection(created_at=FIXED_CREATED_AT)

    rendered = phase_2_detection_smoke.render_result(result, "json")
    parsed = json.loads(rendered)

    assert parsed["alert_count"] == 1
    assert parsed["alerts"][0]["alert"]["created"] == FIXED_CREATED_AT


def test_summary_output_works() -> None:
    result = phase_2_detection_smoke.run_fixture_detection(created_at=FIXED_CREATED_AT)

    rendered = phase_2_detection_smoke.render_result(result, "summary")

    assert "Phase 2 detection smoke" in rendered
    assert "Mode: fixture" in rendered
    assert "Alerts: 1" in rendered
    assert "powershell.exe" in rendered


def test_no_alert_result_behavior() -> None:
    result = phase_2_detection_smoke.run_fixture_detection(
        created_at=FIXED_CREATED_AT,
        force_no_alert=True,
    )

    assert result["candidate_count"] == 1
    assert result["alert_count"] == 0
    assert result["alerts"] == []
    assert result["message"] == "No matching PowerShell alerts produced."


def test_main_returns_zero_for_fixture_success(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = phase_2_detection_smoke.main([])

    captured = capsys.readouterr()
    parsed = json.loads(captured.out)

    assert exit_code == 0
    assert parsed["alert_count"] == 1


def test_main_returns_one_for_no_alert(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = phase_2_detection_smoke.main(["--fixture-no-match"])

    captured = capsys.readouterr()
    parsed = json.loads(captured.out)

    assert exit_code == 1
    assert parsed["alert_count"] == 0


def test_elasticsearch_mode_can_be_monkeypatched(monkeypatch: pytest.MonkeyPatch) -> None:
    event = phase_2_detection_smoke.run_fixture_detection(created_at=FIXED_CREATED_AT)["alerts"][0]
    candidate_event = {
        "event": event["event"],
        "host": event["host"],
        "user": event["user"],
        "process": event["process"],
        "art": event["art"],
    }

    def fake_search(_: object) -> list[SearchCandidate]:
        return [
            SearchCandidate(
                event=candidate_event,
                source={"index": "edr-raw-events-2026.06.16", "document_id": "powershell-doc-1"},
            )
        ]

    monkeypatch.setattr(phase_2_detection_smoke, "search_powershell_candidates", fake_search)

    result = phase_2_detection_smoke.run_elasticsearch_detection(
        phase_2_detection_smoke.ElasticsearchConfig(),
        created_at=FIXED_CREATED_AT,
    )

    assert result["mode"] == "elasticsearch"
    assert result["candidate_count"] == 1
    assert result["alert_count"] == 1


def test_elasticsearch_source_metadata_appears_in_alert(monkeypatch: pytest.MonkeyPatch) -> None:
    fixture_result = phase_2_detection_smoke.run_fixture_detection(created_at=FIXED_CREATED_AT)
    fixture_alert = fixture_result["alerts"][0]
    candidate_event = {
        "event": fixture_alert["event"],
        "host": fixture_alert["host"],
        "user": fixture_alert["user"],
        "process": fixture_alert["process"],
        "art": fixture_alert["art"],
    }

    def fake_search(_: object) -> list[SearchCandidate]:
        return [
            SearchCandidate(
                event=candidate_event,
                source={"index": "edr-raw-events-2026.06.16", "document_id": "powershell-doc-1"},
            )
        ]

    monkeypatch.setattr(phase_2_detection_smoke, "search_powershell_candidates", fake_search)

    result = phase_2_detection_smoke.run_elasticsearch_detection(
        phase_2_detection_smoke.ElasticsearchConfig(),
        created_at=FIXED_CREATED_AT,
    )

    assert result["alerts"][0]["source"] == {
        "index": "edr-raw-events-2026.06.16",
        "document_id": "powershell-doc-1",
    }


def test_elasticsearch_query_errors_map_to_exit_code_2(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def fake_search(_: object) -> list[SearchCandidate]:
        raise ElasticsearchQueryError("Elasticsearch unavailable")

    monkeypatch.setattr(phase_2_detection_smoke, "search_powershell_candidates", fake_search)

    exit_code = phase_2_detection_smoke.main(["--from-elasticsearch"])

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "Operational failure" in captured.err


def test_unexpected_detection_errors_map_to_exit_code_3(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def broken_fixture_detection(*, force_no_alert: bool = False) -> dict:
        raise ValueError("unexpected detection failure")

    monkeypatch.setattr(phase_2_detection_smoke, "run_fixture_detection", broken_fixture_detection)

    exit_code = phase_2_detection_smoke.main([])

    captured = capsys.readouterr()
    assert exit_code == 3
    assert "Detection smoke failed" in captured.err
