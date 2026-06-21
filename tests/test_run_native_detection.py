import json

import pytest

from detection.rules.native.alert_indexer import AlertIndexResult, AlertIndexingError
from detection.rules.native.elasticsearch import ElasticsearchQueryError, SearchCandidate
from scripts.detection import run_native_detection


def test_fixture_input_produces_one_alert() -> None:
    result = run_native_detection.run_native_detection()

    assert result["mode"] == "fixture"
    assert result["candidate_count"] == 1
    assert result["alert_count"] == 1


def test_fixture_input_preserves_rule_metadata() -> None:
    result = run_native_detection.run_native_detection()
    alert = result["alerts"][0]

    assert alert["rule"]["id"] == "det.t1059_001.powershell_process_start"
    assert alert["rule"]["name"] == "PowerShell Process Execution"
    assert alert["rule"]["version"] == 1


def test_fixture_input_preserves_attack_metadata() -> None:
    result = run_native_detection.run_native_detection()
    alert = result["alerts"][0]

    assert alert["attack"]["technique"]["id"] == "T1059.001"
    assert alert["attack"]["technique"]["name"] == "PowerShell"
    assert alert["attack"]["tactic"] == ["Execution"]


def test_fixture_input_preserves_art_metadata() -> None:
    result = run_native_detection.run_native_detection()
    alert = result["alerts"][0]

    assert alert["art"]["technique_id"] == "T1059.001"
    assert alert["art"]["test_name"] == "PowerShell Command Execution"


def test_json_output_is_valid() -> None:
    result = run_native_detection.run_native_detection()

    rendered = run_native_detection.render_result(result, "json")
    parsed = json.loads(rendered)

    assert parsed["alert_count"] == 1


def test_summary_output_works() -> None:
    result = run_native_detection.run_native_detection()

    rendered = run_native_detection.render_result(result, "summary")

    assert "Native detection pipeline" in rendered
    assert "Mode: fixture" in rendered
    assert "Alerts: 1" in rendered
    assert "powershell.exe" in rendered


def test_fixture_no_match_produces_zero_alerts_and_exit_code_1(capsys: pytest.CaptureFixture[str]) -> None:
    result = run_native_detection.run_native_detection(force_no_alert=True)
    exit_code = run_native_detection.main(["--fixture-no-match"])

    captured = capsys.readouterr()
    parsed = json.loads(captured.out)

    assert result["alert_count"] == 0
    assert result["message"] == "No matching PowerShell alerts produced."
    assert exit_code == 1
    assert parsed["alert_count"] == 0


def test_main_returns_zero_for_fixture_success(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = run_native_detection.main([])

    captured = capsys.readouterr()
    parsed = json.loads(captured.out)

    assert exit_code == 0
    assert parsed["alert_count"] == 1


def test_elasticsearch_input_can_be_monkeypatched(monkeypatch: pytest.MonkeyPatch) -> None:
    fixture_alert = run_native_detection.run_native_detection()["alerts"][0]
    candidate = _candidate_from_alert(fixture_alert)

    def fake_search(_: object) -> list[SearchCandidate]:
        return [candidate]

    monkeypatch.setattr(run_native_detection, "search_powershell_candidates", fake_search)

    result = run_native_detection.run_native_detection(input_mode="elasticsearch")

    assert result["mode"] == "elasticsearch"
    assert result["candidate_count"] == 1
    assert result["alert_count"] == 1


def test_elasticsearch_source_metadata_appears_in_alert_source(monkeypatch: pytest.MonkeyPatch) -> None:
    fixture_alert = run_native_detection.run_native_detection()["alerts"][0]
    candidate = _candidate_from_alert(fixture_alert)

    def fake_search(_: object) -> list[SearchCandidate]:
        return [candidate]

    monkeypatch.setattr(run_native_detection, "search_powershell_candidates", fake_search)

    result = run_native_detection.run_native_detection(input_mode="elasticsearch")

    assert result["alerts"][0]["source"] == {
        "index": "edr-raw-events-2026.06.17",
        "document_id": "powershell-doc-1",
    }


def test_write_alerts_calls_indexer(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = []

    def fake_index_alerts(alerts: list[dict], config: object, *, index_date: str | None = None) -> list[AlertIndexResult]:
        calls.append({"alerts": alerts, "index_date": index_date})
        return [
            AlertIndexResult(
                index="edr-alerts-native-2026.06.17",
                document_id=alerts[0]["alert"]["id"],
                result="created",
                status=201,
            )
        ]

    monkeypatch.setattr(run_native_detection, "index_alerts", fake_index_alerts)

    result = run_native_detection.run_native_detection(write_alerts=True, alert_index_date="2026-06-17")

    assert len(calls) == 1
    assert calls[0]["index_date"] == "2026-06-17"
    assert result["indexed_count"] == 1


def test_without_write_alerts_indexer_is_not_called(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_index_alerts(*_: object, **__: object) -> list[AlertIndexResult]:
        raise AssertionError("indexer should not be called")

    monkeypatch.setattr(run_native_detection, "index_alerts", fail_index_alerts)

    result = run_native_detection.run_native_detection(write_alerts=False)

    assert result["indexed_count"] == 0
    assert result["indexed_alerts"] == []


def test_indexed_result_appears_in_command_result(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_index_alerts(alerts: list[dict], config: object, *, index_date: str | None = None) -> list[AlertIndexResult]:
        return [
            AlertIndexResult(
                index="edr-alerts-native-2026.06.17",
                document_id=alerts[0]["alert"]["id"],
                result="created",
                status=201,
            )
        ]

    monkeypatch.setattr(run_native_detection, "index_alerts", fake_index_alerts)

    result = run_native_detection.run_native_detection(write_alerts=True, alert_index_date="2026-06-17")

    assert result["indexed_alerts"] == [
        {
            "index": "edr-alerts-native-2026.06.17",
            "document_id": result["alerts"][0]["alert"]["id"],
            "result": "created",
            "status": 201,
        }
    ]


def test_elasticsearch_query_errors_map_to_exit_code_2(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def fake_search(_: object) -> list[SearchCandidate]:
        raise ElasticsearchQueryError("Elasticsearch unavailable")

    monkeypatch.setattr(run_native_detection, "search_powershell_candidates", fake_search)

    exit_code = run_native_detection.main(["--input", "elasticsearch"])

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "Operational failure" in captured.err


def test_alert_indexing_errors_map_to_exit_code_2(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def fake_index_alerts(*_: object, **__: object) -> list[AlertIndexResult]:
        raise AlertIndexingError("indexing failed")

    monkeypatch.setattr(run_native_detection, "index_alerts", fake_index_alerts)

    exit_code = run_native_detection.main(["--write-alerts"])

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "Operational failure" in captured.err


def test_unexpected_detection_errors_map_to_exit_code_3(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def broken_load_rule() -> dict:
        raise ValueError("broken rule")

    monkeypatch.setattr(run_native_detection, "load_rule", broken_load_rule)

    exit_code = run_native_detection.main([])

    captured = capsys.readouterr()
    assert exit_code == 3
    assert "Native detection failed" in captured.err


def _candidate_from_alert(alert: dict) -> SearchCandidate:
    event = {
        "event": alert["event"],
        "host": alert["host"],
        "user": alert["user"],
        "process": alert["process"],
        "art": alert["art"],
    }
    return SearchCandidate(
        event=event,
        source={
            "index": "edr-raw-events-2026.06.17",
            "document_id": "powershell-doc-1",
        },
    )
