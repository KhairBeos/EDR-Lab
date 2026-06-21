import json

import pytest

from collection.elasticsearch.event_indexer import EventIndexResult, EventIndexingError
from detection.rules.native.alert_indexer import AlertIndexResult, AlertIndexingError
from scripts.pipeline import run_live_telemetry_pipeline
from scripts.smoke.end_to_end_art_telemetry_smoke import load_fixture


def test_fixture_input_normalizes_one_event_without_elasticsearch() -> None:
    result = run_live_telemetry_pipeline.run_live_telemetry_pipeline(input_mode="fixture")

    assert result["mode"] == "fixture"
    assert result["normalized_event_count"] == 1
    assert result["event_indexed_count"] == 0
    assert result["normalized_events"][0]["event"]["dataset"] == "windows.sysmon_operational"
    assert result["normalized_events"][0]["event"]["code"] == 1


def test_fixture_input_without_detectable_flag_produces_zero_alerts() -> None:
    result = run_live_telemetry_pipeline.run_live_telemetry_pipeline(input_mode="fixture")

    assert result["normalized_events"][0]["process"]["name"] == "cmd.exe"
    assert result["alert_count"] == 0
    assert result["alerts"] == []


def test_fixture_input_with_detectable_flag_produces_one_alert() -> None:
    result = run_live_telemetry_pipeline.run_live_telemetry_pipeline(
        input_mode="fixture",
        fixture_detectable_powershell=True,
    )

    assert result["normalized_events"][0]["process"]["name"] == "powershell.exe"
    assert result["alert_count"] == 1
    assert result["alerts"][0]["rule"]["id"] == "det.t1059_001.powershell_process_start"


def test_xml_input_path_works_with_fixture_xml(tmp_path) -> None:
    xml_path = tmp_path / "sysmon_event_1.xml"
    xml_path.write_text(load_fixture(), encoding="utf-8")

    result = run_live_telemetry_pipeline.run_live_telemetry_pipeline(input_mode="xml", xml_path=xml_path)

    assert result["mode"] == "xml"
    assert result["normalized_event_count"] == 1
    assert result["normalized_events"][0]["host"]["name"] == "WIN11-EDR-LAB"


def test_write_events_calls_event_indexer_and_includes_result(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = []

    def fake_index_event(event: dict, config: object, *, index_date: str | None = None) -> EventIndexResult:
        calls.append({"event": event, "index_date": index_date})
        return EventIndexResult(
            index="edr-normalized-events-2026.06.17",
            document_id="event-doc-1",
            result="created",
            status=201,
        )

    monkeypatch.setattr(run_live_telemetry_pipeline, "index_event", fake_index_event)

    result = run_live_telemetry_pipeline.run_live_telemetry_pipeline(
        input_mode="fixture",
        write_events=True,
        event_index_date="2026-06-17",
    )

    assert len(calls) == 1
    assert calls[0]["index_date"] == "2026-06-17"
    assert result["event_indexed_count"] == 1
    assert result["event_index_results"] == [
        {
            "index": "edr-normalized-events-2026.06.17",
            "document_id": "event-doc-1",
            "result": "created",
            "status": 201,
        }
    ]


def test_write_alerts_calls_alert_indexer_and_includes_result(monkeypatch: pytest.MonkeyPatch) -> None:
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

    monkeypatch.setattr(run_live_telemetry_pipeline, "index_alerts", fake_index_alerts)

    result = run_live_telemetry_pipeline.run_live_telemetry_pipeline(
        input_mode="fixture",
        fixture_detectable_powershell=True,
        write_alerts=True,
        alert_index_date="2026-06-17",
    )

    assert len(calls) == 1
    assert calls[0]["index_date"] == "2026-06-17"
    assert result["alert_indexed_count"] == 1
    assert result["alert_index_results"][0]["index"] == "edr-alerts-native-2026.06.17"


def test_without_write_events_event_indexer_is_not_called(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_index_event(*_: object, **__: object) -> EventIndexResult:
        raise AssertionError("event indexer should not be called")

    monkeypatch.setattr(run_live_telemetry_pipeline, "index_event", fail_index_event)

    result = run_live_telemetry_pipeline.run_live_telemetry_pipeline(input_mode="fixture", write_events=False)

    assert result["event_indexed_count"] == 0


def test_without_write_alerts_alert_indexer_is_not_called(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_index_alerts(*_: object, **__: object) -> list[AlertIndexResult]:
        raise AssertionError("alert indexer should not be called")

    monkeypatch.setattr(run_live_telemetry_pipeline, "index_alerts", fail_index_alerts)

    result = run_live_telemetry_pipeline.run_live_telemetry_pipeline(
        input_mode="fixture",
        fixture_detectable_powershell=True,
        write_alerts=False,
    )

    assert result["alert_count"] == 1
    assert result["alert_indexed_count"] == 0


def test_event_source_metadata_is_passed_to_alert_when_event_is_indexed(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_index_event(event: dict, config: object, *, index_date: str | None = None) -> EventIndexResult:
        return EventIndexResult(
            index="edr-normalized-events-2026.06.17",
            document_id="event-doc-1",
            result="created",
            status=201,
        )

    monkeypatch.setattr(run_live_telemetry_pipeline, "index_event", fake_index_event)

    result = run_live_telemetry_pipeline.run_live_telemetry_pipeline(
        input_mode="fixture",
        fixture_detectable_powershell=True,
        write_events=True,
    )

    assert result["alerts"][0]["source"] == {
        "index": "edr-normalized-events-2026.06.17",
        "document_id": "event-doc-1",
    }


def test_json_output_is_valid() -> None:
    result = run_live_telemetry_pipeline.run_live_telemetry_pipeline(input_mode="fixture")

    rendered = run_live_telemetry_pipeline.render_result(result, "json")
    parsed = json.loads(rendered)

    assert parsed["normalized_event_count"] == 1


def test_summary_output_works() -> None:
    result = run_live_telemetry_pipeline.run_live_telemetry_pipeline(
        input_mode="fixture",
        fixture_detectable_powershell=True,
    )

    rendered = run_live_telemetry_pipeline.render_result(result, "summary")

    assert "Live telemetry pipeline" in rendered
    assert "Normalized events: 1" in rendered
    assert "Alerts: 1" in rendered
    assert "powershell.exe" in rendered


def test_event_indexing_error_maps_to_exit_code_2(monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    def fake_index_event(*_: object, **__: object) -> EventIndexResult:
        raise EventIndexingError("event index failed")

    monkeypatch.setattr(run_live_telemetry_pipeline, "index_event", fake_index_event)

    exit_code = run_live_telemetry_pipeline.main(["--input", "fixture", "--write-events"])

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "Operational failure" in captured.err


def test_alert_indexing_error_maps_to_exit_code_2(monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    def fake_index_alerts(*_: object, **__: object) -> list[AlertIndexResult]:
        raise AlertIndexingError("alert index failed")

    monkeypatch.setattr(run_live_telemetry_pipeline, "index_alerts", fake_index_alerts)

    exit_code = run_live_telemetry_pipeline.main(
        ["--input", "fixture", "--fixture-detectable-powershell", "--write-alerts"]
    )

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "Operational failure" in captured.err


def test_malformed_xml_maps_to_exit_code_2(tmp_path, capsys) -> None:
    xml_path = tmp_path / "bad.xml"
    xml_path.write_text("<Event>", encoding="utf-8")

    exit_code = run_live_telemetry_pipeline.main(["--input", "xml", "--xml-path", str(xml_path)])

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "Operational failure" in captured.err
