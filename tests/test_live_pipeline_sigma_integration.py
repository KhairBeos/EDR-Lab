import pytest

from detection.rules.native.alert_indexer import AlertIndexResult
from scripts.pipeline import run_live_telemetry_pipeline


def test_engine_native_keeps_current_fixture_detectable_behavior() -> None:
    result = run_live_telemetry_pipeline.run_live_telemetry_pipeline(
        input_mode="fixture",
        fixture_detectable_powershell=True,
        engine="native",
    )

    assert result["alert_count"] == 1
    assert result["alerts"][0]["rule"]["id"] == "det.t1059_001.powershell_process_start"
    assert "engine" not in result["alerts"][0]["detection"]


def test_engine_sigma_like_fixture_detectable_produces_one_sigma_like_alert() -> None:
    result = run_live_telemetry_pipeline.run_live_telemetry_pipeline(
        input_mode="fixture",
        fixture_detectable_powershell=True,
        engine="sigma-like",
    )

    assert result["engine"] == "sigma-like"
    assert result["alert_count"] == 1
    assert result["alerts"][0]["rule"]["id"] == "sigma_like.t1059_001.powershell_process_start"
    assert result["alerts"][0]["detection"]["engine"] == "sigma-like"


def test_engine_all_fixture_detectable_produces_native_and_sigma_like_alerts() -> None:
    result = run_live_telemetry_pipeline.run_live_telemetry_pipeline(
        input_mode="fixture",
        fixture_detectable_powershell=True,
        engine="all",
    )

    rule_ids = {alert["rule"]["id"] for alert in result["alerts"]}
    engines = {alert["detection"].get("engine", "native") for alert in result["alerts"]}

    assert result["alert_count"] == 2
    assert rule_ids == {
        "det.t1059_001.powershell_process_start",
        "sigma_like.t1059_001.powershell_process_start",
    }
    assert engines == {"native", "sigma-like"}


def test_write_alerts_indexes_sigma_like_alerts(monkeypatch: pytest.MonkeyPatch) -> None:
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
        engine="sigma-like",
        write_alerts=True,
        alert_index_date="2026-06-17",
    )

    assert len(calls) == 1
    assert calls[0]["alerts"][0]["detection"]["engine"] == "sigma-like"
    assert result["alert_indexed_count"] == 1


def test_without_write_alerts_indexer_is_not_called(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_index_alerts(*_: object, **__: object) -> list[AlertIndexResult]:
        raise AssertionError("alert indexer should not be called")

    monkeypatch.setattr(run_live_telemetry_pipeline, "index_alerts", fail_index_alerts)

    result = run_live_telemetry_pipeline.run_live_telemetry_pipeline(
        input_mode="fixture",
        fixture_detectable_powershell=True,
        engine="sigma-like",
        write_alerts=False,
    )

    assert result["alert_count"] == 1
    assert result["alert_indexed_count"] == 0


def test_summary_output_distinguishes_sigma_like_engine() -> None:
    result = run_live_telemetry_pipeline.run_live_telemetry_pipeline(
        input_mode="fixture",
        fixture_detectable_powershell=True,
        engine="sigma-like",
    )

    rendered = run_live_telemetry_pipeline.render_result(result, "summary")

    assert "sigma-like" in rendered
