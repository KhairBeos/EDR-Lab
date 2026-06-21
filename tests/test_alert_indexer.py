import json
import urllib.error
from datetime import date

import pytest

from detection.rules.native.alert_indexer import (
    AlertIndexingConfig,
    AlertIndexingError,
    build_alert_index_name,
    index_alert,
    index_alerts,
)


def sample_alert() -> dict:
    return {
        "alert": {
            "id": "det-t1059-001-powershell-process-start-test",
            "severity": "medium",
            "confidence": "high",
        },
        "rule": {
            "id": "det.t1059_001.powershell_process_start",
        },
    }


class FakeResponse:
    def __init__(self, *, status: int, payload: dict) -> None:
        self.status = status
        self.payload = payload

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def getcode(self) -> int:
        return self.status

    def read(self) -> bytes:
        return json.dumps(self.payload).encode("utf-8")


class RawFakeResponse:
    def __init__(self, *, status: int, payload: bytes) -> None:
        self.status = status
        self.payload = payload

    def __enter__(self) -> "RawFakeResponse":
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def getcode(self) -> int:
        return self.status

    def read(self) -> bytes:
        return self.payload


def test_build_alert_index_name_from_string_date() -> None:
    assert build_alert_index_name("2026-06-17") == "edr-alerts-native-2026.06.17"


def test_build_alert_index_name_from_date_object() -> None:
    assert build_alert_index_name(date(2026, 6, 17)) == "edr-alerts-native-2026.06.17"


def test_index_alert_uses_alert_id_put_url_and_unchanged_json_body(monkeypatch: pytest.MonkeyPatch) -> None:
    captured = {}
    alert = sample_alert()

    def fake_urlopen(request: object, timeout: int) -> FakeResponse:
        captured["request"] = request
        captured["timeout"] = timeout
        return FakeResponse(status=201, payload={"result": "created"})

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    result = index_alert(
        alert,
        AlertIndexingConfig(base_url="http://localhost:9200", timeout_seconds=7),
        index_date="2026-06-17",
    )

    request = captured["request"]
    assert captured["timeout"] == 7
    assert request.get_method() == "PUT"
    assert request.full_url == (
        "http://localhost:9200/edr-alerts-native-2026.06.17/_doc/"
        "det-t1059-001-powershell-process-start-test"
    )
    assert json.loads(request.data.decode("utf-8")) == alert
    assert result.index == "edr-alerts-native-2026.06.17"
    assert result.document_id == "det-t1059-001-powershell-process-start-test"
    assert result.result == "created"
    assert result.status == 201


def test_index_alert_parses_successful_updated_response(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_urlopen(request: object, timeout: int) -> FakeResponse:
        return FakeResponse(status=200, payload={"result": "updated"})

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    result = index_alert(sample_alert(), AlertIndexingConfig(), index_date="2026-06-17")

    assert result.result == "updated"
    assert result.status == 200


def test_index_alerts_indexes_multiple_alerts(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_urlopen(request: object, timeout: int) -> FakeResponse:
        return FakeResponse(status=201, payload={"result": "created"})

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    first = sample_alert()
    second = sample_alert()
    second["alert"]["id"] = "det-t1059-001-powershell-process-start-second"

    results = index_alerts([first, second], AlertIndexingConfig(), index_date="2026-06-17")

    assert [result.document_id for result in results] == [
        "det-t1059-001-powershell-process-start-test",
        "det-t1059-001-powershell-process-start-second",
    ]


def test_missing_alert_id_raises_alert_indexing_error() -> None:
    alert = {"alert": {}}

    with pytest.raises(AlertIndexingError, match="alert.id"):
        index_alert(alert, AlertIndexingConfig(), index_date="2026-06-17")


def test_network_error_raises_alert_indexing_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_urlopen(request: object, timeout: int) -> FakeResponse:
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    with pytest.raises(AlertIndexingError, match="Alert indexing failed"):
        index_alert(sample_alert(), AlertIndexingConfig(), index_date="2026-06-17")


def test_http_error_status_raises_alert_indexing_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_urlopen(request: object, timeout: int) -> FakeResponse:
        return FakeResponse(status=500, payload={"error": "boom"})

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    with pytest.raises(AlertIndexingError, match="HTTP status 500"):
        index_alert(sample_alert(), AlertIndexingConfig(), index_date="2026-06-17")


def test_malformed_json_response_raises_alert_indexing_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_urlopen(request: object, timeout: int) -> RawFakeResponse:
        return RawFakeResponse(status=201, payload=b"not-json")

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    with pytest.raises(AlertIndexingError, match="malformed JSON"):
        index_alert(sample_alert(), AlertIndexingConfig(), index_date="2026-06-17")
