import json
import urllib.error
from datetime import date

import pytest

from collection.elasticsearch.event_indexer import (
    EventIndexingConfig,
    EventIndexingError,
    build_event_document_id,
    build_event_index_name,
    index_event,
    index_events,
)


def sample_event() -> dict:
    return {
        "@timestamp": "2026-06-08T02:30:00.0000000Z",
        "event": {
            "dataset": "windows.sysmon_operational",
            "code": 1,
            "created": "2026-06-08T02:30:00.000Z",
        },
        "host": {"name": "WIN11-EDR-LAB"},
        "process": {
            "entity_id": "{process-guid}",
            "pid": 5824,
            "executable": r"C:\Windows\System32\cmd.exe",
            "command_line": "cmd.exe /c whoami",
        },
        "sysmon": {
            "event_data": {
                "ProcessGuid": "{9f7f5c20-1c5d-6666-0100-000000000400}",
            }
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


def test_build_event_index_name_from_string_date() -> None:
    assert build_event_index_name("2026-06-17") == "edr-normalized-events-2026.06.17"


def test_build_event_index_name_from_date_object() -> None:
    assert build_event_index_name(date(2026, 6, 17)) == "edr-normalized-events-2026.06.17"


def test_event_id_used_as_document_id() -> None:
    event = sample_event()
    event["event"]["id"] = "event-id-1"

    assert build_event_document_id(event) == "event-id-1"


def test_sysmon_process_guid_fallback_document_id() -> None:
    assert build_event_document_id(sample_event()) == "{9f7f5c20-1c5d-6666-0100-000000000400}"


def test_stable_hash_fallback_document_id_is_deterministic() -> None:
    event = sample_event()
    del event["sysmon"]["event_data"]["ProcessGuid"]

    first = build_event_document_id(event)
    second = build_event_document_id(event)

    assert first.startswith("event-")
    assert first == second


def test_invalid_event_document_raises_event_indexing_error() -> None:
    with pytest.raises(EventIndexingError, match="non-empty mapping"):
        build_event_document_id({})


def test_index_event_uses_put_url_and_unchanged_json_body(monkeypatch: pytest.MonkeyPatch) -> None:
    captured = {}
    event = sample_event()

    def fake_urlopen(request: object, timeout: int) -> FakeResponse:
        captured["request"] = request
        captured["timeout"] = timeout
        return FakeResponse(status=201, payload={"result": "created"})

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    result = index_event(
        event,
        EventIndexingConfig(base_url="http://localhost:9200", timeout_seconds=7),
        index_date="2026-06-17",
    )

    request = captured["request"]
    assert captured["timeout"] == 7
    assert request.get_method() == "PUT"
    assert request.full_url == (
        "http://localhost:9200/edr-normalized-events-2026.06.17/_doc/"
        "{9f7f5c20-1c5d-6666-0100-000000000400}"
    )
    assert json.loads(request.data.decode("utf-8")) == event
    assert result.index == "edr-normalized-events-2026.06.17"
    assert result.document_id == "{9f7f5c20-1c5d-6666-0100-000000000400}"
    assert result.result == "created"
    assert result.status == 201


def test_index_event_parses_successful_updated_response(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_urlopen(request: object, timeout: int) -> FakeResponse:
        return FakeResponse(status=200, payload={"result": "updated"})

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    result = index_event(sample_event(), EventIndexingConfig(), index_date="2026-06-17")

    assert result.result == "updated"
    assert result.status == 200


def test_index_events_indexes_multiple_events(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_urlopen(request: object, timeout: int) -> FakeResponse:
        return FakeResponse(status=201, payload={"result": "created"})

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    first = sample_event()
    second = sample_event()
    second["sysmon"]["event_data"]["ProcessGuid"] = "{second-guid}"

    results = index_events([first, second], EventIndexingConfig(), index_date="2026-06-17")

    assert [result.document_id for result in results] == [
        "{9f7f5c20-1c5d-6666-0100-000000000400}",
        "{second-guid}",
    ]


def test_network_error_raises_event_indexing_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_urlopen(request: object, timeout: int) -> FakeResponse:
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    with pytest.raises(EventIndexingError, match="Event indexing failed"):
        index_event(sample_event(), EventIndexingConfig(), index_date="2026-06-17")


def test_http_error_status_raises_event_indexing_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_urlopen(request: object, timeout: int) -> FakeResponse:
        return FakeResponse(status=500, payload={"error": "boom"})

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    with pytest.raises(EventIndexingError, match="HTTP status 500"):
        index_event(sample_event(), EventIndexingConfig(), index_date="2026-06-17")


def test_malformed_json_response_raises_event_indexing_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_urlopen(request: object, timeout: int) -> RawFakeResponse:
        return RawFakeResponse(status=201, payload=b"not-json")

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    with pytest.raises(EventIndexingError, match="malformed JSON"):
        index_event(sample_event(), EventIndexingConfig(), index_date="2026-06-17")


def test_missing_result_response_raises_event_indexing_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_urlopen(request: object, timeout: int) -> FakeResponse:
        return FakeResponse(status=201, payload={"_id": "event-doc"})

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    with pytest.raises(EventIndexingError, match="missing result"):
        index_event(sample_event(), EventIndexingConfig(), index_date="2026-06-17")
