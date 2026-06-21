import copy
from datetime import UTC, datetime

import pytest

from collection.kafka.message_contract import (
    KafkaMessageContractError,
    build_normalized_event_message,
    deserialize_message,
    serialize_message,
)
from normalization.sysmon.process_create_normalizer import normalize_sysmon_event_1
from scripts.smoke.end_to_end_art_telemetry_smoke import load_fixture


def normalized_event() -> dict:
    return normalize_sysmon_event_1(load_fixture())


def valid_message(source: str = "fixture") -> dict:
    return build_normalized_event_message(
        normalized_event(),
        source=source,
        created_at="2026-06-17T00:00:00Z",
    )


def test_valid_normalized_sysmon_event_1_message() -> None:
    message = valid_message()

    assert message["schema_version"] == "1.0"
    assert message["event_id"] == "{9f7f5c20-1c5d-6666-0100-000000000400}"
    assert message["event"]["event"]["dataset"] == "windows.sysmon_operational"
    assert message["event"]["event"]["code"] == 1
    assert message["metadata"] == {
        "producer": "edr-live-telemetry-pipeline",
        "created_at": "2026-06-17T00:00:00Z",
        "source": "fixture",
        "pipeline_phase": "phase-4-kafka-mvp",
    }


@pytest.mark.parametrize(
    ("field", "message_fragment"),
    [
        ("schema_version", "schema_version"),
        ("event_id", "event_id"),
        ("event", "event is required"),
        ("metadata", "metadata is required"),
    ],
)
def test_required_top_level_fields_are_rejected(field: str, message_fragment: str) -> None:
    message = valid_message()
    del message[field]

    with pytest.raises(KafkaMessageContractError, match=message_fragment):
        serialize_message(message)


def test_non_sysmon_dataset_rejected() -> None:
    message = valid_message()
    message["event"]["event"]["dataset"] = "edr.raw"

    with pytest.raises(KafkaMessageContractError, match="dataset"):
        serialize_message(message)


def test_non_event_id_1_rejected() -> None:
    message = valid_message()
    message["event"]["event"]["code"] = 3

    with pytest.raises(KafkaMessageContractError, match="Event ID 1"):
        serialize_message(message)


def test_serialize_deserialize_round_trip() -> None:
    message = valid_message()

    payload = serialize_message(message)
    parsed = deserialize_message(payload)

    assert parsed == message


def test_event_id_override() -> None:
    message = build_normalized_event_message(
        normalized_event(),
        source="fixture",
        event_id="override-event-id",
        created_at=datetime(2026, 6, 17, tzinfo=UTC),
    )

    assert message["event_id"] == "override-event-id"
    assert message["metadata"]["created_at"] == "2026-06-17T00:00:00Z"


def test_metadata_source_fixture_and_xml_are_valid() -> None:
    assert valid_message("fixture")["metadata"]["source"] == "fixture"
    assert valid_message("xml")["metadata"]["source"] == "xml"


def test_invalid_metadata_source_rejected() -> None:
    with pytest.raises(KafkaMessageContractError, match="metadata.source"):
        build_normalized_event_message(normalized_event(), source="socket")


def test_event_code_string_one_is_valid() -> None:
    event = copy.deepcopy(normalized_event())
    event["event"]["code"] = "1"

    message = build_normalized_event_message(event, source="fixture", created_at="2026-06-17T00:00:00Z")

    assert message["event"]["event"]["code"] == "1"
