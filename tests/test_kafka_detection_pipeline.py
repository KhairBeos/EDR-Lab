import copy
import json

import pytest

from collection.kafka.message_contract import build_normalized_event_message
from collection.kafka.producer import InMemoryKafkaProducer, ProducerConfig
from detection.kafka import consumer as kafka_consumer
from detection.kafka.consumer import ConsumerConfig, InMemoryKafkaConsumer, consume_and_detect_messages
from detection.rules.native.alert_indexer import AlertIndexResult
from normalization.sysmon.process_create_normalizer import normalize_sysmon_event_1
from scripts.kafka import consume_and_detect, produce_normalized_event
from scripts.smoke.end_to_end_art_telemetry_smoke import load_fixture


def normalized_event() -> dict:
    return normalize_sysmon_event_1(load_fixture())


def detectable_powershell_event() -> dict:
    event = copy.deepcopy(normalized_event())
    event["process"]["name"] = "powershell.exe"
    event["process"]["executable"] = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    event["process"]["command_line"] = "powershell.exe -NoLogo"
    event["process"]["args"] = ["powershell.exe", "-NoLogo"]
    return event


def detectable_message(event_id: str = "detectable-1") -> dict:
    return build_normalized_event_message(
        detectable_powershell_event(),
        source="fixture",
        event_id=event_id,
        created_at="2026-06-17T00:00:00Z",
    )


def test_producer_can_build_fixture_message_without_live_kafka() -> None:
    message = produce_normalized_event.build_message_from_input(
        input_mode="fixture",
        created_at="2026-06-17T00:00:00Z",
    )

    producer = InMemoryKafkaProducer(ProducerConfig(topic="normalized-events"))
    payload = producer.send_message(message)

    assert producer.sent_messages == [("normalized-events", payload)]
    assert json.loads(payload.decode("utf-8"))["event"]["event"]["code"] == 1


def test_producer_fixture_default_remains_cmd_exe() -> None:
    message = produce_normalized_event.build_message_from_input(
        input_mode="fixture",
        created_at="2026-06-17T00:00:00Z",
    )

    assert message["event"]["process"]["name"] == "cmd.exe"
    assert message["event"]["process"]["command_line"] == "cmd.exe /c whoami"


def test_producer_fixture_detectable_powershell_adapts_current_process_only() -> None:
    original = produce_normalized_event.build_message_from_input(
        input_mode="fixture",
        created_at="2026-06-17T00:00:00Z",
    )

    message = produce_normalized_event.build_message_from_input(
        input_mode="fixture",
        created_at="2026-06-17T00:00:00Z",
        fixture_detectable_powershell=True,
    )

    assert original["event"]["process"]["name"] == "cmd.exe"
    assert message["event"]["process"]["name"] == "powershell.exe"
    assert message["event"]["process"]["executable"] == r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    assert message["event"]["process"]["command_line"] == "powershell.exe -NoLogo"
    assert message["event"]["process"]["args"] == ["powershell.exe", "-NoLogo"]


def test_consumer_engine_all_produces_two_alerts_from_detectable_producer_message() -> None:
    message = produce_normalized_event.build_message_from_input(
        input_mode="fixture",
        created_at="2026-06-17T00:00:00Z",
        fixture_detectable_powershell=True,
    )

    result = consume_and_detect_messages(
        consumer=InMemoryKafkaConsumer([message]),
        config=ConsumerConfig(max_messages=1, timeout_seconds=10),
        engine="all",
    )

    rule_ids = {alert["rule"]["id"] for alert in result["alerts"]}
    assert result["alert_count"] == 2
    assert rule_ids == {
        "det.t1059_001.powershell_process_start",
        "sigma_like.t1059_001.powershell_process_start",
    }


def test_producer_can_build_xml_message_from_temp_file(tmp_path) -> None:
    xml_path = tmp_path / "event.xml"
    xml_path.write_text(load_fixture(), encoding="utf-8")

    message = produce_normalized_event.build_message_from_input(
        input_mode="xml",
        xml_path=xml_path,
        event_id="xml-event-1",
        created_at="2026-06-17T00:00:00Z",
    )

    assert message["event_id"] == "xml-event-1"
    assert message["metadata"]["source"] == "xml"


def test_dry_run_producer_does_not_require_live_kafka(monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    def fail_live_producer(*_: object, **__: object) -> object:
        raise AssertionError("live Kafka producer should not be created for --dry-run")

    monkeypatch.setattr(produce_normalized_event, "create_live_producer", fail_live_producer)

    exit_code = produce_normalized_event.main(["--input", "fixture", "--dry-run", "--event-id", "fixture-1"])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert json.loads(captured.out)["event_id"] == "fixture-1"


def test_consumer_dry_run_fixture_processes_in_memory_message() -> None:
    result = consume_and_detect.run_consumer(
        config=ConsumerConfig(max_messages=1, timeout_seconds=10),
        engine="all",
        write_alerts=False,
        alert_indexing_config=object(),
        dry_run_fixture=True,
    )

    assert result["processed_message_count"] == 1
    assert result["alert_count"] == 2


def test_consumer_engine_native_produces_one_native_alert() -> None:
    result = consume_and_detect_messages(
        consumer=InMemoryKafkaConsumer([detectable_message()]),
        config=ConsumerConfig(max_messages=1, timeout_seconds=10),
        engine="native",
    )

    assert result["alert_count"] == 1
    assert result["alerts"][0]["rule"]["id"] == "det.t1059_001.powershell_process_start"
    assert "engine" not in result["alerts"][0]["detection"]


def test_consumer_engine_sigma_like_produces_one_sigma_like_alert() -> None:
    result = consume_and_detect_messages(
        consumer=InMemoryKafkaConsumer([detectable_message()]),
        config=ConsumerConfig(max_messages=1, timeout_seconds=10),
        engine="sigma-like",
    )

    assert result["alert_count"] == 1
    assert result["alerts"][0]["rule"]["id"] == "sigma_like.t1059_001.powershell_process_start"
    assert result["alerts"][0]["detection"]["engine"] == "sigma-like"


def test_consumer_engine_all_produces_two_alerts() -> None:
    result = consume_and_detect_messages(
        consumer=InMemoryKafkaConsumer([detectable_message()]),
        config=ConsumerConfig(max_messages=1, timeout_seconds=10),
        engine="all",
    )

    rule_ids = {alert["rule"]["id"] for alert in result["alerts"]}
    assert result["alert_count"] == 2
    assert rule_ids == {
        "det.t1059_001.powershell_process_start",
        "sigma_like.t1059_001.powershell_process_start",
    }


def test_consumer_stops_after_max_messages() -> None:
    result = consume_and_detect_messages(
        consumer=InMemoryKafkaConsumer([detectable_message("one"), detectable_message("two")]),
        config=ConsumerConfig(max_messages=1, timeout_seconds=10),
        engine="native",
    )

    assert result["processed_message_count"] == 1
    assert result["messages"][0]["event_id"] == "one"


def test_consumer_timeout_exits_cleanly_with_zero_messages() -> None:
    result = consume_and_detect_messages(
        consumer=InMemoryKafkaConsumer([]),
        config=ConsumerConfig(max_messages=1, timeout_seconds=0),
        engine="all",
    )

    assert result["processed_message_count"] == 0
    assert result["alert_count"] == 0
    assert result["timed_out"] is True
    assert result["message"] == "No Kafka messages consumed before timeout."


def test_consumer_with_write_alerts_uses_existing_alert_indexer(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = []

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

    monkeypatch.setattr(kafka_consumer, "index_alerts", fake_index_alerts)

    result = consume_and_detect_messages(
        consumer=InMemoryKafkaConsumer([detectable_message()]),
        config=ConsumerConfig(max_messages=1, timeout_seconds=10),
        engine="native",
        write_alerts=True,
    )

    assert len(calls) == 1
    assert len(calls[0]["alerts"]) == 1
    assert result["alert_indexed_count"] == 1
    assert result["alert_index_results"][0]["index"] == "edr-alerts-native-2026.06.17"


def test_without_write_alerts_alert_indexer_is_not_called(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_index_alerts(*_: object, **__: object) -> list[AlertIndexResult]:
        raise AssertionError("alert indexer should not be called")

    monkeypatch.setattr(kafka_consumer, "index_alerts", fail_index_alerts)

    result = consume_and_detect_messages(
        consumer=InMemoryKafkaConsumer([detectable_message()]),
        config=ConsumerConfig(max_messages=1, timeout_seconds=10),
        engine="native",
        write_alerts=False,
    )

    assert result["alert_count"] == 1
    assert result["alert_indexed_count"] == 0
