"""Produce normalized Sysmon Event ID 1 messages to Kafka."""

from __future__ import annotations

import argparse
import copy
import json
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from collection.kafka.message_contract import KafkaMessageContractError, build_normalized_event_message
from collection.kafka.producer import (
    InMemoryKafkaProducer,
    KafkaProducerError,
    ProducerConfig,
    create_live_producer,
)
from normalization.sysmon.process_create_normalizer import (
    SysmonNormalizationError,
    UnsupportedSysmonEventError,
    normalize_sysmon_event_1,
)
from scripts.lab_config import default_kafka_bootstrap_servers


FIXTURE_PATH = REPO_ROOT / "collection" / "sysmon" / "fixtures" / "sysmon_event_1_process_create.xml"


class KafkaProduceCommandError(RuntimeError):
    """Raised for predictable producer CLI input failures."""


def build_message_from_input(
    *,
    input_mode: str,
    xml_path: Path | None = None,
    event_id: str | None = None,
    created_at: str | None = None,
    fixture_detectable_powershell: bool = False,
) -> dict:
    """Normalize input XML and build a validated Kafka message."""

    if fixture_detectable_powershell and input_mode != "fixture":
        raise KafkaProduceCommandError("--fixture-detectable-powershell can only be used with --input fixture.")

    xml_event = _load_xml_input(input_mode=input_mode, xml_path=xml_path)
    normalized_event = normalize_sysmon_event_1(xml_event)

    if fixture_detectable_powershell:
        normalized_event = _make_fixture_detectable_powershell(normalized_event)

    return build_normalized_event_message(
        normalized_event,
        source=input_mode,
        event_id=event_id,
        created_at=created_at,
    )


def produce_message(
    *,
    message: dict,
    config: ProducerConfig,
    dry_run: bool = False,
) -> bytes:
    """Send a message through live Kafka or the deterministic in-memory producer."""

    producer = InMemoryKafkaProducer(config) if dry_run else create_live_producer(config)
    try:
        return producer.send_message(message)
    finally:
        producer.close()


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Produce normalized ECS Sysmon Event ID 1 messages to Kafka.")
    parser.add_argument("--input", choices=("fixture", "xml"), default="fixture")
    parser.add_argument("--xml-path", type=Path)
    parser.add_argument("--bootstrap-servers", default=default_kafka_bootstrap_servers())
    parser.add_argument("--topic", default="normalized-events")
    parser.add_argument("--event-id")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--fixture-detectable-powershell", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])

    try:
        message = build_message_from_input(
            input_mode=args.input,
            xml_path=args.xml_path,
            event_id=args.event_id,
            fixture_detectable_powershell=args.fixture_detectable_powershell,
        )
        produce_message(
            message=message,
            config=ProducerConfig(bootstrap_servers=args.bootstrap_servers, topic=args.topic),
            dry_run=args.dry_run,
        )
    except (
        KafkaProduceCommandError,
        KafkaMessageContractError,
        KafkaProducerError,
        SysmonNormalizationError,
        UnsupportedSysmonEventError,
        OSError,
    ) as exc:
        print(f"Kafka producer failed: {exc}", file=sys.stderr)
        return 2

    print(json.dumps(message, indent=2, sort_keys=True))
    return 0


def _load_xml_input(*, input_mode: str, xml_path: Path | None) -> str:
    if input_mode == "fixture":
        return FIXTURE_PATH.read_text(encoding="utf-8")

    if input_mode == "xml":
        if xml_path is None:
            raise KafkaProduceCommandError("--xml-path is required when --input xml.")
        return xml_path.read_text(encoding="utf-8")

    raise KafkaProduceCommandError(f"Unsupported input mode: {input_mode!r}.")


def _make_fixture_detectable_powershell(normalized_event: dict) -> dict:
    event = copy.deepcopy(normalized_event)
    event["process"]["name"] = "powershell.exe"
    event["process"]["executable"] = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    event["process"]["command_line"] = "powershell.exe -NoLogo"
    event["process"]["args"] = ["powershell.exe", "-NoLogo"]
    return event


if __name__ == "__main__":
    raise SystemExit(main())
