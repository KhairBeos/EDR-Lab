"""Consume normalized Kafka messages and run detection engines."""

from __future__ import annotations

import argparse
import copy
import json
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from collection.kafka.message_contract import build_normalized_event_message
from detection.kafka.consumer import (
    ConsumerConfig,
    InMemoryKafkaConsumer,
    KafkaConsumerError,
    consume_and_detect_messages,
    create_live_consumer,
)
from detection.rules.native.alert_indexer import AlertIndexingConfig, AlertIndexingError
from normalization.sysmon.process_create_normalizer import (
    SysmonNormalizationError,
    UnsupportedSysmonEventError,
    normalize_sysmon_event_1,
)
from scripts.lab_config import default_elasticsearch_url, default_kafka_bootstrap_servers


FIXTURE_PATH = REPO_ROOT / "collection" / "sysmon" / "fixtures" / "sysmon_event_1_process_create.xml"


def build_dry_run_fixture_message() -> dict:
    """Build a deterministic detectable fixture message for consumer dry-run."""

    xml_event = FIXTURE_PATH.read_text(encoding="utf-8")
    normalized_event = normalize_sysmon_event_1(xml_event)
    normalized_event = _make_fixture_detectable_powershell(normalized_event)
    return build_normalized_event_message(normalized_event, source="fixture")


def run_consumer(
    *,
    config: ConsumerConfig,
    engine: str,
    write_alerts: bool,
    alert_indexing_config: AlertIndexingConfig,
    dry_run_fixture: bool,
) -> dict:
    """Create the selected consumer and run the Kafka detection pipeline."""

    consumer = (
        InMemoryKafkaConsumer([build_dry_run_fixture_message()])
        if dry_run_fixture
        else create_live_consumer(config)
    )
    return consume_and_detect_messages(
        consumer=consumer,
        config=config,
        engine=engine,
        write_alerts=write_alerts,
        alert_indexing_config=alert_indexing_config,
    )


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Consume normalized Kafka messages and run EDR detections.")
    parser.add_argument("--bootstrap-servers", default=default_kafka_bootstrap_servers())
    parser.add_argument("--topic", default="normalized-events")
    parser.add_argument("--engine", choices=("native", "sigma-like", "all"), default="all")
    parser.add_argument("--write-alerts", action="store_true")
    parser.add_argument("--elasticsearch-url", default=default_elasticsearch_url())
    parser.add_argument("--alert-index-prefix", default="edr-alerts-native")
    parser.add_argument("--max-messages", type=int, default=1)
    parser.add_argument("--timeout-seconds", type=int, default=10)
    parser.add_argument("--dry-run-fixture", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])

    try:
        result = run_consumer(
            config=ConsumerConfig(
                bootstrap_servers=args.bootstrap_servers,
                topic=args.topic,
                max_messages=args.max_messages,
                timeout_seconds=args.timeout_seconds,
            ),
            engine=args.engine,
            write_alerts=args.write_alerts,
            alert_indexing_config=AlertIndexingConfig(
                base_url=args.elasticsearch_url,
                index_prefix=args.alert_index_prefix,
            ),
            dry_run_fixture=args.dry_run_fixture,
        )
    except (
        KafkaConsumerError,
        AlertIndexingError,
        SysmonNormalizationError,
        UnsupportedSysmonEventError,
        OSError,
    ) as exc:
        print(f"Kafka consumer failed: {exc}", file=sys.stderr)
        return 2

    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def _make_fixture_detectable_powershell(normalized_event: dict) -> dict:
    event = copy.deepcopy(normalized_event)
    event["process"]["name"] = "powershell.exe"
    event["process"]["executable"] = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    event["process"]["command_line"] = "powershell.exe -NoLogo"
    event["process"]["args"] = ["powershell.exe", "-NoLogo"]
    return event


if __name__ == "__main__":
    raise SystemExit(main())
