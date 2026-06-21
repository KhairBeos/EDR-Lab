# Kafka Pipeline MVP Runbook

## Purpose

This runbook documents the Phase 4 Kafka transport MVP for normalized ECS Sysmon Event ID 1 events.

Kafka is optional transport between normalization and detection:

```text
Sysmon XML / fixture
  -> normalize Sysmon Event ID 1
  -> produce normalized event JSON to Kafka topic normalized-events
  -> consume normalized event JSON from Kafka
  -> run detection engine native|sigma-like|all
  -> build alerts
  -> optionally index alerts
```

This is not a smoke-only script. Dry-run fixture mode and in-memory transport exercise the same message contract and detection path without requiring live Kafka or Elasticsearch.

## Architecture

Producer side:

- `scripts/kafka/produce_normalized_event.py` loads fixture or XML input.
- `normalize_sysmon_event_1` converts Sysmon Event ID 1 XML into normalized ECS JSON.
- `collection/kafka/message_contract.py` builds and validates the Kafka message.
- `collection/kafka/producer.py` sends JSON bytes through live Kafka when a Kafka client is installed, or in-memory transport for dry-run/tests.

Consumer side:

- `scripts/kafka/consume_and_detect.py` reads live Kafka or deterministic fixture input.
- `detection/kafka/consumer.py` validates each consumed message.
- Existing native and Sigma-like detection engines evaluate `message["event"]`.
- Existing alert builders create alert documents.
- Existing alert indexer writes alerts only when `--write-alerts` is set.

## Message Contract

Topic:

```text
normalized-events
```

Message shape:

```json
{
  "schema_version": "1.0",
  "event_id": "...",
  "event": {},
  "metadata": {
    "producer": "edr-live-telemetry-pipeline",
    "created_at": "2026-06-17T00:00:00Z",
    "source": "fixture",
    "pipeline_phase": "phase-4-kafka-mvp"
  }
}
```

Validation rules:

- `schema_version` must be exactly `1.0`.
- `event_id` must be non-empty.
- `event` must contain normalized ECS Sysmon Event ID 1 JSON.
- `event.event.dataset` must be `windows.sysmon_operational`.
- `event.event.code` must be `1`.
- `metadata.producer` must be `edr-live-telemetry-pipeline`.
- `metadata.source` must be `fixture` or `xml`.
- `metadata.pipeline_phase` must be `phase-4-kafka-mvp`.
- `metadata.created_at` must be present.

## Dry-Run Commands

Producer dry-run, no Kafka required:

```powershell
python scripts\kafka\produce_normalized_event.py --input fixture --dry-run
```

Consumer dry-run fixture, no Kafka or Elasticsearch required:

```powershell
python scripts\kafka\consume_and_detect.py --dry-run-fixture --engine all --max-messages 1 --timeout-seconds 10
```

The consumer dry-run fixture adapts the existing Sysmon Event ID 1 fixture into a detectable current-process PowerShell event so both native and Sigma-like detections can be verified deterministically.

## Local Kafka

Start local Kafka:

```powershell
docker compose -f docker-compose.kafka.yml up -d
```

Produce one normalized fixture event:

```powershell
python scripts\kafka\produce_normalized_event.py --input fixture --bootstrap-servers localhost:9092 --topic normalized-events
```

Produce one deterministic detectable PowerShell fixture event for the live Kafka demo:

```powershell
python scripts\kafka\produce_normalized_event.py --input fixture --fixture-detectable-powershell --bootstrap-servers localhost:9092 --topic normalized-events
```

Consume one event and run both engines:

```powershell
python scripts\kafka\consume_and_detect.py --bootstrap-servers localhost:9092 --topic normalized-events --engine all --max-messages 1 --timeout-seconds 10
```

Consume, detect, and write alerts:

```powershell
python scripts\kafka\consume_and_detect.py --bootstrap-servers localhost:9092 --topic normalized-events --engine all --write-alerts
```

## XML Input

Produce an exported Sysmon Event ID 1 XML file:

```powershell
python scripts\kafka\produce_normalized_event.py --input xml --xml-path .\event.xml --dry-run
```

Live Kafka XML produce:

```powershell
python scripts\kafka\produce_normalized_event.py --input xml --xml-path .\event.xml --bootstrap-servers localhost:9092 --topic normalized-events
```

## Dependency Behavior

No Kafka Python dependency is added by this MVP.

Live producer and consumer adapters choose an already-installed client in this order:

1. `confluent-kafka`
2. `kafka-python`

If neither package is importable, live Kafka commands fail with a clear operational error. Dry-run commands and tests still work through the in-memory transport.

## Alert Indexing

Alerts are not written by default.

Use `--write-alerts` to index produced alerts through the existing alert indexer:

```text
edr-alerts-native-YYYY.MM.DD
```

Elasticsearch URL and prefix can be changed:

```powershell
python scripts\kafka\consume_and_detect.py `
  --engine all `
  --write-alerts `
  --elasticsearch-url http://localhost:9200 `
  --alert-index-prefix edr-alerts-native
```

## Tests

```powershell
python -m pytest tests\test_kafka_message_contract.py
python -m pytest tests\test_kafka_detection_pipeline.py
python -m pytest tests
```

Tests do not require live Kafka or Elasticsearch.

## Out of Scope

- ML
- SOAR
- TheHive
- Dashboards
- Schema Registry
- Kafka Connect
- Exactly-once semantics
- Multi-broker Kafka clusters
- New Sysmon Event IDs
- Replacing the existing live telemetry pipeline
- Replacing native or Sigma-like detection semantics

## Related Final Docs

- [Docker lab setup](docker_lab_setup.md)
- [Architecture](architecture.md)
- [Final demo script](final_demo_script.md)
- [Final demo report MVP](final_demo_report_mvp.md)
