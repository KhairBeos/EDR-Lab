Status: done

# Kafka normalized event detection pipeline

## Parent

`.scratch/phase-4-kafka-pipeline-mvp/PRD.md`

## Goal

Implement a production-shaped Kafka pipeline MVP that transports normalized ECS Sysmon Event ID 1 events through Kafka and runs the existing detection engines to produce alert documents.

This must not be smoke-only. Fixture mode and fake in-memory transport are deterministic test modes of the real pipeline boundary.

## Context

Phase 2 Native Detection Pipeline MVP is complete.

Phase 3 Live Telemetry Pipeline and Detection Engines are complete.

Current capabilities:

- Normalize Sysmon Event ID 1 XML/fixture with `normalize_sysmon_event_1`.
- Index normalized events to `edr-normalized-events-YYYY.MM.DD`.
- Run the native detection engine.
- Run the Sigma-like detection engine.
- Build alert documents for both engines.
- Index alerts to `edr-alerts-native-YYYY.MM.DD`.
- Generate detection coverage reports.

## What to build

Add Kafka as an optional transport between normalized event production and detection consumption.

Target pipeline:

```text
Sysmon XML / fixture
  -> normalize Sysmon Event ID 1
  -> produce normalized event JSON to Kafka topic normalized-events
  -> consume normalized event JSON from Kafka
  -> run selected detection engine native|sigma-like|all
  -> build alerts
  -> optionally index alerts to edr-alerts-native-YYYY.MM.DD
```

The implementation should preserve the Phase 3 live telemetry behavior and reuse existing modules wherever possible. Kafka is a transport boundary, not a new detection engine or a replacement for the existing normalizer.

## Technical design

Add a small Kafka transport layer under `collection/kafka/`:

- `message_contract.py` owns the message schema, validation, serialization, and deserialization helpers.
- `producer.py` owns producer interfaces and the live Kafka producer adapter when a supported dependency exists.
- A fake in-memory producer/consumer should be available for tests and `--dry-run`/fixture paths.

Add a detection consumer under `detection/kafka/`:

- Consume normalized event messages from `normalized-events`.
- Validate the message contract before detection.
- Pass `message["event"]` into existing native and Sigma-like detection logic.
- Build alerts using the existing alert builders.
- Optionally index alerts with the existing native alert indexer.
- Stop after `--max-messages` or `--timeout-seconds`; never block forever.

Dependency strategy:

1. Prefer `confluent-kafka` only if it already exists in project dependencies.
2. Otherwise use `kafka-python` only if it already exists in project dependencies.
3. If no Kafka dependency exists, implement the producer/consumer behind a small interface and keep live Kafka dependency documented as an operator prerequisite.

Do not add a new Kafka Python dependency unless the repo already uses one or a human explicitly approves it later.

## Message contract

Messages on `normalized-events` must use this shape:

```json
{
  "schema_version": "1.0",
  "event_id": "...",
  "event": {},
  "metadata": {
    "producer": "edr-live-telemetry-pipeline",
    "created_at": "...",
    "source": "fixture",
    "pipeline_phase": "phase-4-kafka-mvp"
  }
}
```

Contract requirements:

- `schema_version` must be exactly `"1.0"` for this MVP.
- `event_id` must be stable and should come from normalized `event.id` when available.
- `event` must be a normalized ECS Sysmon Event ID 1 document.
- `event.event.dataset` must be `windows.sysmon_operational`.
- `event.event.code` must be `1` or `"1"`.
- `metadata.producer` must default to `edr-live-telemetry-pipeline`.
- `metadata.created_at` must be an ISO-8601 UTC timestamp.
- `metadata.source` must be `fixture` or `xml`.
- `metadata.pipeline_phase` must be `phase-4-kafka-mvp`.
- Validation errors must be explicit and testable.

## Files to create or edit

Create:

- `docker-compose.kafka.yml` or update existing `docker-compose.yml` if that is the established local service file.
- `collection/kafka/message_contract.py`
- `collection/kafka/producer.py`
- `detection/kafka/consumer.py`
- `scripts/kafka/produce_normalized_event.py`
- `scripts/kafka/consume_and_detect.py`
- `tests/test_kafka_message_contract.py`
- `tests/test_kafka_detection_pipeline.py`
- `docs/kafka_pipeline_mvp.md`

Edit only if needed for clean imports or shared helpers:

- `scripts/pipeline/run_live_telemetry_pipeline.py`
- `docs/live_telemetry_pipeline_mvp.md`
- `docs/sigma_detection_mvp.md`

Do not edit unless a blocking bug is found:

- `normalization/sysmon/process_create_normalizer.py`
- `collection/elasticsearch/event_indexer.py`
- `detection/rules/native/loader.py`
- `detection/rules/native/evaluator.py`
- `detection/rules/native/alerts.py`
- `detection/rules/native/alert_indexer.py`
- `detection/rules/sigma_like/loader.py`
- `detection/rules/sigma_like/evaluator.py`
- `detection/rules/sigma_like/alerts.py`
- Existing Phase 2/Phase 3 smoke scripts.

## CLI

Producer fixture input:

```powershell
python scripts\kafka\produce_normalized_event.py --input fixture
```

Producer XML input:

```powershell
python scripts\kafka\produce_normalized_event.py --input xml --xml-path .\event.xml
```

Producer options:

- `--bootstrap-servers`, default `localhost:9092`
- `--topic`, default `normalized-events`
- `--event-id`, optional override
- `--dry-run`

Consumer:

```powershell
python scripts\kafka\consume_and_detect.py
```

Consumer options:

- `--bootstrap-servers`, default `localhost:9092`
- `--topic`, default `normalized-events`
- `--engine native|sigma-like|all`, default `all`
- `--write-alerts`
- `--elasticsearch-url`, default `http://localhost:9200`
- `--alert-index-prefix`, default `edr-alerts-native`
- `--max-messages`, default `1`
- `--timeout-seconds`, default `10`
- `--dry-run-fixture`

## Behavior details

Producer behavior:

- `--input fixture` must load the existing Sysmon Event ID 1 fixture.
- `--input xml --xml-path <path>` must normalize the provided XML file.
- `--dry-run` must print the validated message JSON without requiring live Kafka.
- Without `--dry-run`, the producer must send validated JSON bytes to the configured topic.
- Operational failures should exit non-zero with readable stderr.

Consumer behavior:

- `--dry-run-fixture` must build an in-memory Kafka message from the fixture and process it through the same consumer/detection code path.
- The consumer must validate every message before detection.
- `--engine native` runs only the native engine.
- `--engine sigma-like` runs only the Sigma-like engine.
- `--engine all` runs native and Sigma-like engines and returns alerts from both.
- `--write-alerts` writes produced alerts through the existing alert indexer.
- Without `--write-alerts`, alerts are returned/rendered but not indexed.
- The consumer must stop after `--max-messages` or `--timeout-seconds`.
- Empty polls/timeouts must produce a clear summary, not an infinite wait.

## Docker/Kafka

Add local Kafka support for development.

Acceptable shape:

- A dedicated `docker-compose.kafka.yml` is preferred if the existing compose file is focused on Elasticsearch.
- Updating an existing compose file is acceptable if that is the repo convention.
- Use a single-broker local Kafka service.
- Expose Kafka at `localhost:9092`.
- Do not add Schema Registry, Kafka Connect, exactly-once setup, or a multi-broker production cluster.

## Commands to run

Focused tests:

```powershell
python -m pytest tests\test_kafka_message_contract.py
python -m pytest tests\test_kafka_detection_pipeline.py
```

Full regression:

```powershell
python -m pytest tests
```

Producer dry-run:

```powershell
python scripts\kafka\produce_normalized_event.py --input fixture --dry-run
```

Consumer dry-run fixture:

```powershell
python scripts\kafka\consume_and_detect.py --dry-run-fixture --engine all --max-messages 1 --timeout-seconds 10
```

Local Kafka service:

```powershell
docker compose -f docker-compose.kafka.yml up -d
```

Live Kafka produce:

```powershell
python scripts\kafka\produce_normalized_event.py --input fixture --bootstrap-servers localhost:9092 --topic normalized-events
```

Live Kafka consume and detect:

```powershell
python scripts\kafka\consume_and_detect.py --bootstrap-servers localhost:9092 --topic normalized-events --engine all --max-messages 1 --timeout-seconds 10
```

Live Kafka consume, detect, and index alerts:

```powershell
python scripts\kafka\consume_and_detect.py --bootstrap-servers localhost:9092 --topic normalized-events --engine all --write-alerts
```

## Acceptance criteria

- [ ] Kafka message contract validates a normalized Sysmon Event ID 1 ECS event.
- [ ] Message contract validation rejects missing `schema_version`, missing `event_id`, missing `event`, missing `metadata`, non-Sysmon dataset, and non Event ID 1 messages.
- [ ] Producer can build a Kafka message from the existing fixture without live Kafka using `--dry-run`.
- [ ] Producer can build a Kafka message from XML input using `--input xml --xml-path`.
- [ ] Producer supports `--bootstrap-servers`, `--topic`, `--event-id`, and `--dry-run`.
- [ ] Live producer path is behind a small interface so tests do not require Kafka.
- [ ] Consumer can process fixture/in-memory message without live Kafka using `--dry-run-fixture`.
- [ ] Consumer can run native detection on the consumed normalized event.
- [ ] Consumer can run Sigma-like detection on the consumed normalized event.
- [ ] Consumer with `--engine all` can produce native and Sigma-like alerts for a detectable PowerShell event.
- [ ] Consumer supports `--max-messages` and stops after the configured count.
- [ ] Consumer supports `--timeout-seconds` and exits cleanly when no messages arrive.
- [ ] Consumer does not block forever.
- [ ] Consumer with `--write-alerts` uses the existing alert indexer.
- [ ] Tests pass without live Kafka.
- [ ] Tests pass without live Elasticsearch.
- [ ] Docker docs include commands to start local Kafka.
- [ ] Docs include fixture dry-run producer and consumer commands.
- [ ] Docs include live Kafka producer and consumer commands.
- [ ] Docs clearly state dependency behavior when no Kafka Python package exists.
- [ ] Pipeline remains production-shaped and is not a smoke-only script.

## Blocked by

- `.scratch/phase-3-live-telemetry-pipeline/issues/01-live-telemetry-to-detection-pipeline.md`
- `.scratch/phase-3-live-telemetry-pipeline/issues/02-sigma-like-detection-mvp.md`
- `.scratch/phase-3-live-telemetry-pipeline/issues/03-detection-coverage-validation-report.md`
- `.scratch/phase-2-detection-engine-mvp/issues/06-native-detection-pipeline-with-alert-indexing.md`

## Out-of-scope boundaries

- Do not add ML.
- Do not add SOAR.
- Do not add TheHive.
- Do not create dashboards.
- Do not add Schema Registry.
- Do not implement exactly-once semantics.
- Do not add a multi-broker production Kafka cluster.
- Do not add Kafka Connect.
- Do not add new Sysmon Event IDs.
- Do not replace the existing live telemetry pipeline.
- Do not replace existing native or Sigma-like detection semantics.
- Do not require live Kafka or Elasticsearch for tests.

## Comments
