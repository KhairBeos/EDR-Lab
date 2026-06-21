"""Kafka consumer pipeline that runs existing detection engines."""

from __future__ import annotations

import importlib.util
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Protocol

from collection.kafka.message_contract import (
    KafkaMessageContractError,
    deserialize_message,
    serialize_message,
)
from detection.rules.native.alert_indexer import AlertIndexingConfig, AlertIndexingError, index_alerts
from detection.rules.engine import run_detection_engines
from detection.rules.native.alerts import AlertDocumentError
from detection.rules.sigma_like.alerts import SigmaLikeAlertError


class KafkaConsumerError(RuntimeError):
    """Raised when the Kafka detection consumer fails predictably."""


@dataclass(frozen=True)
class ConsumerConfig:
    """Configuration for consuming normalized event messages."""

    bootstrap_servers: str = "localhost:9092"
    topic: str = "normalized-events"
    max_messages: int = 1
    timeout_seconds: int = 10


class NormalizedEventConsumer(Protocol):
    """Small consumer interface shared by live Kafka and deterministic tests."""

    def poll(self, timeout_seconds: float) -> bytes | None:
        """Return one message payload or None when no message is available."""

    def close(self) -> None:
        """Release consumer resources."""


@dataclass
class InMemoryKafkaConsumer:
    """In-memory consumer used by tests and dry-run fixture flows."""

    messages: list[bytes | dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        self._payloads = [serialize_message(item) if isinstance(item, dict) else item for item in self.messages]

    def poll(self, timeout_seconds: float) -> bytes | None:
        del timeout_seconds
        if not self._payloads:
            return None
        return self._payloads.pop(0)

    def close(self) -> None:
        return None


class KafkaConsumerAdapter:
    """Live Kafka consumer adapter using an already-installed Kafka client."""

    def __init__(self, config: ConsumerConfig) -> None:
        self.config = config
        self._backend = _select_backend()
        self._consumer = self._build_consumer()

    def poll(self, timeout_seconds: float) -> bytes | None:
        try:
            if self._backend == "confluent-kafka":
                message = self._consumer.poll(timeout_seconds)
                if message is None:
                    return None
                error = message.error()
                if error:
                    raise KafkaConsumerError(f"Kafka consumer poll failed: {error}")
                return message.value()

            if self._backend == "kafka-python":
                records = self._consumer.poll(timeout_ms=max(1, int(timeout_seconds * 1000)), max_records=1)
                for batch in records.values():
                    if batch:
                        return batch[0].value
                return None

            raise KafkaConsumerError(f"Unsupported Kafka consumer backend: {self._backend!r}.")
        except KafkaConsumerError:
            raise
        except Exception as exc:  # pragma: no cover - live Kafka client behavior
            raise KafkaConsumerError(f"Kafka consumer poll failed: {exc}") from exc

    def close(self) -> None:
        close = getattr(self._consumer, "close", None)
        if callable(close):
            close()

    def _build_consumer(self) -> Any:
        if self._backend == "confluent-kafka":
            from confluent_kafka import Consumer

            consumer = Consumer(
                {
                    "bootstrap.servers": self.config.bootstrap_servers,
                    "group.id": "edr-phase-4-kafka-mvp",
                    "auto.offset.reset": "earliest",
                    "enable.auto.commit": False,
                }
            )
            consumer.subscribe([self.config.topic])
            return consumer

        if self._backend == "kafka-python":
            from kafka import KafkaConsumer

            return KafkaConsumer(
                self.config.topic,
                bootstrap_servers=self.config.bootstrap_servers,
                auto_offset_reset="earliest",
                enable_auto_commit=False,
            )

        raise KafkaConsumerError(f"Unsupported Kafka consumer backend: {self._backend!r}.")


def create_live_consumer(config: ConsumerConfig) -> KafkaConsumerAdapter:
    """Create a live Kafka consumer adapter or raise a clear dependency error."""

    return KafkaConsumerAdapter(config)


def consume_and_detect_messages(
    *,
    consumer: NormalizedEventConsumer,
    config: ConsumerConfig,
    engine: str = "all",
    write_alerts: bool = False,
    alert_indexing_config: AlertIndexingConfig | None = None,
    alert_index_date: str | None = None,
) -> dict[str, Any]:
    """Consume normalized event messages and run selected detection engines."""

    if config.max_messages < 1:
        raise KafkaConsumerError("max_messages must be at least 1.")
    if config.timeout_seconds < 0:
        raise KafkaConsumerError("timeout_seconds must be non-negative.")
    if engine not in {"native", "sigma-like", "all"}:
        raise KafkaConsumerError(f"Unsupported detection engine: {engine!r}.")

    started_at = time.monotonic()
    messages: list[dict[str, Any]] = []
    alerts: list[dict[str, Any]] = []
    alert_index_results = []

    try:
        while len(messages) < config.max_messages:
            elapsed = time.monotonic() - started_at
            remaining = config.timeout_seconds - elapsed
            if remaining <= 0:
                break

            payload = consumer.poll(timeout_seconds=remaining)
            if payload is None:
                break

            message = deserialize_message(payload)
            messages.append(message)
            alerts.extend(_run_detection_engines(engine=engine, event=message["event"], source={}))
    except KafkaMessageContractError as exc:
        raise KafkaConsumerError(f"Invalid normalized event Kafka message: {exc}") from exc
    except (AlertDocumentError, SigmaLikeAlertError, KeyError, TypeError, ValueError) as exc:
        raise KafkaConsumerError(f"Kafka detection pipeline failed: {exc}") from exc
    finally:
        consumer.close()

    if write_alerts and alerts:
        try:
            alert_index_results = index_alerts(
                alerts,
                alert_indexing_config or AlertIndexingConfig(),
                index_date=alert_index_date,
            )
        except AlertIndexingError:
            raise

    result: dict[str, Any] = {
        "topic": config.topic,
        "engine": engine,
        "processed_message_count": len(messages),
        "alert_count": len(alerts),
        "alert_indexed_count": len(alert_index_results),
        "messages": messages,
        "alerts": alerts,
        "alert_index_results": [asdict(indexed) for indexed in alert_index_results],
        "timed_out": len(messages) < config.max_messages,
    }

    if not messages:
        result["message"] = "No Kafka messages consumed before timeout."
    elif not alerts:
        result["message"] = "No matching alerts produced from consumed Kafka messages."

    return result


def _run_detection_engines(*, engine: str, event: dict[str, Any], source: dict[str, str]) -> list[dict[str, Any]]:
    return run_detection_engines(engine=engine, event=event, source=source)


def _select_backend() -> str:
    if importlib.util.find_spec("confluent_kafka") is not None:
        return "confluent-kafka"

    if importlib.util.find_spec("kafka") is not None:
        return "kafka-python"

    raise KafkaConsumerError(
        "No Kafka Python client is installed. Install confluent-kafka or kafka-python to use live Kafka; "
        "dry-run and tests use the in-memory transport."
    )
