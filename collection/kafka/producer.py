"""Kafka producer adapters for normalized ECS event messages."""

from __future__ import annotations

import importlib.util
from dataclasses import dataclass, field
from typing import Any, Protocol

from collection.kafka.message_contract import serialize_message, validate_normalized_event_message


class KafkaProducerError(RuntimeError):
    """Raised when a Kafka producer cannot send normalized event messages."""


@dataclass(frozen=True)
class ProducerConfig:
    """Configuration for producing normalized event messages."""

    bootstrap_servers: str = "localhost:9092"
    topic: str = "normalized-events"


class NormalizedEventProducer(Protocol):
    """Small producer interface shared by live Kafka and deterministic tests."""

    def send_message(self, message: dict[str, Any]) -> bytes:
        """Send one validated normalized event message and return the JSON payload bytes."""

    def close(self) -> None:
        """Release producer resources."""


@dataclass
class InMemoryKafkaProducer:
    """In-memory producer used by tests and dry-run flows."""

    config: ProducerConfig = field(default_factory=ProducerConfig)
    sent_messages: list[tuple[str, bytes]] = field(default_factory=list)

    def send_message(self, message: dict[str, Any]) -> bytes:
        payload = serialize_message(message)
        self.sent_messages.append((self.config.topic, payload))
        return payload

    def close(self) -> None:
        return None


class KafkaProducerAdapter:
    """Live Kafka producer adapter using an already-installed Kafka client."""

    def __init__(self, config: ProducerConfig) -> None:
        self.config = config
        self._backend = _select_backend()
        self._producer = self._build_producer()

    def send_message(self, message: dict[str, Any]) -> bytes:
        validate_normalized_event_message(message)
        payload = serialize_message(message)

        try:
            if self._backend == "confluent-kafka":
                self._producer.produce(self.config.topic, value=payload)
                remaining = self._producer.flush()
                if remaining:
                    raise KafkaProducerError(f"Kafka producer flush left {remaining} undelivered message(s).")
            elif self._backend == "kafka-python":
                future = self._producer.send(self.config.topic, payload)
                future.get(timeout=10)
                self._producer.flush()
            else:
                raise KafkaProducerError(f"Unsupported Kafka producer backend: {self._backend!r}.")
        except KafkaProducerError:
            raise
        except Exception as exc:  # pragma: no cover - live Kafka client behavior
            raise KafkaProducerError(f"Kafka producer send failed: {exc}") from exc

        return payload

    def close(self) -> None:
        close = getattr(self._producer, "close", None)
        if callable(close):
            close()

    def _build_producer(self) -> Any:
        if self._backend == "confluent-kafka":
            from confluent_kafka import Producer

            return Producer({"bootstrap.servers": self.config.bootstrap_servers})

        if self._backend == "kafka-python":
            from kafka import KafkaProducer

            return KafkaProducer(bootstrap_servers=self.config.bootstrap_servers)

        raise KafkaProducerError(f"Unsupported Kafka producer backend: {self._backend!r}.")


def create_live_producer(config: ProducerConfig) -> KafkaProducerAdapter:
    """Create a live Kafka producer adapter or raise a clear dependency error."""

    return KafkaProducerAdapter(config)


def _select_backend() -> str:
    if importlib.util.find_spec("confluent_kafka") is not None:
        return "confluent-kafka"

    if importlib.util.find_spec("kafka") is not None:
        return "kafka-python"

    raise KafkaProducerError(
        "No Kafka Python client is installed. Install confluent-kafka or kafka-python to use live Kafka; "
        "dry-run and tests use the in-memory transport."
    )
