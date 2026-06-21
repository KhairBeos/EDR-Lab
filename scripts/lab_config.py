"""Runtime defaults for Docker-backed lab services."""

from __future__ import annotations

import os


DEFAULT_DOCKER_HOST = "localhost"
DEFAULT_ELASTICSEARCH_PORT = "9200"
DEFAULT_KAFKA_PORT = "9092"
DEFAULT_LOGSTASH_HTTP_PORT = "8080"


def default_docker_host() -> str:
    """Host/IP that Python commands should use to reach Docker services."""

    return _env("EDR_DOCKER_HOST", DEFAULT_DOCKER_HOST)


def default_elasticsearch_url() -> str:
    """Elasticsearch URL for CLI defaults.

    Override order:
    1. EDR_ELASTICSEARCH_URL
    2. EDR_DOCKER_HOST + EDR_ELASTICSEARCH_PORT
    3. localhost:9200
    """

    return _env(
        "EDR_ELASTICSEARCH_URL",
        f"http://{default_docker_host()}:{_env('EDR_ELASTICSEARCH_PORT', DEFAULT_ELASTICSEARCH_PORT)}",
    )


def default_logstash_url() -> str:
    """Logstash HTTP ingest URL for CLI defaults."""

    return _env(
        "EDR_LOGSTASH_URL",
        f"http://{default_docker_host()}:{_env('EDR_LOGSTASH_HTTP_PORT', DEFAULT_LOGSTASH_HTTP_PORT)}",
    )


def default_kafka_bootstrap_servers() -> str:
    """Kafka bootstrap server list for CLI defaults."""

    return _env(
        "EDR_KAFKA_BOOTSTRAP_SERVERS",
        f"{default_docker_host()}:{_env('EDR_KAFKA_PORT', DEFAULT_KAFKA_PORT)}",
    )


def _env(name: str, default: str) -> str:
    value = os.environ.get(name)
    if value is None or not value.strip():
        return default
    return value.strip()
