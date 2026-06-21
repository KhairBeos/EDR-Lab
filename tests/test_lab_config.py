from scripts.lab_config import (
    default_elasticsearch_url,
    default_kafka_bootstrap_servers,
    default_logstash_url,
)


def test_lab_config_defaults_to_localhost(monkeypatch) -> None:
    monkeypatch.delenv("EDR_DOCKER_HOST", raising=False)
    monkeypatch.delenv("EDR_ELASTICSEARCH_URL", raising=False)
    monkeypatch.delenv("EDR_LOGSTASH_URL", raising=False)
    monkeypatch.delenv("EDR_KAFKA_BOOTSTRAP_SERVERS", raising=False)

    assert default_elasticsearch_url() == "http://localhost:9200"
    assert default_logstash_url() == "http://localhost:8080"
    assert default_kafka_bootstrap_servers() == "localhost:9092"


def test_lab_config_uses_vm_host_ip(monkeypatch) -> None:
    monkeypatch.setenv("EDR_DOCKER_HOST", "192.168.213.1")
    monkeypatch.delenv("EDR_ELASTICSEARCH_URL", raising=False)
    monkeypatch.delenv("EDR_LOGSTASH_URL", raising=False)
    monkeypatch.delenv("EDR_KAFKA_BOOTSTRAP_SERVERS", raising=False)

    assert default_elasticsearch_url() == "http://192.168.213.1:9200"
    assert default_logstash_url() == "http://192.168.213.1:8080"
    assert default_kafka_bootstrap_servers() == "192.168.213.1:9092"


def test_explicit_service_env_wins_over_docker_host(monkeypatch) -> None:
    monkeypatch.setenv("EDR_DOCKER_HOST", "192.168.213.1")
    monkeypatch.setenv("EDR_ELASTICSEARCH_URL", "http://10.10.10.10:9200")
    monkeypatch.setenv("EDR_LOGSTASH_URL", "http://10.10.10.10:8080")
    monkeypatch.setenv("EDR_KAFKA_BOOTSTRAP_SERVERS", "10.10.10.10:9092")

    assert default_elasticsearch_url() == "http://10.10.10.10:9200"
    assert default_logstash_url() == "http://10.10.10.10:8080"
    assert default_kafka_bootstrap_servers() == "10.10.10.10:9092"
