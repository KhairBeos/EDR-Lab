# Docker Lab Setup

Docker services are optional manual lab infrastructure. They are not required for deterministic tests or CI.

## Elastic / Kibana / Logstash

The default Docker Compose stack is defined in:

```text
docker-compose.yml
```

Start the local Elastic lab:

```powershell
docker compose up -d
```

Check services:

```powershell
docker compose ps
```

Stop services:

```powershell
docker compose down
```

Expected local endpoints when the stack is healthy:

- Elasticsearch: `http://localhost:9200`
- Kibana: `http://localhost:5601`
- Logstash HTTP ingest: `http://localhost:8080`

## Docker on Host, Project in VM

When Docker runs on the Windows host and Python commands run inside a VM, the
VM must call the host IP instead of `localhost`.

For the current VMware NAT setup, the host IP is:

```text
192.168.213.1
```

Set the lab endpoint env vars before starting Docker on the host, and before
running Python commands in the VM:

```powershell
.\scripts\setup\use_host_docker.ps1 192.168.213.1
```

If you move to another network, change only that IP argument. Common choices:

- VMware NAT / VMnet8: `192.168.213.1`
- VMware Host-only / VMnet1: `192.168.88.1`
- Bridged Wi-Fi: host Wi-Fi IP, for example `192.168.1.107`

The Python CLI defaults read these variables:

```text
EDR_DOCKER_HOST
EDR_ELASTICSEARCH_URL
EDR_LOGSTASH_URL
EDR_KAFKA_BOOTSTRAP_SERVERS
```

Kafka also needs the host-side advertised listener:

```text
KAFKA_ADVERTISED_HOST
```

`docker-compose.kafka.yml` uses `KAFKA_ADVERTISED_HOST` and defaults to
`192.168.213.1` for this VMware NAT lab.

From the VM, verify connectivity:

```powershell
curl.exe http://192.168.213.1:9200
curl.exe http://192.168.213.1:8080
```

## Kafka

Kafka local setup is defined in:

```text
docker-compose.kafka.yml
```

Start Kafka:

```powershell
docker compose -f docker-compose.kafka.yml up -d
```

Check services:

```powershell
docker compose -f docker-compose.kafka.yml ps
```

Stop Kafka:

```powershell
docker compose -f docker-compose.kafka.yml down
```

The MVP topic is:

```text
normalized-events
```

## Useful Commands

```powershell
docker compose up -d
docker compose -f docker-compose.kafka.yml up -d
docker compose ps
docker compose down
```

## Troubleshooting

### Kafka Image / Tag Issue

If Docker cannot pull the Kafka image, inspect `docker-compose.kafka.yml` and verify the image tag still exists upstream. Do not change compose behavior unless the tag is clearly broken.

### Port 9092 Conflict

Kafka uses port `9092`. Stop any local Kafka broker or change the compose port mapping intentionally for your lab.

### Elasticsearch Unavailable

Check service health:

```powershell
docker compose ps
```

Then query:

```powershell
curl.exe http://localhost:9200
```

### Missing Kafka Python Dependency

Live Kafka adapters need a Kafka Python client such as `confluent-kafka` or `kafka-python`. Deterministic dry-run tests do not need these packages.
