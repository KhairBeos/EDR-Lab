#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

wait_for_url() {
  local name="$1"
  local url="$2"
  local max_attempts="${3:-60}"
  local attempt=1

  while (( attempt <= max_attempts )); do
    if curl -fsS "$url" >/dev/null 2>&1; then
      echo "$name is ready: $url"
      return
    fi

    sleep 5
    attempt=$((attempt + 1))
  done

  echo "$name did not become ready: $url" >&2
  exit 1
}

if ! docker compose config >/dev/null; then
  echo "docker-compose.yml is invalid." >&2
  exit 1
fi

docker compose up -d

wait_for_url "Elasticsearch" "http://localhost:${ELASTICSEARCH_PORT:-9200}/_cluster/health?wait_for_status=yellow&timeout=5s"
wait_for_url "Kibana" "http://localhost:${KIBANA_PORT:-5601}/api/status" 90
wait_for_url "Logstash monitoring API" "http://localhost:${LOGSTASH_MONITORING_PORT:-9600}/_node/pipelines" 60

cat <<EOF

Phase 1 Elastic lab is running.

Elasticsearch: http://localhost:${ELASTICSEARCH_PORT:-9200}
Kibana:        http://localhost:${KIBANA_PORT:-5601}
Logstash HTTP: http://localhost:${LOGSTASH_HTTP_PORT:-8080}

Smoke ingest example:
curl -X POST http://localhost:${LOGSTASH_HTTP_PORT:-8080} \\
  -H 'Content-Type: application/json' \\
  -d '{"message":"phase-1-smoke","art.technique_id":"T1059.001"}'
EOF
