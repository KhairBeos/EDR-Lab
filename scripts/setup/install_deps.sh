#!/usr/bin/env bash
set -euo pipefail

required_ports=(9200 5601 8080)

require_command() {
  local name="$1"

  if ! command -v "$name" >/dev/null 2>&1; then
    echo "Missing required command: $name" >&2
    exit 1
  fi
}

check_port() {
  local port="$1"

  if command -v ss >/dev/null 2>&1; then
    if ss -ltn "( sport = :$port )" | grep -q ":$port"; then
      echo "Port $port is already in use." >&2
      exit 1
    fi
    return
  fi

  if command -v lsof >/dev/null 2>&1; then
    if lsof -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1; then
      echo "Port $port is already in use." >&2
      exit 1
    fi
  fi
}

require_command docker

if ! docker compose version >/dev/null 2>&1; then
  echo "Docker Compose v2 is required. Install the Docker Compose plugin." >&2
  exit 1
fi

if ! docker info >/dev/null 2>&1; then
  echo "Docker is installed but the daemon is not reachable." >&2
  exit 1
fi

echo "Docker: $(docker --version)"
echo "Docker Compose: $(docker compose version)"

for port in "${required_ports[@]}"; do
  check_port "$port"
done

echo "Phase 1 Elastic lab prerequisites look ready."
