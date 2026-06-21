# CI/CD

The CI workflow validates deterministic local behavior only. It intentionally avoids live Docker, Kafka, Elasticsearch, Kibana, and Windows VM dependencies.

## Workflow

Primary workflow:

```text
.github/workflows/ci.yml
```

It runs:

```powershell
python -m pytest tests
```

On Windows, use a stable pytest temp directory if invoking tests manually:

```powershell
python -m pytest tests --basetemp=.pytest_tmp
```

The workflow uses:

- `actions/checkout`
- `actions/setup-python`
- dependency install from `requirements.txt` when present

## What CI Validates

- Sysmon Event ID 1 normalization.
- Native PowerShell detection.
- Sigma-like PowerShell detection.
- Detection coverage report generation.
- Kafka in-memory dry-run producer/consumer paths.
- SOAR dry-run response planning.
- ML-style process anomaly scoring.
- Final demo report generation.
- Documentation presence tests when enabled.

## What CI Does Not Validate

- Docker service startup.
- Live Kafka broker connectivity.
- Live Elasticsearch/Kibana connectivity.
- Windows VM setup.
- Sysmon installation on Windows.
- Atomic Red Team execution on a VM.
- Production containment actions.
- Lab-only kill-process execution.

## Manual Checks

Docker lab:

```powershell
docker compose up -d
docker compose ps
```

Kafka lab:

```powershell
docker compose -f docker-compose.kafka.yml up -d
python scripts\kafka\consume_and_detect.py --dry-run-fixture --engine all
```

Elasticsearch counts:

```powershell
python scripts\reporting\generate_final_demo_report.py --include-elasticsearch --elasticsearch-url http://localhost:9200
```

Windows VM:

Use [windows_vm_lab_setup.md](windows_vm_lab_setup.md) and validate exported Sysmon Event ID 1 XML through the fixture/XML pipeline.
