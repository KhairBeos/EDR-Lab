# ML Anomaly MVP

## Purpose

Phase 6 adds a deterministic ML-style process anomaly detection MVP for normalized Sysmon Event ID 1 ECS documents.

This is heuristic anomaly scoring, not trained production ML. It uses inspectable features, a local baseline profile, and fixed weights. There is no training service, MLflow, LSTM, sklearn dependency, or heavy ML framework.

## Pipeline

```text
normalized event -> features -> baseline -> score -> anomaly alert -> optional alert index
```

The command extracts process features, compares them with `detection/ml/baselines/process_baseline.json`, computes a score from `0.0` to `1.0`, and builds an alert only when the score is at or above the threshold.

## Baseline Profile

The local baseline includes:

- `common_process_names`
- `allowed_parent_child_pairs`
- `max_command_line_length`
- `max_args_count`
- `suspicious_keywords`
- `normal_hours`

The default baseline keeps the repository's benign Sysmon fixture low-scoring while allowing crafted suspicious process events to cross the default threshold.

## Features

Extracted process features include:

- `process_name`
- `process_executable`
- `parent_process_name`
- `process_command_line`
- `command_line_length`
- `args_count`
- `executable_directory_depth`
- `has_encoded_command`
- `has_network_tool_flag`
- `matched_network_keywords`
- `hour_of_day`

Encoded command detection covers PowerShell flags such as `-enc`, `-encodedcommand`, `/enc`, and `/encodedcommand`.

Network/download keyword detection covers `curl`, `wget`, `nc`, `netcat`, `Invoke-WebRequest`, `iwr`, `Invoke-RestMethod`, `irm`, `DownloadString`, and `WebClient`.

## Scoring

The default threshold is `0.7`.

The score is deterministic and clamped to `0.0 <= score <= 1.0`. Risk is added for uncommon process names, unusual parent-child pairs, long command lines, too many args, encoded command flags, suspicious keywords, unusual executable paths, and hours outside the baseline when configured.

No anomaly output means the event was scored below threshold and no alert document was produced.

## Commands

Fixture input:

```powershell
python scripts\ml\run_process_anomaly_detection.py --input fixture
```

Fixture summary:

```powershell
python scripts\ml\run_process_anomaly_detection.py --input fixture --output summary
```

JSON input:

```powershell
python scripts\ml\run_process_anomaly_detection.py --input json --event-path .\event.json
```

Alert indexing:

```powershell
python scripts\ml\run_process_anomaly_detection.py --input json --event-path .\event.json --write-alerts --elasticsearch-url http://localhost:9200
```

## Alert Index Compatibility

When `--write-alerts` is set, anomaly alerts are indexed with the existing native alert indexer. The default index prefix is:

```text
edr-alerts-native
```

That keeps compatibility with the existing daily alert index naming:

```text
edr-alerts-native-YYYY.MM.DD
```

Tests monkeypatch the indexer, so live Elasticsearch is not required.

## Expected Alert Shape

```json
{
  "alert": {
    "id": "det-ml-anomaly-process-...",
    "kind": "signal",
    "status": "open",
    "created": "2026-06-17T10:00:00Z",
    "severity": "medium",
    "confidence": "medium"
  },
  "rule": {
    "id": "ml.process_anomaly",
    "name": "ML-style Process Anomaly",
    "version": 1,
    "description": "Deterministic heuristic anomaly detection for process creation events."
  },
  "event": {
    "dataset": "windows.sysmon_operational",
    "code": 1,
    "kind": "event",
    "category": ["process"],
    "type": ["start"],
    "created": "2026-06-17T10:00:00Z"
  },
  "process": {},
  "host": {},
  "user": {},
  "detection": {
    "engine": "ml-anomaly"
  },
  "ml": {
    "score": 0.82,
    "threshold": 0.7,
    "features": {},
    "reasons": []
  }
}
```

## Out Of Scope

- Heavy ML frameworks
- MLflow
- Training service
- LSTM or sequence models
- Kafka changes
- SOAR changes
- TheHive
- Dashboards
- Real containment

## Related Final Docs

- [Architecture](architecture.md)
- [Final demo script](final_demo_script.md)
- [Final demo report MVP](final_demo_report_mvp.md)
