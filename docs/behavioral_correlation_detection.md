# Behavioral Correlation Detection

Phase 14 adds a pure local behavioral engine that correlates already normalized ECS-like Sysmon events into short deterministic attack sequences. It does not replace the existing native or Sigma-like single-event rules.

## What It Detects

Behavioral sequence detection means the engine links several related events into one alert:

- `T1105`: process start -> network connection -> file create.
- `T1547.001`: process start -> registry Run/RunOnce value set, with optional payload follow-up.
- `T1218`: suspicious LOLBin process, with optional network or child/file follow-up.

The public API is:

```python
from detection.behavioral.correlation import detect_behavioral_sequences

alerts = detect_behavioral_sequences(normalized_events)
```

`detection/behavioral/sequence_detector.py` remains a compatibility wrapper for older callers:

```python
from detection.behavioral.sequence_detector import detect_sequences

alerts = detect_sequences(normalized_events, window_seconds=300)
```

## Correlation Keys

Events are sorted by `@timestamp` or `event.created`, then grouped by `host.name`. A sequence cannot cross hosts.

Process context uses this order:

1. Prefer `process.entity_id` when both events provide it.
2. Fall back to `(process.pid, process.name)` for deterministic samples that do not have an entity ID.
3. For close context, allow matching safe demo markers on the same host inside the sequence window.

Example:

```python
process = {
    "host": {"name": "WIN11-EDR-LAB"},
    "process": {"pid": 5100, "entity_id": "{demo}", "name": "certutil.exe"},
}
network = {
    "host": {"name": "WIN11-EDR-LAB"},
    "process": {"pid": 5100, "entity_id": "{demo}", "name": "certutil.exe"},
    "destination": {"ip": "127.0.0.1"},
}
```

## Default Windows

| Sequence | Rule ID | Window |
| --- | --- | ---: |
| T1105 download chain | `det.behavioral.t1105_download_sequence` | 300 seconds |
| T1547.001 registry persistence chain | `det.behavioral.t1547_001_registry_persistence_sequence` | 600 seconds |
| T1218 LOLBin chain | `det.behavioral.t1218_lolbin_sequence` | 300 seconds |

You can override all defaults for a call:

```python
alerts = detect_behavioral_sequences(events, window_seconds=60)
```

## Demo Samples

Behavioral samples live under `samples/demo_cases/` as JSON arrays:

- `behavioral_t1105_sequence.json`
- `behavioral_t1547_sequence.json`
- `behavioral_benign_unrelated_sequence.json`

They are normalized event documents only. They do not execute commands, download payloads, modify registry keys, or require Windows/Sysmon at test time.

## Reports And Demo Matrix

The detection coverage report includes a `behavioral` engine count and rule inventory entries for all three behavioral rules. The demo case matrix has `runner_mode = "behavioral"` for sequence samples and records `correlated_sequence_count`.

Regenerate artifacts:

```powershell
python -m pytest tests\test_behavioral_correlation.py
python scripts\reporting\generate_detection_coverage_report.py
python scripts\reporting\generate_final_demo_report.py
python scripts\demo\run_demo_case_matrix.py --output reports\demo_cases\case_matrix.json
python scripts\demo\generate_demo_dashboard_data.py --case-matrix reports\demo_cases\case_matrix.json --output reports\demo_cases\dashboard_data.json
```

## Limitations

- No live infrastructure is required.
- No graph database is used.
- No streaming state is kept between calls.
- No production containment is triggered.
- `T1218` remains T1218-lite: deterministic demo correlation, not full LOLBin analytics.
