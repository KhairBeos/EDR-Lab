Status: done

# Process/network/file/registry behavioral sequence detection

## Goal

Add deterministic behavioral correlation detection for the EDR demo by linking normalized Sysmon events across process, network, file, and registry telemetry.

This phase should detect short attack sequences using the Phase 12 telemetry breadth and Phase 13 single-event rules, without changing the existing native or Sigma-like rule semantics.

## Context

Current project capabilities:

- Sysmon Event ID `1`, `3`, `11`, and `13` normalization.
- Native and Sigma-like rules for `T1059.001`, `T1105`, `T1547.001`, and `T1218-lite`.
- ML anomaly detection.
- SOAR dry-run response.
- Lab-only protection action.
- Demo case matrix with TP/TN/FP/FN transparency.
- Detection coverage report, final demo report, and dashboard data generation.
- A current behavioral stub at `detection/behavioral/sequence_detector.py` that returns no alerts.

The project domain calls this area `Analysis and correlation`: enrichment, scoring, case creation, and ATT&CK coverage updates.

## Problem

The current detection layer is mostly single-event detection. That is useful for deterministic demos, but an advanced EDR should also show how related endpoint telemetry becomes a behavioral story:

- A download chain: process start -> network connection -> file create.
- A persistence chain: process start -> registry value set -> optional payload launch.
- A LOLBin chain: suspicious proxy execution -> optional network or child/file follow-up.

The key constraint is that this must remain deterministic, local, testable, and lab-safe. The goal is not full graph analytics yet; the goal is a clear correlation engine that can explain why several normalized events belong to one short sequence.

## What to build

Create:

- `detection/behavioral/correlation.py`
- `detection/behavioral/sequences.py`
- `detection/behavioral/alerts.py`
- `samples/demo_cases/behavioral_t1105_sequence.json`
- `samples/demo_cases/behavioral_t1547_sequence.json`
- `tests/test_behavioral_correlation.py`
- `docs/behavioral_correlation_detection.md`

Update:

- `detection/behavioral/sequence_detector.py` to become a compatibility wrapper, or remove the stub only if no imports depend on it.
- Detection coverage reporting to include behavioral rule metadata and the behavioral engine.
- Final demo report to mention behavioral rules, behavioral engine coverage, technique coverage, and correlated sequence count if available.
- Demo case catalog and runner only if low-risk, adding behavioral sequence cases without removing existing Phase 9 or Phase 13 cases.
- Dashboard data only if needed to surface `behavioral` engine counts or correlated sequence counts.

Do not remove or rewrite existing single-event cases.

## Technical Design

### Public API

Expose a pure local API from `detection/behavioral/correlation.py`:

```python
from typing import Any


def detect_behavioral_sequences(
    events: list[dict[str, Any]],
    *,
    window_seconds: int | None = None,
) -> list[dict[str, Any]]:
    """Return zero or more behavioral alert documents from normalized ECS events."""
    ...
```

Keep `detection/behavioral/sequence_detector.py` as a thin wrapper for existing callers:

```python
from typing import Any

from detection.behavioral.correlation import detect_behavioral_sequences


def detect_sequences(events: list[dict[str, Any]], window_seconds: int = 60) -> list[dict[str, Any]]:
    return detect_behavioral_sequences(events, window_seconds=window_seconds)
```

Why: a compatibility wrapper keeps the old symbol working while allowing the clearer Phase 14 module names. Trade-off: one extra import path exists, but it avoids breaking any current or future tests that already found `detect_sequences()`.

### Correlation Model

The behavioral engine should:

- Accept a list of already normalized ECS-like event dictionaries.
- Deep-copy or read events without mutation.
- Sort by `@timestamp` or `event.created`.
- Group by `host.name`.
- Prefer `process.entity_id` as the process context key.
- Fall back to `(process.pid, process.name)` for deterministic samples.
- Optionally consider a close process context when a registry or file event shares host, process name, marker, and time window.
- Support configurable sequence windows, with per-sequence defaults.
- Avoid Elasticsearch, Windows, Docker, Kafka, Sysmon, or wall-clock dependencies.

Recommended internal shape in `detection/behavioral/sequences.py`:

```python
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

StepMatcher = Callable[[dict[str, Any]], bool]


@dataclass(frozen=True)
class SequenceDefinition:
    rule_id: str
    sequence_name: str
    technique_id: str
    technique_name: str
    tactic: tuple[str, ...]
    severity: str
    confidence: str
    required_steps: tuple[str, ...]
    optional_steps: tuple[str, ...] = ()
    window_seconds: int = 300
```

Best practice: keep matchers small and deterministic. Do not duplicate the whole single-event rule engine; reuse shared marker constants or helper semantics from `detection/rules/demo_semantics.py` when that keeps the implementation simple.

### Alert Document

Create `detection/behavioral/alerts.py` to build alert documents similar to native alerts, but with behavioral fields:

- `rule.id`
- `rule.name`
- `rule.version`
- `rule.description`
- `alert.kind = "signal"`
- `alert.status = "open"`
- `alert.severity`
- `alert.confidence`
- `detection.engine = "behavioral"`
- `detection.sequence_name`
- `detection.sequence_steps`
- `detection.correlated_event_count`
- `attack.technique.id`
- `attack.technique.name`
- `attack.tactic`
- `host.name`
- Representative `process` context when available.
- `source.document_ids` for provenance.

Important: `source.document_ids` is alert provenance, not ECS network `source.ip`. Do not overwrite or confuse the two concepts. If a normalized event has no document ID, derive a stable local ID from event timestamp, event code, host, process context, and sequence index.

Example alert shape:

```python
{
    "alert": {
        "id": "det-behavioral-t1105-download-sequence-...",
        "kind": "signal",
        "status": "open",
        "severity": "high",
        "confidence": "high",
        "created": "2026-06-18T01:03:00Z",
    },
    "rule": {
        "id": "det.behavioral.t1105_download_sequence",
        "name": "T1105 behavioral download sequence",
        "version": 1,
        "description": "Correlates process, network, and file evidence for a deterministic T1105 demo sequence.",
    },
    "detection": {
        "engine": "behavioral",
        "sequence_name": "t1105_download_sequence",
        "sequence_steps": ["process", "network", "file"],
        "correlated_event_count": 3,
    },
    "source": {
        "document_ids": ["demo-t1105-process", "demo-t1105-network", "demo-t1105-file"],
    },
    "attack": {
        "technique": {
            "id": "T1105",
            "name": "Ingress Tool Transfer",
        },
        "tactic": ["Command and Control"],
    },
}
```

Trade-off: reusing the native `build_alert_document()` would avoid duplication, but behavioral alerts represent multiple events rather than one event. A dedicated builder is clearer and prevents awkward single-event assumptions.

### Sequence 1: T1105 Download Chain

Rule ID:

- `det.behavioral.t1105_download_sequence`

Detect when events on the same host and same or close process context show all required steps within `5` minutes by default:

1. Process event:
   - `event.category` contains `process`
   - `process.name` is one of `certutil.exe`, `bitsadmin.exe`, `curl.exe`, or `powershell.exe`
   - `process.command_line` or `sysmon.event_data` contains `EDR_DEMO_T1105` or a safe download marker.
2. Network event:
   - `event.code = 3`
   - destination is `127.0.0.1` or `example.test`
   - process context matches the process event where possible.
3. File create event:
   - `event.code = 11`
   - `file.path` contains `Downloads`
   - `file.name` or `file.path` contains `edr_demo`
   - marker contains `EDR_DEMO_T1105` when available.

Alert metadata:

- Technique ID: `T1105`
- Technique name: `Ingress Tool Transfer`
- Tactic: `Command and Control`
- Severity: `high`
- Confidence: `high`
- Detection sequence: `["process", "network", "file"]`

### Sequence 2: T1547.001 Persistence Chain

Rule ID:

- `det.behavioral.t1547_001_registry_persistence_sequence`

Detect when events on the same host and same or close process context show required steps within `10` minutes by default:

1. Process event:
   - `process.name` is `reg.exe` or `powershell.exe`
   - command line or `sysmon.event_data` contains `EDR_DEMO_T1547`, `Run`, `RunOnce`, or a registry persistence marker.
2. Registry event:
   - `event.code = 13`
   - `event.category` contains `registry`
   - `registry.path` contains `CurrentVersion\Run` or `CurrentVersion\RunOnce`
   - `registry.data.strings` or `sysmon.event_data.Details` contains `EDR_DEMO_T1547`, `EDRDemo`, or a configured payload marker.
3. Optional follow-up process:
   - process command line contains the configured payload marker.

Alert metadata:

- Technique ID: `T1547.001`
- Technique name: `Registry Run Keys / Startup Folder`
- Tactic: `Persistence`
- Severity: `high`
- Confidence: `high`
- Detection engine: `behavioral`

### Sequence 3: T1218 LOLBin Chain

Rule ID:

- `det.behavioral.t1218_lolbin_sequence`

Detect when events on the same host and same or close process context show:

1. Required process event:
   - `process.name` is one of `rundll32.exe`, `regsvr32.exe`, or `mshta.exe`
   - command line or `sysmon.event_data` contains `EDR_DEMO_T1218` or a safe suspicious marker such as `javascript:`, `scrobj.dll`, `url.dll,FileProtocolHandler`, `suspicious.dll`, or `example.test`.
2. Optional network event:
   - destination is `127.0.0.1` or `example.test`.
3. Optional child process or file event:
   - event carries the same marker or close process context.

Window: `5` minutes by default.

Alert metadata:

- Technique ID: `T1218`
- Technique name: `System Binary Proxy Execution`
- Tactic: `Defense Evasion`
- Severity: `medium`
- Confidence: `medium`
- Detection engine: `behavioral`

This remains `T1218-lite`: deterministic demo correlation, not full LOLBin behavior analytics.

## Demo Sample Design

Create sequence JSON samples as arrays of normalized events, not executable payloads.

`samples/demo_cases/behavioral_t1105_sequence.json` should contain three events:

- Process Event ID `1` for `certutil.exe` with `EDR_DEMO_T1105`.
- Network Event ID `3` to `127.0.0.1` or `example.test`.
- File Event ID `11` creating `C:\Users\edr-lab\Downloads\EDR_DEMO_T1105_edr_demo.txt`.

`samples/demo_cases/behavioral_t1547_sequence.json` should contain at least two events:

- Process Event ID `1` for `reg.exe` or `powershell.exe` with a registry persistence marker.
- Registry Event ID `13` setting a `CurrentVersion\Run` or `RunOnce` value.

Use stable timestamps such as `2026-06-18T01:00:00.000Z`, `2026-06-18T01:01:00.000Z`, and `2026-06-18T01:02:00.000Z`. Keep host and process context aligned so tests can prove correlation.

## Demo Case Integration

Add two to three demo catalog cases only if the integration stays small:

- TP behavioral `T1105` sequence.
- TP behavioral `T1547.001` sequence.
- TN benign unrelated sequence.

Because the current live demo runner processes one normalized event at a time, behavioral sequence cases likely need either:

- A new `runner_mode = "behavioral"` that loads a JSON array and calls `detect_behavioral_sequences()`.
- Or a small adapter that can pass list-of-events samples into the behavioral engine without changing the single-event `run_live_telemetry_pipeline()` contract.

Prefer the new runner mode if implemented. It keeps single-event detection and behavioral correlation separated.

Update catalog validation as needed:

- Add `behavioral` to allowed engines or keep `engine = "all"` and record actual alert engine from `detection.engine`.
- Add `behavioral` to allowed runner modes.
- Ensure expected rule IDs include the behavioral rule IDs.

Do not hide existing false positives or false negatives.

## Report Integration

Detection coverage report should include behavioral rule metadata:

- Engine coverage summary includes behavioral count.
- Rule inventory includes:
  - `det.behavioral.t1105_download_sequence`
  - `det.behavioral.t1547_001_registry_persistence_sequence`
  - `det.behavioral.t1218_lolbin_sequence`
- Covered techniques show behavioral engine coverage for `T1105`, `T1547.001`, and `T1218`.

Final demo report should mention:

- Behavioral correlation as Phase 14.
- Behavioral engine coverage.
- Correlated sequence count if available from demo matrix or generated dashboard data.
- Limitations: deterministic local sequence correlation, not full endpoint graph analytics.

## Docs

Create `docs/behavioral_correlation_detection.md`.

Cover:

- What behavioral sequence detection means in this project.
- How process, network, file, and registry events are linked.
- Default time windows and why they are deterministic.
- How demo samples are structured.
- How to run tests and regenerate reports.
- Limitations:
  - No live infrastructure required.
  - No graph database.
  - No streaming state.
  - No production containment.
  - T1218 remains a constrained `T1218-lite` demo.

## Tests

Create `tests/test_behavioral_correlation.py`.

Cover:

- `T1105` sequence matches process + network + file.
- `T1105` sequence does not match when outside the window.
- `T1105` sequence does not match benign unrelated events.
- `T1547.001` sequence matches process + registry event.
- `T1218` sequence matches LOLBin chain.
- Alerts include `detection.engine = "behavioral"`.
- Alerts include correlated event count.
- Alerts include correlated document IDs.
- Input events are not mutated.
- Events are sorted by timestamp before matching.
- Host grouping prevents cross-host correlation.
- `process.entity_id` is preferred over PID/name when available.
- PID/name fallback works for deterministic samples.
- Case matrix includes behavioral cases if demo integration is implemented.
- Detection coverage report includes behavioral rules.
- Tests require no Windows, Sysmon, Elasticsearch, Docker, or Kafka.

## Commands

Behavioral tests:

```powershell
python -m pytest tests\test_behavioral_correlation.py
```

Full tests:

```powershell
python -m pytest tests --basetemp=.pytest_tmp_phase14
```

Regenerate detection coverage report:

```powershell
python scripts\reporting\generate_detection_coverage_report.py
```

Regenerate final demo report:

```powershell
python scripts\reporting\generate_final_demo_report.py
```

Regenerate demo case matrix:

```powershell
python scripts\demo\run_demo_case_matrix.py --output reports\demo_cases\case_matrix.json
```

Regenerate dashboard data:

```powershell
python scripts\demo\generate_demo_dashboard_data.py --case-matrix reports\demo_cases\case_matrix.json --output reports\demo_cases\dashboard_data.json
```

## Acceptance Criteria

- [ ] `detect_behavioral_sequences()` returns one `T1105` behavioral alert for the deterministic process + network + file sample.
- [ ] `detect_behavioral_sequences()` returns one `T1547.001` behavioral alert for the deterministic process + registry sample.
- [ ] `detect_behavioral_sequences()` returns one `T1218` behavioral alert for the deterministic LOLBin sample.
- [ ] Correlation uses sorted event timestamps and does not depend on wall-clock time.
- [ ] Correlation groups by `host.name`.
- [ ] Correlation prefers `process.entity_id` and falls back to `(process.pid, process.name)`.
- [ ] Input events are not mutated.
- [ ] Behavioral alerts include `detection.engine = "behavioral"`.
- [ ] Behavioral alerts include `detection.sequence_name`, `detection.sequence_steps`, and `detection.correlated_event_count`.
- [ ] Behavioral alerts include `source.document_ids`.
- [ ] Existing native and Sigma-like single-event rule behavior stays stable.
- [ ] Existing Phase 9 and Phase 13 demo cases are not removed.
- [ ] Behavioral demo cases are added if low-risk and run without live infrastructure.
- [ ] Detection coverage report includes behavioral rules and engine counts.
- [ ] Final demo report includes behavioral correlation coverage and limitations.
- [ ] `docs/behavioral_correlation_detection.md` explains sequence detection, windows, samples, and limitations.
- [ ] `python -m pytest tests\test_behavioral_correlation.py` succeeds.
- [ ] `python -m pytest tests --basetemp=.pytest_tmp_phase14` succeeds.
- [ ] `python scripts\reporting\generate_detection_coverage_report.py` succeeds.
- [ ] `python scripts\reporting\generate_final_demo_report.py` succeeds.
- [ ] `python scripts\demo\run_demo_case_matrix.py --output reports\demo_cases\case_matrix.json` succeeds.
- [ ] `python scripts\demo\generate_demo_dashboard_data.py --case-matrix reports\demo_cases\case_matrix.json --output reports\demo_cases\dashboard_data.json` succeeds.

## Blocked By

None - can start immediately. Phase 12 telemetry and Phase 13 single-event detection are already present.

## Do Not

- Do not add malware payloads.
- Do not add credential dumping.
- Do not add production containment.
- Do not change existing single-event rule semantics.
- Do not hide FP/FN cases.
- Do not require live infrastructure in tests.
- Do not require Elasticsearch, Docker, Kafka, Sysmon, or Windows to run behavioral tests.
