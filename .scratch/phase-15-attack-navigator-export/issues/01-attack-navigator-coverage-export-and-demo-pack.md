Status: done

# ATT&CK Navigator coverage export and demo pack

## Goal

Generate a MITRE ATT&CK Navigator-compatible coverage layer from the current EDR detection coverage report.

This phase is reporting and visualization only. It should make existing coverage easier to explain during the teacher demo, without adding new detection rules or changing detection behavior.

## Context

Current project capabilities:

- Sysmon Event ID `1`, `3`, `11`, and `13` normalization.
- Native and Sigma-like detections for `T1059.001`, `T1105`, `T1547.001`, and constrained `T1218-lite`.
- ML anomaly detection for deterministic process anomaly samples.
- Behavioral correlation detections for `T1105`, `T1547.001`, and `T1218-lite`.
- Detection coverage report at `reports/detection_coverage_report.json`.
- Final demo report at `reports/final_demo_report.json` and `reports/final_demo_report.md`.
- Demo case matrix at `reports/demo_cases/case_matrix.json` with TP/TN/FP/FN transparency.
- Dashboard data at `reports/demo_cases/dashboard_data.json`, including `correlated_sequence_count`.
- Lab-only protection action with guarded kill-process evidence.

The project domain calls this area `Coverage matrix`: the mapping between MITRE ATT&CK techniques and implemented detection coverage. This issue turns that matrix into a Navigator import artifact.

## Problem

The EDR now has strong deterministic demo coverage across native, Sigma-like, ML anomaly, and behavioral engines. The current JSON and Markdown reports are useful for validation, but they are not as visually clear as an ATT&CK Navigator layer.

For the final demo, the teacher should be able to see:

- Which ATT&CK techniques are covered.
- Which detection engines contribute to each technique.
- Which Sysmon Event IDs support the coverage.
- Which techniques have demo case evidence.
- Which limitations still exist, especially `T1218-lite`, deterministic demo rules, and lab-only response/protection.

This must stay local, deterministic, and testable without internet or live infrastructure.

## What to build

Create:

- `reporting/attack_navigator_layer.py`
- `scripts/reporting/generate_attack_navigator_layer.py`
- `docs/attack_navigator_coverage.md`
- `tests/test_attack_navigator_layer.py`
- `reports/attack_navigator/README.md`

Generate:

- `reports/attack_navigator/edr_attack_layer.json`
- `reports/attack_navigator/coverage_summary.md`

Update only if low-risk:

- `scripts/demo/build_demo_evidence_bundle.py` to include the generated Navigator artifacts when present.
- `reporting/final_demo_report.py` to mention ATT&CK Navigator coverage export as a reporting capability.
- `README.md` final demo command checklist to include the new generator command.

Do not add new detection semantics.

## Technical Design

### Public API

Create `reporting/attack_navigator_layer.py` with a pure local API:

```python
from typing import Any


def build_attack_navigator_layer(coverage_report: dict[str, Any]) -> dict[str, Any]:
    """Build a MITRE ATT&CK Navigator-compatible layer from coverage report data."""
    ...


def build_coverage_summary_markdown(
    coverage_report: dict[str, Any],
    layer: dict[str, Any],
    *,
    case_matrix: dict[str, Any] | None = None,
    dashboard_data: dict[str, Any] | None = None,
    project_status: str | None = None,
) -> str:
    """Render a deterministic operator summary for the generated layer."""
    ...
```

Why: the layer builder should be unit-testable without file I/O. The CLI owns reading and writing files. Trade-off: the function signatures are slightly more explicit, but they keep reporting logic separate from operational concerns.

### Layer Shape

The generated JSON must be compatible with common ATT&CK Navigator import expectations.

Use:

- `name = "EDR Advanced MVP Coverage"`
- `domain = "enterprise-attack"`
- `description` describing the project phase and engines.
- A Navigator layer version field compatible with common imports, for example `versions.layer = "4.5"` and `versions.attack = "14"` if the repo already uses this style; otherwise use a stable, documented shape.
- `techniques` list.

Each technique entry should include:

- `techniqueID`
- `tactic` when known.
- `score`
- `color`
- `comment`
- `metadata`

Required techniques:

- `T1059.001`
- `T1105`
- `T1547.001`
- `T1218`

The layer should be deterministic: repeated runs from the same inputs produce the same technique ordering, scores, colors, comments, and metadata ordering.

### Source Data

Use `reports/detection_coverage_report.json` as the primary source when practical.

Expected fields from the current report:

- `covered_techniques`
- `rule_inventory`
- `engine_coverage_summary`
- `validation_results`
- `project_phase`

Enhance with optional local artifacts when available:

- `reports/demo_cases/case_matrix.json`
- `reports/demo_cases/dashboard_data.json`
- `reports/final_demo_report.json`

Missing optional artifacts should not fail the layer build. Missing required coverage report should fail clearly in the CLI.

Do not require:

- Elasticsearch
- Kibana
- Docker
- Kafka
- Windows
- Sysmon service
- Atomic Red Team execution
- Internet access

### Technique Aggregation

Build each technique from the coverage report by joining:

- `covered_techniques[*].technique_id`
- matching `rule_inventory[*].attack.technique_id`
- matching demo case rows from `case_matrix.cases[*].technique_id`
- matching dashboard counts from `dashboard_data`

Recommended internal shape:

```python
technique = {
    "technique_id": "T1105",
    "technique_name": "Ingress Tool Transfer",
    "tactic": ["Command and Control"],
    "engines": ["native", "sigma-like", "behavioral"],
    "rule_ids": [
        "det.t1105.lolbin_download",
        "sigma_like.t1105.lolbin_download",
        "det.behavioral.t1105_download_sequence",
    ],
    "telemetry_event_ids": ["1", "3", "11"],
    "demo_case_count": 4,
    "true_positive_count": 4,
    "false_positive_count": 0,
    "false_negative_count": 0,
    "notes": ["Includes behavioral process/network/file sequence coverage."],
}
```

Best practice: derive ATT&CK technique metadata from local report/rule data, not from incoming demo events. This keeps the export explainable and avoids trusting event payload labels.

### Scoring

Use deterministic score rules:

- Score `1`: single engine coverage.
- Score `2`: native + Sigma-like coverage.
- Score `3`: multi-engine coverage including behavioral or ML.
- Score `4`: multi-engine coverage plus demo case evidence.
- Score `5`: multi-engine coverage plus behavioral coverage, demo case evidence, and response/protection evidence where applicable.

Recommended helper:

```python
def score_technique(*, engines: set[str], demo_case_count: int, has_response_or_protection: bool) -> int:
    if len(engines) <= 1:
        return 1
    if engines == {"native", "sigma-like"}:
        return 2
    if demo_case_count <= 0:
        return 3
    if has_response_or_protection and "behavioral" in engines:
        return 5
    return 4
```

Use this as a starting point, but keep behavior aligned with tests. For `T1059.001`, response/protection evidence can come from case matrix fields like `expected_response`, `response_count`, `expected_protection`, or protection-related final report capabilities. For other techniques, do not invent response/protection evidence if it is not present in local reports.

Trade-off: the score is a demo communication score, not a scientific ATT&CK coverage maturity model. Keep the docs explicit about that limitation.

### Coloring

Use fixed local colors. Do not depend on external services or ATT&CK Navigator APIs.

Suggested mapping:

- Score `1`: `#d8e2ef`
- Score `2`: `#9ecae1`
- Score `3`: `#6baed6`
- Score `4`: `#3182bd`
- Score `5`: `#08519c`

Keep the colors documented in `docs/attack_navigator_coverage.md` and in the generated `coverage_summary.md`.

### Metadata

Each technique metadata list should include these names when data is available:

- `engines`
- `rule_ids`
- `demo_case_count`
- `true_positive_count`
- `false_positive_count`
- `false_negative_count`
- `telemetry_event_ids`
- `notes`

Navigator metadata is commonly represented as a list of name/value objects. Use that shape unless existing project code already establishes another convention:

```json
{
  "metadata": [
    {"name": "engines", "value": "native, sigma-like, behavioral"},
    {"name": "rule_ids", "value": "det.t1105.lolbin_download, sigma_like.t1105.lolbin_download"},
    {"name": "telemetry_event_ids", "value": "1, 3, 11"}
  ]
}
```

### Comments

Technique comments should be human-readable and demo-friendly.

Examples:

- `T1059.001 covered by native, Sigma-like, and ML anomaly demo evidence using Sysmon Event ID 1 process telemetry.`
- `T1105 covered by native, Sigma-like, and behavioral detections using Sysmon Event ID 1/3/11 evidence.`
- `T1547.001 covered by native, Sigma-like, and behavioral detections using Sysmon Event ID 1/13 evidence.`
- `T1218 is constrained T1218-lite demo coverage for deterministic LOLBin execution and behavioral sequence evidence.`

Important: the `T1218` comment must explicitly mention `T1218-lite` or constrained demo coverage.

## CLI

Create `scripts/reporting/generate_attack_navigator_layer.py`.

Command:

```powershell
python scripts\reporting\generate_attack_navigator_layer.py
```

Options:

- `--coverage-report`, default `reports\detection_coverage_report.json`
- `--case-matrix`, default `reports\demo_cases\case_matrix.json`
- `--dashboard-data`, default `reports\demo_cases\dashboard_data.json`
- `--output`, default `reports\attack_navigator\edr_attack_layer.json`
- `--markdown-output`, default `reports\attack_navigator\coverage_summary.md`
- `--project-status`, default read from final demo report if available.
- `--output-summary`

Behavior:

- Create output directory if missing.
- Read coverage report.
- Read case matrix if available.
- Read dashboard data if available.
- Read final demo report project status if available.
- Build Navigator layer JSON.
- Write JSON with stable indentation and sorted keys where practical.
- Write Markdown summary.
- Print summary with:
  - technique count
  - engine count
  - rule count
  - output paths

Exit codes:

- `0`: success.
- `2`: predictable operational failure, such as missing coverage report, invalid JSON, or output write error.
- `3`: unexpected implementation failure.

## Markdown Summary

Generate `reports/attack_navigator/coverage_summary.md`.

It should include:

- Project status.
- Covered techniques table.
- Rule IDs by technique.
- Engines by technique.
- Telemetry Event IDs by technique.
- Demo case stats where available.
- Score and color legend.
- Artifact paths.
- Limitations:
  - Not full ATT&CK coverage.
  - Deterministic demo rules.
  - `T1218-lite` is constrained.
  - No production containment.
  - Kill-process is lab-only.
  - Navigator score is a communication score, not production detection maturity.

Keep Markdown deterministic enough for tests to assert exact sections and key phrases.

## Reports README

Create `reports/attack_navigator/README.md`.

Document:

- What files are generated in this directory.
- How to regenerate them.
- Which input reports are used.
- How to import `edr_attack_layer.json` manually into ATT&CK Navigator.
- That no internet is required for generation or tests.

The README can be short; detailed explanation belongs in `docs/attack_navigator_coverage.md`.

## Docs

Create `docs/attack_navigator_coverage.md`.

Cover:

- What ATT&CK Navigator export is in this project.
- How coverage report data becomes a Navigator layer.
- How to generate the layer.
- How to manually import the JSON into ATT&CK Navigator.
- What scores mean.
- What colors mean.
- How to explain the layer during the teacher demo.
- Safety notes.
- Limitations.

Suggested teacher demo narrative:

```text
This layer is not claiming full enterprise ATT&CK coverage. It visualizes the techniques this MVP validates locally: PowerShell execution, ingress transfer, registry persistence, and constrained LOLBin proxy execution. The score reflects how many local evidence sources support the technique: rule engines, behavioral correlation, demo cases, and lab-only response/protection evidence.
```

## Evidence Bundle Integration

Update `scripts/demo/build_demo_evidence_bundle.py` only if low-risk.

Include optional files:

- `reports/attack_navigator/edr_attack_layer.json`
- `reports/attack_navigator/coverage_summary.md`

Missing Navigator files must not break older evidence bundle behavior. They should appear in `missing_optional_files`, matching the current pattern for optional reports.

## Final Report Integration

Update `reporting/final_demo_report.py` only if low-risk.

Include capability:

- `attack_navigator_export`

Mention generated artifacts:

- `reports/attack_navigator/edr_attack_layer.json`
- `reports/attack_navigator/coverage_summary.md`

Do not make final report generation depend on Navigator artifacts unless they are generated as part of a clearly tested path. Prefer referencing the export capability and command.

## Tests

Create `tests/test_attack_navigator_layer.py`.

Tests must not require internet or live infrastructure.

Cover:

- Layer contains `enterprise-attack` domain.
- Layer contains `T1059.001`, `T1105`, `T1547.001`, and `T1218`.
- Technique entries contain `score`, `color`, `comment`, and `metadata`.
- Technique ordering is deterministic.
- `T1105` metadata includes `native`, `sigma-like`, and `behavioral` engines.
- `T1547.001` metadata includes `behavioral` engine.
- `T1218` comment mentions `T1218-lite` or constrained demo coverage.
- Score calculation is deterministic for single-engine, native+sigma, multi-engine, demo-backed, and response/protection-backed coverage.
- Markdown summary includes technique table and limitations.
- CLI writes JSON and Markdown outputs to a temp directory.
- CLI exits with `2` and clear output when the coverage report is missing.
- Optional case matrix and dashboard data absence does not fail the CLI.
- Evidence bundle includes Navigator files when present if integration is implemented.
- Final report references ATT&CK Navigator if integration is implemented.
- Tests do not require web, Elasticsearch, Kibana, Docker, Kafka, Sysmon, Windows, or Atomic Red Team execution.

Use small in-test dictionaries for core layer tests. Use temp files for CLI tests.

Example fixture shape:

```python
coverage_report = {
    "project_phase": "Phase 14 Behavioral Correlation Detection",
    "covered_techniques": [
        {
            "technique_id": "T1105",
            "technique_name": "Ingress Tool Transfer",
            "tactic": ["Command and Control"],
            "datasource": {"event_code": "1/3/11"},
            "engines": ["native", "sigma-like", "behavioral"],
        }
    ],
    "rule_inventory": [
        {
            "rule_id": "det.t1105.lolbin_download",
            "engine": "native",
            "attack": {"technique_id": "T1105"},
        }
    ],
}
```

## Commands

Focused tests:

```powershell
python -m pytest tests\test_attack_navigator_layer.py
```

Full regression:

```powershell
python -m pytest tests --basetemp=.pytest_tmp_phase15
```

Regenerate detection coverage report:

```powershell
python scripts\reporting\generate_detection_coverage_report.py
```

Regenerate final demo report:

```powershell
python scripts\reporting\generate_final_demo_report.py
```

Generate ATT&CK Navigator layer:

```powershell
python scripts\reporting\generate_attack_navigator_layer.py
```

Build evidence bundle:

```powershell
python scripts\demo\build_demo_evidence_bundle.py --output-dir reports\demo_evidence
```

## Acceptance Criteria

- [ ] `build_attack_navigator_layer()` returns a JSON-compatible dict with `domain = "enterprise-attack"`.
- [ ] Layer name is `EDR Advanced MVP Coverage`.
- [ ] Layer includes techniques `T1059.001`, `T1105`, `T1547.001`, and `T1218`.
- [ ] Each technique includes `techniqueID`, `score`, `color`, `comment`, and `metadata`.
- [ ] `T1105` metadata includes `native`, `sigma-like`, and `behavioral` engines.
- [ ] `T1547.001` metadata includes behavioral coverage.
- [ ] `T1218` comment clearly says `T1218-lite` or constrained demo coverage.
- [ ] Scores are deterministic and follow the documented score rules.
- [ ] Colors are fixed local values and documented.
- [ ] Metadata includes rule IDs, engines, telemetry Event IDs, and demo case counts when available.
- [ ] CLI creates `reports/attack_navigator/edr_attack_layer.json`.
- [ ] CLI creates `reports/attack_navigator/coverage_summary.md`.
- [ ] CLI creates output directories when missing.
- [ ] CLI prints technique count, engine count, rule count, and output paths when `--output-summary` is used.
- [ ] Missing required coverage report returns exit code `2` with a clear message.
- [ ] Missing optional case matrix/dashboard data does not fail generation.
- [ ] `docs/attack_navigator_coverage.md` explains generation, import, scores, colors, demo narrative, and limitations.
- [ ] `reports/attack_navigator/README.md` explains generated artifacts and regeneration command.
- [ ] Evidence bundle includes Navigator artifacts when present if integration is implemented.
- [ ] Final demo report references ATT&CK Navigator coverage export if integration is implemented.
- [ ] Existing detection rule semantics remain unchanged.
- [ ] Existing ML scoring remains unchanged.
- [ ] Existing behavioral correlation remains unchanged.
- [ ] Existing TP/TN/FP/FN case visibility remains unchanged.
- [ ] `python -m pytest tests\test_attack_navigator_layer.py` succeeds.
- [ ] `python -m pytest tests --basetemp=.pytest_tmp_phase15` succeeds.
- [ ] `python scripts\reporting\generate_detection_coverage_report.py` succeeds.
- [ ] `python scripts\reporting\generate_final_demo_report.py` succeeds.
- [ ] `python scripts\reporting\generate_attack_navigator_layer.py` succeeds.
- [ ] `python scripts\demo\build_demo_evidence_bundle.py --output-dir reports\demo_evidence` succeeds.

## Blocked by

None - can start immediately. Phase 13 multi-technique detection and Phase 14 behavioral correlation artifacts are already present in the repo.

## Out-of-scope boundaries

- Do not add new detection rules.
- Do not change existing rule semantics.
- Do not change ML anomaly scoring.
- Do not change behavioral correlation logic.
- Do not require internet.
- Do not call the live ATT&CK Navigator website in tests.
- Do not require Elasticsearch, Kibana, Docker, Kafka, Windows, Sysmon, or Atomic Red Team execution.
- Do not hide FP/FN cases.
- Do not claim full ATT&CK enterprise coverage.
- Do not claim production containment.

## Implementation Notes

Keep the implementation small and reporting-focused.

Good flow:

```text
detection_coverage_report.json
  + optional case_matrix.json
  + optional dashboard_data.json
  -> build_attack_navigator_layer()
  -> edr_attack_layer.json
  -> coverage_summary.md
```

Avoid broad dependencies. The Python standard library is enough for CLI parsing, JSON I/O, path handling, and deterministic rendering.

## Comments
