Status: done

# Final teacher demo rehearsal and submission pack

## Goal

Create the final teacher demo rehearsal and submission package for the completed EDR Advanced project.

This phase is documentation and demo packaging only. It should make the already-completed project easier to rehearse, present, verify, and submit without changing any detection or response behavior.

## Context

Current project capabilities:

- Sysmon Event ID `1`, `3`, `11`, and `13` normalization.
- Native and Sigma-like detections for `T1059.001`, `T1105`, `T1547.001`, and constrained `T1218-lite`.
- ML anomaly detection.
- Behavioral correlation detection.
- SOAR dry-run response.
- Lab-only kill-process protection.
- ATT&CK Navigator coverage export.
- Final demo report.
- Demo case matrix with TP/TN/FP/FN transparency.
- Dashboard data.
- Evidence bundle.

Current verification snapshot:

- Full regression: `375 passed`.
- Detection coverage has `11` rules.
- ATT&CK Navigator layer has `4` covered techniques.
- Demo case matrix has `TP=12`, `TN=6`, `FP=1`, and `FN=1`.
- Evidence bundle includes Navigator artifacts and has `Missing optional files: 0`.

The project domain calls the end-to-end path:

```text
collection -> normalization -> detection -> correlation -> response -> reporting
```

This issue packages that path into a final teacher-facing rehearsal and submission flow. It must preserve the existing truthfulness boundary: this is a deterministic local demo project, not a production EDR or a claim of full ATT&CK coverage.

## Problem

The repo now has the required technical pieces for the final EDR Advanced demo, but the final presentation still needs a teacher-friendly package:

- A timed rehearsal guide with exact commands and expected outputs.
- A talk track that explains the architecture and evidence clearly.
- A submission checklist that reduces last-minute mistakes.
- Evidence checklist updates so the generated bundle is easy to audit.
- Lightweight tests that keep the final package present and honest.

Without this package, the demo depends too much on memory and scattered docs. The goal is to make the final review repeatable in 7 to 10 minutes, with safe fallbacks if live lab dependencies are unavailable.

## What to build

Create:

- `docs/final_teacher_demo_rehearsal.md`
- `docs/final_teacher_demo_talk_track.md`
- `docs/final_submission_checklist.md`
- `tests/test_final_teacher_demo_package.py`

Update if low-risk:

- `README.md` final demo section.
- `reports/demo_evidence/demo_evidence_checklist.md`.

Do not add new detection rules, alter scoring, or change runtime behavior.

## Technical Design

### Rehearsal Guide

Create `docs/final_teacher_demo_rehearsal.md`.

The guide should be written as an operator checklist for a 7 to 10 minute teacher demo. It should include:

- Demo prerequisites.
- Exact command order.
- Expected outputs.
- Kibana screens to show.
- ATT&CK Navigator import/show step.
- Fallback plan if Elasticsearch/Kibana is unavailable.
- Fallback plan if Windows VM/Atomic Red Team is unavailable.
- Safety notes for lab-only protection.
- Timing target: `7 to 10 minutes`.

Core deterministic command sequence:

```powershell
python -m pytest tests --basetemp=.pytest_tmp_demo
python scripts\reporting\generate_detection_coverage_report.py
python scripts\reporting\generate_final_demo_report.py
python scripts\demo\run_demo_case_matrix.py --output reports\demo_cases\case_matrix.json
python scripts\demo\generate_demo_dashboard_data.py --case-matrix reports\demo_cases\case_matrix.json --output reports\demo_cases\dashboard_data.json
python scripts\reporting\generate_attack_navigator_layer.py
python scripts\demo\build_demo_evidence_bundle.py --output-dir reports\demo_evidence
```

Optional live Elasticsearch/Kibana commands should be documented separately from the deterministic core:

- Run Sysmon XML validation with `--write-events --write-alerts --write-response`.
- Run protection dry-run.
- Optionally run lab-only kill-process in an isolated VM.

Best practice: keep the deterministic core first, then treat live infrastructure as optional evidence enhancement. This keeps the final demo robust if Docker, Elasticsearch, Kibana, or the Windows VM is unavailable.

Trade-off: the rehearsal guide may repeat commands already present in README and phase docs. That duplication is acceptable because this file is the final demo runbook.

### Talk Track

Create `docs/final_teacher_demo_talk_track.md`.

Write what to say during the demo. Keep it direct and teacher-facing, with short sections that map to the order of screens and artifacts shown.

Required sections:

- Opening: project goal.
- Architecture: collection to reporting.
- Telemetry: Sysmon Event ID `1`, `3`, `11`, and `13`.
- Detection engines:
  - Native.
  - Sigma-like.
  - ML anomaly.
  - Behavioral correlation.
- ATT&CK coverage:
  - `T1059.001`.
  - `T1105`.
  - `T1547.001`.
  - `T1218-lite`.
- Case matrix:
  - TP/TN/FP/FN explanation.
  - Explicitly do not hide FP/FN.
- Response:
  - SOAR dry-run.
  - Protection lab-only kill-process.
- Dashboard/evidence:
  - Kibana.
  - Navigator layer.
  - Evidence bundle.
- Limitations and future work:
  - Not full ATT&CK coverage.
  - Deterministic demo rules.
  - `T1218-lite` is constrained.
  - No production containment.
  - No real credential dumping or malware payloads.

Suggested narrative boundary:

```text
This project demonstrates a local EDR learning pipeline with deterministic evidence. It validates selected ATT&CK techniques with normalized Sysmon telemetry, rule-based detections, ML-style anomaly scoring, behavioral correlation, dry-run response planning, and lab-only protection evidence. It does not claim production containment or full ATT&CK coverage.
```

### Submission Checklist

Create `docs/final_submission_checklist.md`.

The checklist must include:

- Tests pass.
- Reports regenerated.
- Case matrix regenerated.
- Dashboard data regenerated.
- Navigator layer generated.
- Evidence bundle generated.
- README/architecture reviewed.
- Screenshots captured.
- VM XML sample exported if doing live demo.
- Protection only dry-run unless isolated lab execution is explicitly intended.
- Git commit/tag created.

Keep the checklist concrete and easy to scan before submission.

### Evidence Checklist Update

Update `reports/demo_evidence/demo_evidence_checklist.md` if low-risk.

Include these artifacts:

- `final_demo_report.md` / `final_demo_report.json`.
- `detection_coverage_report.md` / `detection_coverage_report.json`.
- `case_matrix.md` / `case_matrix.json`.
- `dashboard_data.json`.
- `attack_navigator/edr_attack_layer.json`.
- `attack_navigator/coverage_summary.md`.
- Kibana screenshots.
- Optional VM Sysmon exported XML.
- Optional protection execution screenshot.

Missing optional screenshots or VM artifacts should not imply the deterministic demo failed. The checklist should distinguish generated local artifacts from manual live-lab evidence.

### README Update

Update `README.md` only if low-risk.

If updated, the final demo section should mention Phase 15/16 and point to:

- `docs/final_teacher_demo_rehearsal.md`
- `docs/final_teacher_demo_talk_track.md`
- `docs/final_submission_checklist.md`

Do not turn the README into a second copy of the rehearsal guide.

## Tests

Create `tests/test_final_teacher_demo_package.py`.

Tests must read docs/files only. They must not require:

- Elasticsearch.
- Kibana.
- Docker.
- Kafka.
- Windows.
- Sysmon service.
- Atomic Red Team.
- Live protection execution.
- Internet access.

Cover:

- Rehearsal doc exists and mentions `7 to 10 minutes`.
- Rehearsal doc includes the exact core commands.
- Rehearsal doc mentions Kibana and ATT&CK Navigator.
- Rehearsal doc mentions fallback plans.
- Talk track exists and mentions TP/TN/FP/FN.
- Talk track mentions behavioral correlation.
- Talk track mentions lab-only protection.
- Submission checklist exists and mentions tests, reports, Navigator layer, evidence bundle, screenshots, and git tag.
- Evidence checklist mentions Navigator artifacts if updated.
- README final demo section mentions Phase 15/16 only if updated.

Suggested helper pattern:

```python
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_rehearsal_includes_core_commands() -> None:
    doc = read("docs/final_teacher_demo_rehearsal.md")

    assert "python -m pytest tests --basetemp=.pytest_tmp_demo" in doc
    assert "python scripts\\reporting\\generate_detection_coverage_report.py" in doc
    assert "python scripts\\reporting\\generate_final_demo_report.py" in doc
    assert "python scripts\\demo\\run_demo_case_matrix.py --output reports\\demo_cases\\case_matrix.json" in doc
    assert "python scripts\\demo\\generate_demo_dashboard_data.py --case-matrix reports\\demo_cases\\case_matrix.json --output reports\\demo_cases\\dashboard_data.json" in doc
    assert "python scripts\\reporting\\generate_attack_navigator_layer.py" in doc
    assert "python scripts\\demo\\build_demo_evidence_bundle.py --output-dir reports\\demo_evidence" in doc
```

Keep assertions resilient to prose changes, but strict for exact commands and safety boundaries.

## Commands

Focused package test:

```powershell
python -m pytest tests\test_final_teacher_demo_package.py
```

Full regression:

```powershell
python -m pytest tests --basetemp=.pytest_tmp_phase16
```

Final demo rehearsal commands:

```powershell
python -m pytest tests --basetemp=.pytest_tmp_demo
python scripts\reporting\generate_detection_coverage_report.py
python scripts\reporting\generate_final_demo_report.py
python scripts\demo\run_demo_case_matrix.py --output reports\demo_cases\case_matrix.json
python scripts\demo\generate_demo_dashboard_data.py --case-matrix reports\demo_cases\case_matrix.json --output reports\demo_cases\dashboard_data.json
python scripts\reporting\generate_attack_navigator_layer.py
python scripts\demo\build_demo_evidence_bundle.py --output-dir reports\demo_evidence
```

## Acceptance Criteria

- [ ] `docs/final_teacher_demo_rehearsal.md` exists.
- [ ] Rehearsal guide states the timing target is `7 to 10 minutes`.
- [ ] Rehearsal guide includes prerequisites, exact command order, expected outputs, Kibana screens, ATT&CK Navigator step, fallback plans, and lab-only protection safety notes.
- [ ] Rehearsal guide includes the exact deterministic core command sequence.
- [ ] Rehearsal guide separates optional live Elasticsearch/Kibana and Windows VM/Atomic Red Team steps from the deterministic core.
- [ ] `docs/final_teacher_demo_talk_track.md` exists.
- [ ] Talk track explains project goal, architecture, telemetry, detection engines, ATT&CK coverage, case matrix, response, dashboard/evidence, limitations, and future work.
- [ ] Talk track explicitly mentions native, Sigma-like, ML anomaly, and behavioral correlation detection.
- [ ] Talk track explicitly mentions `T1059.001`, `T1105`, `T1547.001`, and `T1218-lite`.
- [ ] Talk track explains TP/TN/FP/FN and does not hide FP/FN.
- [ ] Talk track describes SOAR dry-run and lab-only kill-process protection.
- [ ] Talk track states the project does not claim full ATT&CK coverage or production containment.
- [ ] `docs/final_submission_checklist.md` exists.
- [ ] Submission checklist includes tests, regenerated reports, regenerated case matrix, regenerated dashboard data, Navigator layer, evidence bundle, README/architecture review, screenshots, optional VM XML sample, protection safety, and git commit/tag.
- [ ] `reports/demo_evidence/demo_evidence_checklist.md` mentions final reports, detection coverage reports, case matrix, dashboard data, Navigator artifacts, Kibana screenshots, optional VM Sysmon XML, and optional protection screenshot if updated.
- [ ] `README.md` links the Phase 16 final teacher demo package docs if updated.
- [ ] `tests/test_final_teacher_demo_package.py` exists and only reads local docs/files.
- [ ] `python -m pytest tests\test_final_teacher_demo_package.py` succeeds.
- [ ] `python -m pytest tests --basetemp=.pytest_tmp_phase16` succeeds.
- [ ] No new detection rules are added.
- [ ] Existing detection semantics remain unchanged.
- [ ] Existing ML scoring remains unchanged.
- [ ] Existing behavioral correlation remains unchanged.
- [ ] Existing SOAR behavior remains unchanged.
- [ ] Existing protection behavior remains unchanged.
- [ ] Tests do not require live infrastructure.

## Blocked by

- `.scratch/phase-15-attack-navigator-export/issues/01-attack-navigator-coverage-export-and-demo-pack.md`
- `.scratch/final-consistency/issues/01-final-repo-consistency-and-submission-cleanup.md`

These blockers are already marked `Status: done`, so this issue can start immediately.

## Out-of-scope boundaries

- Do not add new detection rules.
- Do not change existing rule semantics.
- Do not change ML scoring.
- Do not change behavioral correlation.
- Do not change SOAR dry-run behavior.
- Do not change protection behavior.
- Do not require live infrastructure.
- Do not require Elasticsearch, Kibana, Docker, Kafka, Windows, Sysmon, or Atomic Red Team for tests.
- Do not claim full ATT&CK coverage.
- Do not claim production containment.
- Do not hide false positives.
- Do not hide false negatives.
- Do not introduce real credential dumping, malware payloads, or destructive actions.

## Implementation Notes

Keep this issue small and documentation-focused.

Recommended implementation flow:

```text
final_teacher_demo_rehearsal.md
  -> final_teacher_demo_talk_track.md
  -> final_submission_checklist.md
  -> evidence checklist update
  -> optional README links
  -> doc-only pytest coverage
```

Use stable phrases for tests, but avoid asserting large full paragraphs. The point is to keep the final package present, runnable, and honest.

## Comments
