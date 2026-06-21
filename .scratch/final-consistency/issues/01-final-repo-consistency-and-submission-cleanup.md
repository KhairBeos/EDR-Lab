Status: done

# Final repository consistency and submission cleanup

## Goal

Make the repository internally consistent and submission-ready after Phase 1 through Phase 10 implementation.

This is a cleanup, documentation, and test-stability issue. Do not add new detection semantics.

## Context

The project has implemented Phase 1 through Phase 10:

- Phase 1: Foundation
- Phase 2: Native detection
- Phase 3: Live telemetry, Sigma-like detection, and coverage
- Phase 4: Kafka
- Phase 5: SOAR dry-run
- Phase 6: ML anomaly
- Phase 7: Final report
- Phase 8: Atomic Red Team / Sysmon VM demo
- Phase 9: 10-case TP/TN/FP/FN matrix
- Phase 10: Lab-only kill-process protection

Current repository gaps:

- `README.md` and architecture docs do not fully reflect Phase 9 and Phase 10.
- Some `.scratch` issues still say `Status: ready-for-agent` or `Status: design-only` even though implementation is complete.
- `pytest` on Windows can emit `PermissionError` cleanup warnings around temp symlink / `tmp_path` cleanup.
- Some old roadmap or stub modules may look like implemented features.
- Placeholder CI workflows, especially `detection-ci.yml` and `rule-deploy.yml`, may confuse readers into thinking they are production workflows.

## What to build

Perform a final consistency pass across docs, issue statuses, CI placeholder messaging, and deterministic documentation tests:

```text
README / architecture / final demo docs
  -> Phase 1-10 consistency
  -> Phase 9 case matrix and TP/TN/FP/FN visibility
  -> Phase 10 lab-only protection visibility
  -> known stubs clearly marked as future work
  -> placeholder workflows made non-misleading
  -> Windows pytest temp cleanup guidance
  -> consistency tests
```

Keep the implementation focused on repository truthfulness and submission readiness. The completed MVP must be easier to review without claiming future-work capabilities as current features.

## Required files

Update:

- `README.md`
- `docs/architecture.md`
- `docs/final_demo_script.md`
- `docs/final_demo_report_mvp.md`
- `docs/demo_dashboard_design.md`
- `docs/protection_action_mvp.md`
- `pytest.ini` or equivalent test config
- `.scratch/**/*.md` statuses
- `.github/workflows/detection-ci.yml`
- `.github/workflows/rule-deploy.yml`

Create or update:

- `docs/known_stubs_and_future_work.md`
- `tests/test_final_repo_consistency.py`

Optional only if the repo already uses this name:

- `docs/roadmap_or_stubs.md`

Prefer `docs/known_stubs_and_future_work.md` as the canonical file if both names are absent.

## README requirements

Update `README.md` so it clearly reflects the completed MVP state.

README must list Phase 1 through Phase 10:

- Phase 1: Foundation
- Phase 2: Native detection
- Phase 3: Live telemetry, Sigma-like detection, and coverage
- Phase 4: Kafka
- Phase 5: SOAR dry-run
- Phase 6: ML anomaly
- Phase 7: Final report
- Phase 8: ART / Sysmon VM demo
- Phase 9: 10-case TP/TN/FP/FN demo case matrix
- Phase 10: Lab-only kill-process protection action

README capability matrix must include:

- Demo case matrix
- TP/TN/FP/FN classification
- Lab-only protection action
- `edr-protection-actions-*` index

Replace outdated wording such as:

```text
no process kill
```

with wording that is accurate after Phase 10:

```text
no production containment
lab-only kill-process requires explicit flags
```

README should keep the safety boundary prominent:

- SOAR remains dry-run response planning.
- Kill-process is lab-only, safe-by-default, and requires explicit execution flags.
- No production containment or host isolation is implemented.

## Architecture requirements

Update `docs/architecture.md`.

Architecture diagram must include:

- Protection action path
- `edr-protection-actions-*`
- Dashboard / reporting
- Safety note: kill-process is lab-only and safe-by-default

The architecture should show the post-Phase-10 flow:

```text
Sysmon XML / fixture
  -> normalization
  -> native / Sigma-like / ML anomaly detection
  -> alerts
  -> SOAR dry-run response planning
  -> lab-only protection action path
  -> protection action records
  -> dashboard/reporting
```

Include index names where relevant:

- `edr-normalized-events-*`
- `edr-alerts-native-*`
- `edr-response-actions-*`
- `edr-protection-actions-*`

Use clear wording:

```text
No production containment is implemented.
The kill-process protection action is lab-only, dry-run by default, and requires explicit flags for execution.
```

## Final demo and dashboard docs

Update these docs so they match the current completed MVP:

- `docs/final_demo_script.md`
- `docs/final_demo_report_mvp.md`
- `docs/demo_dashboard_design.md`
- `docs/protection_action_mvp.md`

The docs should reference:

- Phase 9 case matrix
- 10 demo cases
- TP/TN/FP/FN classification
- Dashboard/reporting evidence
- Phase 10 protection records
- `edr-protection-actions-*`
- Lab-only kill-process safety flags

Do not hide false positives or false negatives. The final report and dashboard docs should continue to treat FP/FN cases as explicit evidence for evaluation, not as failures to omit.

## Known stubs and future work

Create or update `docs/known_stubs_and_future_work.md`.

This document must clearly mark the following as future work, not current MVP claims:

- Behavioral stubs
- ML model stubs
- Sigma compiler stub
- Threat intel stubs
- Containment legacy stubs
- Detection validator placeholder
- Placeholder CI workflows

For each category, include:

- What exists today.
- Why it is not a current MVP claim.
- What a future production implementation would need.

Example shape:

```markdown
## Sigma Compiler Stub

Current state:
- The repo contains a deterministic Sigma-like MVP path, but not a full Sigma compiler.

Not an MVP claim:
- The current MVP does not claim broad Sigma rule compatibility.

Future work:
- Add parser coverage, field mapping, validation, and fixture-backed compatibility tests.
```

Keep this as documentation only. Do not implement the stubbed features in this issue.

## Scratch issue status cleanup

Update `.scratch/**/*.md` status lines where implementation is already complete.

Change completed implementation issue status lines from `ready-for-agent` or `design-only` to:

```text
Status: done
```

Only update issues that correspond to completed implementation work. Do not mark future planning docs, PRDs, or incomplete items as done unless the repository evidence shows they are complete.

The new consistency test should ensure completed implementation issue files no longer contain stale `ready-for-agent` status text for the completed Phase 1-10 work.

## Pytest Windows temp cleanup stability

Add pytest config or docs so Windows runs avoid temp cleanup warnings around symlink / `tmp_path`.

Preferred implementation:

- Set `basetemp = .pytest_tmp` in `pytest.ini` if supported by the existing pytest version and repo conventions.

Fallback implementation:

- Document the Windows command:

```powershell
python -m pytest tests --basetemp=.pytest_tmp
```

The test should accept either:

- A pytest config that sets or references `.pytest_tmp`.
- Documentation that clearly mentions `--basetemp=.pytest_tmp`.

Do not add tests that depend on platform-specific symlink behavior.

## Placeholder workflow cleanup

Update:

- `.github/workflows/detection-ci.yml`
- `.github/workflows/rule-deploy.yml`

Choose one of these approaches:

1. Remove the placeholder workflows if they are not useful.
2. Keep them as manual-only placeholders using `workflow_dispatch`.

If kept, they must:

- Not run on `push` or `pull_request`.
- Clearly echo that they are future-work placeholders.
- Point readers to `.github/workflows/ci.yml` as the real deterministic CI.
- Avoid implying production detection CI or production rule deployment exists.

`ci.yml` remains the real deterministic CI workflow.

## Tests

Create `tests/test_final_repo_consistency.py`.

The tests should read docs/workflow/issue files only. They must not require Docker, Kafka, Elasticsearch, Kibana, Windows, Sysmon, Atomic Red Team, or live protection execution.

Cover:

- `README.md` references Phase 9 and Phase 10.
- `README.md` references `edr-protection-actions-*`.
- `README.md` capability wording includes demo case matrix and TP/TN/FP/FN classification.
- `docs/architecture.md` references lab-only protection.
- `docs/architecture.md` references `edr-protection-actions-*`.
- `docs/known_stubs_and_future_work.md` exists.
- `docs/known_stubs_and_future_work.md` identifies the required stub categories as future work.
- Placeholder workflows are not misleading:
  - Removed workflows are acceptable.
  - Existing placeholder workflows must be manual-only via `workflow_dispatch`.
  - Existing placeholder workflows must clearly say future-work / placeholder.
  - Existing placeholder workflows must not include `push` or `pull_request` triggers.
- Pytest config or docs mention `.pytest_tmp` / `--basetemp=.pytest_tmp`.
- Scratch statuses no longer contain `Status: ready-for-agent` for completed implementation issues.

Example helper pattern:

```python
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_readme_references_phase_9_and_phase_10() -> None:
    readme = read("README.md").lower()

    assert "phase 9" in readme
    assert "phase 10" in readme
    assert "tp/tn/fp/fn" in readme
    assert "edr-protection-actions-*" in readme
```

Keep tests resilient to small prose changes by checking stable phrases and file existence, not full paragraphs.

## Commands to run

Focused consistency test:

```powershell
python -m pytest tests\test_final_repo_consistency.py
```

Full deterministic test suite with stable temp directory:

```powershell
python -m pytest tests --basetemp=.pytest_tmp
```

Final report generation:

```powershell
python scripts\reporting\generate_final_demo_report.py
```

Phase 9 demo case matrix:

```powershell
python scripts\demo\run_demo_case_matrix.py --output reports\demo_cases\case_matrix.json
```

Dashboard data generation:

```powershell
python scripts\demo\generate_demo_dashboard_data.py --case-matrix reports\demo_cases\case_matrix.json --output reports\demo_cases\dashboard_data.json
```

## Acceptance criteria

- [ ] `README.md` lists Phase 1 through Phase 10.
- [ ] `README.md` capability matrix includes demo case matrix, TP/TN/FP/FN classification, lab-only protection action, and `edr-protection-actions-*`.
- [ ] Outdated `no process kill` wording is replaced with `no production containment` and lab-only explicit-flag wording.
- [ ] `docs/architecture.md` includes protection action path, `edr-protection-actions-*`, dashboard/reporting, and lab-only safe-by-default kill-process note.
- [ ] Final demo/dashboard/protection docs reflect Phase 9 and Phase 10 without hiding FP/FN cases.
- [ ] `docs/known_stubs_and_future_work.md` exists and clearly marks required stub categories as future work, not current MVP claims.
- [ ] Completed `.scratch` implementation issues have `Status: done` instead of stale `ready-for-agent` or `design-only`.
- [ ] Pytest config or docs support `--basetemp=.pytest_tmp` for Windows cleanup stability.
- [ ] Placeholder workflows are removed or converted to manual `workflow_dispatch` placeholders with clear future-work messaging.
- [ ] `.github/workflows/ci.yml` remains the real deterministic CI.
- [ ] `tests/test_final_repo_consistency.py` covers README, architecture, known stubs, placeholder workflows, pytest temp guidance, and scratch statuses.
- [ ] `python -m pytest tests\test_final_repo_consistency.py` passes.
- [ ] `python -m pytest tests --basetemp=.pytest_tmp` passes.
- [ ] `python scripts\reporting\generate_final_demo_report.py` succeeds.
- [ ] `python scripts\demo\run_demo_case_matrix.py --output reports\demo_cases\case_matrix.json` succeeds.
- [ ] `python scripts\demo\generate_demo_dashboard_data.py --case-matrix reports\demo_cases\case_matrix.json --output reports\demo_cases\dashboard_data.json` succeeds.
- [ ] No detection semantics, Sysmon event IDs, ML scoring, SOAR behavior, or protection behavior are changed.

## Blocked by

- `.scratch/final-polish/issues/01-readme-cicd-vm-lab-demo-polish.md`
- `.scratch/phase-8-vm-art-attack-demo-validation/issues/01-atomic-red-team-sysmon-dashboard-demo.md`
- `.scratch/phase-9-demo-case-dashboard-mvp/issues/01-multi-attack-case-dashboard-validation.md`
- `.scratch/phase-10-protection-action-mvp/issues/01-lab-only-kill-process-protection-action.md`

## Out-of-scope boundaries

- Do not add new detection rules.
- Do not add new Sysmon event IDs.
- Do not change detection semantics.
- Do not change ML scoring.
- Do not change SOAR behavior.
- Do not change protection behavior.
- Do not add production containment.
- Do not add host isolation.
- Do not add network blocking.
- Do not add broad Sigma compiler support.
- Do not hide false positives.
- Do not hide false negatives.
- Do not require Docker, Kafka, Elasticsearch, Kibana, Sysmon, Atomic Red Team, or Windows VM in tests.

## Implementation notes

- Treat this as a truthfulness pass: the docs should make the completed MVP easy to understand and the future-work boundaries hard to misread.
- Prefer small doc edits over broad rewrites.
- Keep consistency tests deterministic and text-based.
- If changing `.scratch` statuses mechanically, inspect the changed file list before finishing to ensure only completed implementation issues were marked done.

## Comments
