# Final Submission Checklist

Use this checklist before the final teacher demo and repository submission.

## Deterministic Verification

- [ ] Tests pass with `python -m pytest tests --basetemp=.pytest_tmp_demo`.
- [ ] Focused Phase 16 test passes with `python -m pytest tests\test_final_teacher_demo_package.py`.
- [ ] Detection coverage reports regenerated.
- [ ] Final demo reports regenerated.
- [ ] Case matrix regenerated.
- [ ] Dashboard data regenerated.
- [ ] ATT&CK Navigator layer generated.
- [ ] Evidence bundle generated.

## Artifact Review

- [ ] `README.md` reviewed.
- [ ] `docs/architecture.md` reviewed.
- [ ] `reports/final_demo_report.md` reviewed.
- [ ] `reports/detection_coverage_report.md` reviewed.
- [ ] `reports/demo_cases/case_matrix.md` reviewed.
- [ ] `reports/attack_navigator/coverage_summary.md` reviewed.
- [ ] `reports/demo_evidence/manifest.json` reviewed.

## Screenshots And Live Evidence

- [ ] Screenshots captured for final report and case matrix.
- [ ] ATT&CK Navigator screenshot captured after importing `reports/attack_navigator/edr_attack_layer.json`.
- [ ] Kibana screenshots captured if Elasticsearch/Kibana is used.
- [ ] VM XML sample exported if doing a live Windows VM / Atomic Red Team demo.
- [ ] Optional protection execution screenshot captured only if isolated lab execution is explicitly intended.

## Safety Check

- [ ] Protection remains dry-run unless isolated lab execution is explicitly intended.
- [ ] No Atomic Red Team activity is run on production endpoints.
- [ ] No production containment is claimed.
- [ ] FP/FN cases remain visible in the demo evidence.

## Git Submission

- [ ] Final changes reviewed with `git status`.
- [ ] Git commit created.
- [ ] Git tag created for submission.
