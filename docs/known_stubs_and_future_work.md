# Known Stubs And Future Work

This document separates current MVP claims from future-work placeholders. The repository is submission-ready for the implemented Phase 1 through Phase 10 plus Phase 12, Phase 13, Phase 14, and Phase 15 MVP slices, but several modules and workflows intentionally remain stubs.

## Behavioral Stubs

Current state:

- Phase 14 implements deterministic local behavioral sequence correlation for `T1105`, `T1547.001`, and `T1218-lite`.
- Phase 15 implements local ATT&CK Navigator coverage export for demo visualization.
- Broader behavioral or scenario-oriented modules beyond those documented sequences remain roadmap placeholders.

Not an MVP claim:

- The MVP does not claim broad behavior analytics, full user/entity behavior analytics, graph database backed endpoint analytics, streaming state, or production-grade adversary behavior modeling.

Future work:

- Add endpoint graph modeling, long-lived streaming correlation state, richer entity resolution, case creation workflows, and production-scale behavior analytics.

## ML Model Stubs

Current state:

- Phase 6 implements deterministic ML-style process anomaly scoring.
- The score is heuristic and testable without heavy ML frameworks.

Not an MVP claim:

- The MVP does not claim trained production ML, model serving, model drift detection, or online learning.

Future work:

- Add a real training dataset, feature store, model artifact versioning, offline evaluation, drift monitoring, and rollback strategy.

## Sigma Compiler Stub

Current state:

- The repo contains a deterministic Sigma-like detection MVP for the current PowerShell-focused path.
- It does not implement broad Sigma parsing or full backend query compilation.

Not an MVP claim:

- The MVP does not claim broad Sigma rule compatibility.

Future work:

- Add parser coverage, field mapping, backend query generation, validation errors, compatibility fixtures, and regression tests for supported Sigma features.

## Threat Intel Stubs

Current state:

- Threat-intel-oriented names or placeholders may exist for future enrichment work.
- Current deterministic detections do not require external threat intelligence.

Not an MVP claim:

- The MVP does not claim live indicator feeds, reputation scoring, STIX/TAXII ingestion, or enrichment pipelines.

Future work:

- Add source adapters, indicator schemas, TTL handling, confidence scoring, enrichment joins, and tests that do not depend on live third-party services.

## Containment Legacy Stubs

Current state:

- Earlier roadmap or legacy containment placeholders may exist.
- Phase 5 SOAR remains dry-run response planning.
- Phase 10 adds only a guarded lab-only kill-process protection action, dry-run by default.

Not an MVP claim:

- The MVP does not claim production containment, host isolation, network blocking, or endpoint quarantine.

Future work:

- Add endpoint identity, process entity IDs, approval workflows, policy allow/deny lists, rollback handling, production safety controls, and audit review.

## Detection Validator Placeholder

Current state:

- Detection validation is covered by deterministic tests, coverage reports, and the Phase 9 10-case TP/TN/FP/FN matrix.
- Any broader detection validator placeholder should be treated as future work.

Not an MVP claim:

- The MVP does not claim a complete detection validation platform or production rule-quality gate.

Future work:

- Add rule metadata validation, fixture coverage requirements, ATT&CK mapping checks, regression baselines, and CI gating once the validator has a real contract.

## Placeholder CI Workflows

Current state:

- `.github/workflows/ci.yml` is the real deterministic CI workflow.
- `detection-ci.yml` and `rule-deploy.yml`, if present, are manual-only future-work placeholders.

Not an MVP claim:

- The MVP does not claim production detection CI, production rule deployment, or automated release of detection content.

Future work:

- Add signed rule bundles, environment approvals, rule validation gates, staged deployment targets, rollback, and production audit logs.
