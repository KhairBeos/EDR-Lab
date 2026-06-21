# ATT&CK Navigator Coverage Export

This phase exports the local EDR coverage matrix as a MITRE ATT&CK Navigator layer.

The export is reporting and visualization only. It does not add detection rules, change ML scoring, change behavioral correlation, or require live infrastructure.

## What It Shows

The layer visualizes the techniques this MVP validates locally:

- `T1059.001` PowerShell execution.
- `T1105` ingress transfer using process, network, and file evidence.
- `T1547.001` registry Run key persistence.
- `T1218` constrained `T1218-lite` LOLBin proxy execution.

It combines local report data from:

- `reports/detection_coverage_report.json`
- `reports/demo_cases/case_matrix.json` when present
- `reports/demo_cases/dashboard_data.json` when present
- `reports/final_demo_report.json` when present

No internet, Elasticsearch, Kibana, Docker, Kafka, Windows VM, Sysmon service, or Atomic Red Team execution is required to generate or test the layer.

## Generate The Layer

```powershell
python scripts\reporting\generate_attack_navigator_layer.py
```

Generated artifacts:

- `reports/attack_navigator/edr_attack_layer.json`
- `reports/attack_navigator/coverage_summary.md`

The command reads `reports/detection_coverage_report.json` as the required source. Optional case matrix and dashboard data enrich demo case counts, ML anomaly evidence, and behavioral sequence notes.

## Manual Import

To inspect the layer in ATT&CK Navigator:

1. Open ATT&CK Navigator in a browser.
2. Choose the import/open layer option.
3. Select `reports/attack_navigator/edr_attack_layer.json`.
4. Review the highlighted Enterprise ATT&CK techniques and their comments.

Tests do not call the live Navigator website.

## Score Meaning

The score is a demo communication score, not a scientific production maturity score.

| Score | Meaning |
| --- | --- |
| 1 | Single engine coverage |
| 2 | Native plus Sigma-like coverage |
| 3 | Multi-engine coverage including behavioral or ML evidence |
| 4 | Multi-engine coverage plus demo case evidence |
| 5 | Multi-engine, behavioral, demo case, and response/protection evidence |

## Color Meaning

| Score | Color |
| --- | --- |
| 1 | `#d8e2ef` |
| 2 | `#9ecae1` |
| 3 | `#6baed6` |
| 4 | `#3182bd` |
| 5 | `#08519c` |

Colors are fixed local values and do not depend on external services.

## Teacher Demo Narrative

This layer is not claiming full enterprise ATT&CK coverage. It visualizes the techniques this MVP validates locally: PowerShell execution, ingress transfer, registry persistence, and constrained LOLBin proxy execution. The score reflects how many local evidence sources support the technique: rule engines, behavioral correlation, demo cases, and lab-only response/protection evidence.

Use the technique comments to explain what each colored cell means:

- `T1059.001` shows process telemetry, native/Sigma-like detection, ML-style demo evidence, and lab-only response/protection evidence where present.
- `T1105` shows process, network, and file evidence plus behavioral correlation.
- `T1547.001` shows process and registry evidence plus behavioral correlation.
- `T1218` is explicitly `T1218-lite`: deterministic LOLBin demo coverage, not complete LOLBin analytics.

## Safety Notes

- Do not run Atomic Red Team on production endpoints.
- Do not treat this layer as production ATT&CK coverage certification.
- SOAR remains dry-run response planning.
- Kill-process is lab-only and requires explicit execution flags.
- No production containment, host isolation, or network blocking is implemented.

## Limitations

- Not full ATT&CK coverage.
- Deterministic demo rules, not broad production detections.
- `T1218-lite` is constrained.
- No production containment.
- Kill-process is lab-only.
- Navigator score is a communication score, not production detection maturity.
