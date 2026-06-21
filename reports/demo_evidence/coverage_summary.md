# ATT&CK Navigator Coverage Summary

Project status: Phase 15 ATT&CK Navigator export ready
Layer name: EDR Advanced MVP Coverage
Domain: enterprise-attack

## Covered Techniques

| Technique | Name | Tactic | Score | Color | Engines | Rule IDs | Event IDs | Demo Cases | TP | FP | FN |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| T1059.001 | PowerShell | Execution | 4 | #3182bd | native, Sigma-like, ML anomaly | det.t1059_001.powershell_process_start, ml.process_anomaly, sigma_like.t1059_001.powershell_process_start | 1 | 6 | 5 | 1 | 0 |
| T1105 | Ingress Tool Transfer | Command and Control | 4 | #3182bd | native, Sigma-like, behavioral | det.behavioral.t1105_download_sequence, det.t1105.lolbin_download, sigma_like.t1105.lolbin_download | 1, 3, 11 | 4 | 4 | 0 | 0 |
| T1547.001 | Registry Run Keys / Startup Folder | Persistence | 4 | #3182bd | native, Sigma-like, behavioral | det.behavioral.t1547_001_registry_persistence_sequence, det.t1547_001.registry_run_key_persistence, sigma_like.t1547_001.registry_run_key_persistence | 1, 13 | 2 | 2 | 0 | 0 |
| T1218 | System Binary Proxy Execution | Defense Evasion | 4 | #3182bd | native, Sigma-like, behavioral | det.behavioral.t1218_lolbin_sequence, det.t1218.lolbin_suspicious_execution, sigma_like.t1218.lolbin_suspicious_execution | 1, 3, 11 | 1 | 1 | 0 | 0 |

## Demo Matrix Totals

| Total Cases | True Positives | True Negatives | False Positives | False Negatives |
| --- | --- | --- | --- | --- |
| 20 | 12 | 6 | 1 | 1 |

## Score And Color Legend

| Score | Color | Meaning |
| --- | --- | --- |
| 1 | #d8e2ef | Single engine coverage |
| 2 | #9ecae1 | Native plus Sigma-like coverage |
| 3 | #6baed6 | Multi-engine coverage including behavioral or ML evidence |
| 4 | #3182bd | Multi-engine coverage plus demo case evidence |
| 5 | #08519c | Multi-engine, behavioral, demo case, and response/protection evidence |

## Technique Comments

- T1059.001: T1059.001 covered by native, Sigma-like, and ML anomaly demo evidence using Sysmon Event ID 1 process telemetry.
- T1105: T1105 covered by native, Sigma-like, and behavioral detections using Sysmon Event ID 1/3/11 evidence.
- T1547.001: T1547.001 covered by native, Sigma-like, and behavioral detections using Sysmon Event ID 1/13 evidence.
- T1218: T1218 is constrained T1218-lite demo coverage for deterministic LOLBin execution and behavioral sequence evidence.

## Artifact Paths

- Layer JSON: `reports/attack_navigator/edr_attack_layer.json`
- Markdown summary: `reports/attack_navigator/coverage_summary.md`
- Source coverage report: `reports/detection_coverage_report.json`
- Optional case matrix: `reports/demo_cases/case_matrix.json`
- Optional dashboard data: `reports/demo_cases/dashboard_data.json`

## Limitations

- This is not full ATT&CK coverage.
- Detection rules are deterministic demo rules.
- T1218-lite is constrained demo coverage.
- There is no production containment.
- Kill-process is lab-only and guarded by explicit flags.
- The Navigator score is a communication score, not production detection maturity.
