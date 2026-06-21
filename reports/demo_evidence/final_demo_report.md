# Final Demo Report

Generated: 2026-06-19T16:30:47Z
Project status: Phase 15 ATT&CK Navigator export ready
Correlated sequences validated: 3

## Implemented Phases

- Phase 1 Foundation
- Phase 2 Native Detection Pipeline MVP
- Phase 3 Live Telemetry Pipeline, Sigma-like Detection, and Coverage Report
- Phase 4 Kafka Normalized Event Detection Pipeline
- Phase 5 SOAR Dry-run Response Pipeline
- Phase 6 ML-style Process Anomaly Detection MVP
- Phase 7 Final Demo Report and Operator Dashboard MVP
- Phase 8 ART / Sysmon VM Demo
- Phase 9 10-case TP/TN/FP/FN Demo Case Matrix
- Phase 10 Lab-only Kill-process Protection Action
- Phase 13 Multi-technique ATT&CK Demo Detection
- Phase 14 Behavioral Correlation Detection
- Phase 15 ATT&CK Navigator Coverage Export

## Capability Matrix

| Capability | Status | Validation | Primary Command / Artifact | Description |
| --- | --- | --- | --- | --- |
| telemetry | implemented | passed | `python scripts\smoke\end_to_end_art_telemetry_smoke.py` | Elastic/Kibana/Logstash local lab and Sysmon Event ID 1 fixture telemetry. |
| normalization | implemented | passed | `normalization/sysmon/process_create_normalizer.py` | Normalizes Sysmon Event ID 1 process creation XML into ECS-like documents. |
| native_detection | implemented | passed | `python scripts\detection\run_native_detection.py` | Detects PowerShell process execution using native rule logic. |
| sigma_like_detection | implemented | passed | `python scripts\pipeline\run_live_telemetry_pipeline.py --input fixture --fixture-detectable-powershell --engine sigma-like` | Detects PowerShell process execution using Sigma-like rule logic. |
| kafka_transport | implemented | passed | `python scripts\kafka\consume_and_detect.py --dry-run-fixture --engine all` | Transports normalized event messages through deterministic Kafka dry-run producer/consumer paths. |
| alert_indexing | implemented | passed | `detection/rules/native/alert_indexer.py` | Indexes alert documents into edr-alerts-native-* through the existing alert indexer. |
| soar_dry_run | implemented | passed | `python scripts\response\run_soar_response.py --input fixture-alert` | Plans dry-run SOAR response records for matching alerts. |
| ml_anomaly | implemented | passed | `python scripts\ml\run_process_anomaly_detection.py --input fixture` | Scores process anomaly features against a deterministic local baseline. |
| reporting | implemented | passed | `python scripts\reporting\generate_final_demo_report.py` | Generates detection coverage and final demo reports. |
| attack_navigator_export | implemented | passed | `python scripts\reporting\generate_attack_navigator_layer.py` | Exports the local coverage matrix as reports/attack_navigator/edr_attack_layer.json and reports/attack_navigator/coverage_summary.md. |
| multi_technique_detection | implemented | passed | `docs/multi_technique_detection_coverage.md` | Detects safe demo coverage for T1105, T1547.001, and T1218 using Sysmon Event ID 1/3/11/13 evidence. |
| behavioral_correlation | implemented | passed | `docs/behavioral_correlation_detection.md` | Correlates normalized process, network, file, and registry telemetry into deterministic attack sequences. |
| demo_case_matrix | implemented | passed | `python scripts\demo\run_demo_case_matrix.py --output reports\demo_cases\case_matrix.json` | Generates the Phase 9 10-case demo matrix for TP/TN/FP/FN classification. |
| tp_tn_fp_fn_classification | implemented | passed | `reports/demo_cases/dashboard_data.json` | Keeps true positives, true negatives, false positives, and false negatives visible as evaluation evidence. |
| lab_only_protection_action | implemented | passed | `python scripts\response\run_protection_action.py --input fixture-alert --action kill-process --output summary` | Builds guarded Phase 10 lab-only kill-process protection records with dry-run default. |
| protection_action_index | implemented | passed | `edr-protection-actions-*` | Stores lab-only protection evidence in edr-protection-actions-* when indexing is requested. |

## Validation Results

| ID | Name | Status | Details | Counts |
| --- | --- | --- | --- | --- |
| live_telemetry_native | Live telemetry fixture produces native PowerShell alert | passed | Expected one native alert, got 1. | alert_count=1 |
| live_telemetry_sigma_like | Live telemetry fixture produces Sigma-like PowerShell alert | passed | Expected one Sigma-like alert, got 1. | alert_count=1 |
| kafka_native | Kafka dry-run fixture produces native PowerShell alert | passed | Expected one native Kafka alert, got 1. | alert_count=1 |
| kafka_sigma_like | Kafka dry-run fixture produces Sigma-like PowerShell alert | passed | Expected one Sigma-like Kafka alert, got 1. | alert_count=1 |
| soar_fixture_response | SOAR fixture alert produces one dry-run response record | passed | Expected one response record, got 1. | response_count=1 |
| ml_fixture_scoring | ML benign fixture produces low score and no alert | passed | Expected low score and no alert, got score 0.0 and 0 alerts. | alert_count=0, score=0.0 |
| detection_coverage_report | Detection coverage report validation passes | passed | Coverage report produced 2 fixture alerts. | alert_count=2 |
| multi_technique_detection | Coverage report includes Phase 13 and Phase 14 multi-technique rules | passed | Covered techniques: T1059.001, T1105, T1218, T1547.001. | rule_count=11 |
| behavioral_correlation | Behavioral correlation detects deterministic Phase 14 sequences | passed | Behavioral rules matched: det.behavioral.t1105_download_sequence, det.behavioral.t1218_lolbin_sequence, det.behavioral.t1547_001_registry_persistence_sequence. | correlated_sequence_count=3 |

## Demo Command Checklist

- `python scripts\smoke\end_to_end_art_telemetry_smoke.py`
- `python scripts\detection\run_native_detection.py`
- `python scripts\pipeline\run_live_telemetry_pipeline.py --input fixture --fixture-detectable-powershell --engine all`
- `python scripts\kafka\produce_normalized_event.py --input fixture --fixture-detectable-powershell --dry-run`
- `python scripts\kafka\consume_and_detect.py --dry-run-fixture --engine all`
- `python scripts\response\run_soar_response.py --input fixture-alert`
- `python scripts\response\run_protection_action.py --input fixture-alert --action kill-process --output summary`
- `python scripts\ml\run_process_anomaly_detection.py --input fixture`
- `python scripts\reporting\generate_detection_coverage_report.py`
- `python scripts\reporting\generate_final_demo_report.py`
- `python scripts\reporting\generate_attack_navigator_layer.py`
- `python scripts\demo\run_demo_case_matrix.py --output reports\demo_cases\case_matrix.json`
- `python scripts\demo\generate_demo_dashboard_data.py --case-matrix reports\demo_cases\case_matrix.json --output reports\demo_cases\dashboard_data.json`

## Known Limitations

- Elasticsearch and Kibana are optional unless live index counts are requested.
- Kafka validation uses deterministic in-memory dry-run paths, not a required live broker.
- SOAR remains dry-run response planning and does not execute production containment.
- Lab-only kill-process requires explicit --execute-protection and --lab-allow-execute flags.
- ML anomaly detection is heuristic and deterministic, not trained production ML.
- Behavioral correlation is deterministic local sequence matching, not full endpoint graph analytics.
- ATT&CK Navigator scores are demo communication scores, not production detection maturity scores.

## Out Of Scope

- New Sysmon Event IDs
- TheHive
- Production containment
- Host isolation or network blocking
- Dashboards requiring Kibana API
- Heavy ML frameworks
- Graph database backed endpoint analytics
- Streaming behavioral state
- Full enterprise ATT&CK coverage
