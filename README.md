# EDR MVP Lab

Local Endpoint Detection and Response MVP lab for learning and demoing a 5-layer EDR pipeline:

```text
collection -> normalization -> detection -> response -> reporting
```

Current status: Phase 16 final teacher demo package ready. Phase 1 through Phase 10 plus Phase 12, Phase 13, Phase 14, Phase 15, and Phase 16 are implemented, deterministic local tests pass, and the final demo reports can be generated without live Docker, Kafka, Elasticsearch, Kibana, or a Windows VM.

## Current Status

- Full deterministic regression command: `python -m pytest tests`
- Final report command: `python scripts\reporting\generate_final_demo_report.py`
- Final artifacts:
  - `reports/final_demo_report.json`
  - `reports/final_demo_report.md`
  - `reports/attack_navigator/edr_attack_layer.json`
  - `reports/attack_navigator/coverage_summary.md`

The live lab integrations are still useful for manual verification, but CI and default tests intentionally use fixtures and in-memory dry-run paths.

## Architecture Overview

See [docs/architecture.md](docs/architecture.md) for the full architecture diagram and data flow.

```text
Sysmon XML / fixture
  -> ECS normalization (Sysmon Event ID 1/3/11/13)
  -> native detection / Sigma-like detection / behavioral correlation / ML-style anomaly scoring
  -> alert documents
  -> optional Kafka transport
  -> SOAR dry-run response planning
  -> lab-only protection action records
  -> final reports
```

Indexes and topics used by the MVP:

- Elasticsearch normalized events: `edr-normalized-events-*`
- Elasticsearch alerts: `edr-alerts-native-*`
- Elasticsearch response actions: `edr-response-actions-*`
- Elasticsearch protection actions: `edr-protection-actions-*`
- Kafka topic: `normalized-events`

## Completed Phases

- Phase 1 Foundation: Docker lab, Windows VM setup path, Sysmon Event ID 1 fixture, ART smoke path, ECS normalization.
- Phase 2 Native Detection Pipeline MVP: native PowerShell `T1059.001` detection and alert indexing.
- Phase 3 Live Telemetry Pipeline, Sigma-like Detection, and Coverage Report: fixture live telemetry path, Sigma-like detection, detection coverage report.
- Phase 4 Kafka Normalized Event Detection Pipeline: deterministic producer/consumer dry-run and optional Kafka transport.
- Phase 5 SOAR Dry-run Response Pipeline: planned response records for PowerShell alerts, no production containment.
- Phase 6 ML-style Process Anomaly Detection MVP: deterministic feature extraction, baseline scoring, anomaly alert builder.
- Phase 7 Final Demo Report and Operator Dashboard MVP: JSON/Markdown final report with validation matrix and optional Elasticsearch counts.
- Phase 8 ART / Sysmon VM Demo: safe Atomic Red Team backed Windows VM demo path and evidence workflow.
- Phase 9 10-case TP/TN/FP/FN Demo Case Matrix: teacher-friendly case catalog, matrix report, and dashboard data.
- Phase 10 Lab-only Kill-process Protection Action: guarded protection action records with dry-run default and explicit lab execution flags.
- Phase 12 Expanded Sysmon Telemetry: normalized Sysmon Event ID 1, 3, 11, and 13 coverage.
- Phase 13 Multi-technique ATT&CK Demo Detection: deterministic T1105, T1547.001, and T1218-lite single-event coverage.
- Phase 14 Behavioral Correlation Detection: deterministic process/network/file/registry sequence correlation for T1105, T1547.001, and T1218-lite.
- Phase 15 ATT&CK Navigator Coverage Export: local Navigator layer and Markdown summary for demo coverage visualization.
- Phase 16 Final Teacher Demo Package: rehearsal guide, talk track, submission checklist, and doc-only package tests.

## Capability Matrix

| Capability | Status | Primary command / artifact |
| --- | --- | --- |
| Telemetry fixture | Implemented | `python scripts\smoke\end_to_end_art_telemetry_smoke.py` |
| ECS normalization | Implemented | `normalization/sysmon/event_router.py` for Sysmon Event ID 1/3/11/13 |
| Native detection | Implemented | `python scripts\detection\run_native_detection.py` |
| Sigma-like detection | Implemented | `python scripts\pipeline\run_live_telemetry_pipeline.py --input fixture --fixture-detectable-powershell --engine all` |
| Behavioral correlation | Implemented | `python -m pytest tests\test_behavioral_correlation.py` |
| Kafka transport | Implemented | `python scripts\kafka\consume_and_detect.py --dry-run-fixture --engine all` |
| Alert indexing | Implemented | `detection/rules/native/alert_indexer.py` |
| SOAR dry-run | Implemented | `python scripts\response\run_soar_response.py --input fixture-alert` |
| ML anomaly | Implemented | `python scripts\ml\run_process_anomaly_detection.py --input fixture` |
| Reporting | Implemented | `python scripts\reporting\generate_final_demo_report.py` |
| ATT&CK Navigator export | Implemented | `python scripts\reporting\generate_attack_navigator_layer.py` |
| Demo case matrix | Implemented | `python scripts\demo\run_demo_case_matrix.py --output reports\demo_cases\case_matrix.json` |
| TP/TN/FP/FN classification | Implemented | `reports/demo_cases/case_matrix.json` and `reports/demo_cases/dashboard_data.json` |
| Lab-only protection action | Implemented | `python scripts\response\run_protection_action.py --input fixture-alert --action kill-process --output summary` |
| Protection action index | Implemented | `edr-protection-actions-*` |

## Quickstart

```powershell
python -m pytest tests
python scripts\reporting\generate_final_demo_report.py
python scripts\reporting\generate_attack_navigator_layer.py
Get-Content reports\final_demo_report.md
```

Run the main deterministic demo path:

```powershell
python scripts\pipeline\run_live_telemetry_pipeline.py --input fixture --fixture-detectable-powershell --engine all --output summary
python scripts\kafka\consume_and_detect.py --dry-run-fixture --engine all
python scripts\response\run_soar_response.py --input fixture-alert --output summary
python scripts\ml\run_process_anomaly_detection.py --input fixture --output summary
python scripts\demo\run_demo_case_matrix.py --output reports\demo_cases\case_matrix.json
python scripts\demo\generate_demo_dashboard_data.py --case-matrix reports\demo_cases\case_matrix.json --output reports\demo_cases\dashboard_data.json
python scripts\reporting\generate_attack_navigator_layer.py
```

## Local Docker Lab

See [docs/docker_lab_setup.md](docs/docker_lab_setup.md).

Useful commands:

```powershell
docker compose up -d
docker compose -f docker-compose.kafka.yml up -d
docker compose ps
docker compose down
```

Docker services are for manual lab validation. They are not required for tests or CI.

## Windows VM / Sysmon Lab

See [docs/windows_vm_lab_setup.md](docs/windows_vm_lab_setup.md).

The Windows VM is the recommended real endpoint lab for Sysmon and Atomic Red Team telemetry. It is not required for deterministic tests because this repo includes safe Sysmon Event ID 1/3/11/13 fixtures.

## VM Attack Demo and Dashboard Validation

Phase 8 validates the EDR MVP with a safe Atomic Red Team backed Windows VM demo path and Kibana evidence workflow.

- [Windows VM Atomic Red Team Demo](docs/windows_vm_atomic_red_team_demo.md)
- [Atomic Attack Case Catalog](docs/atomic_attack_case_catalog.md)
- [Sysmon Event XML Export](docs/sysmon_event_export.md)
- [Kibana Dashboard Validation](docs/kibana_dashboard_validation.md)
- [Demo Evidence Checklist](docs/demo_evidence_checklist.md)

Core commands:

```powershell
python scripts\demo\run_art_sysmon_demo_validation.py --input fixture --engine all --output summary
python scripts\demo\run_demo_case_matrix.py --output reports\demo_cases\case_matrix.json
python scripts\demo\generate_demo_dashboard_data.py --case-matrix reports\demo_cases\case_matrix.json --output reports\demo_cases\dashboard_data.json
python scripts\demo\build_demo_evidence_bundle.py --output-dir reports\demo_evidence
```

## Kafka Local Setup

Kafka is optional for live transport. The deterministic test/demo path uses in-memory dry-run helpers.

Manual Kafka lab:

```powershell
docker compose -f docker-compose.kafka.yml up -d
python scripts\kafka\produce_normalized_event.py --input fixture --fixture-detectable-powershell --dry-run
python scripts\kafka\consume_and_detect.py --dry-run-fixture --engine all
```

## CI/CD

See [docs/cicd.md](docs/cicd.md).

The lightweight CI workflow runs deterministic tests only:

```powershell
python -m pytest tests
```

CI intentionally does not require Docker, Kafka, Elasticsearch, Kibana, or a Windows VM.

## Final Demo Commands

See [docs/final_demo_script.md](docs/final_demo_script.md) for a 5-minute operator flow.

For the Phase 15/16 final teacher demo package, use:

- [Final Teacher Demo Rehearsal](docs/final_teacher_demo_rehearsal.md)
- [Final Teacher Demo Talk Track](docs/final_teacher_demo_talk_track.md)
- [Final Submission Checklist](docs/final_submission_checklist.md)

Core commands:

```powershell
python scripts\reporting\generate_final_demo_report.py
python scripts\reporting\generate_attack_navigator_layer.py
python -m pytest tests
python scripts\pipeline\run_live_telemetry_pipeline.py --input fixture --fixture-detectable-powershell --engine all --output summary
python scripts\kafka\produce_normalized_event.py --input fixture --fixture-detectable-powershell --dry-run
python scripts\kafka\consume_and_detect.py --dry-run-fixture --engine all
python scripts\response\run_soar_response.py --input fixture-alert --output summary
python scripts\ml\run_process_anomaly_detection.py --input fixture --output summary
python scripts\demo\run_demo_case_matrix.py --output reports\demo_cases\case_matrix.json
python scripts\demo\generate_demo_dashboard_data.py --case-matrix reports\demo_cases\case_matrix.json --output reports\demo_cases\dashboard_data.json
```

Optional live Elasticsearch counts:

```powershell
python scripts\reporting\generate_final_demo_report.py --include-elasticsearch --elasticsearch-url http://localhost:9200
```

## Report Artifacts

- Final demo report: [reports/final_demo_report.md](reports/final_demo_report.md)
- Final demo JSON: [reports/final_demo_report.json](reports/final_demo_report.json)
- Detection coverage report: `reports/detection_coverage_report.md`
- ATT&CK Navigator layer: `reports/attack_navigator/edr_attack_layer.json`
- ATT&CK Navigator summary: `reports/attack_navigator/coverage_summary.md`
- Phase 9 case matrix: `reports/demo_cases/case_matrix.json`
- Phase 9 dashboard data: `reports/demo_cases/dashboard_data.json`

## Known Limitations

- Sysmon normalization covers Event ID 1, 3, 11, and 13 only; other Sysmon event IDs are future work.
- Detection coverage includes PowerShell `T1059.001`, deterministic single-event `T1105` / `T1547.001` / `T1218-lite`, and deterministic behavioral correlation for `T1105` / `T1547.001` / `T1218-lite`.
- SOAR response is dry-run only.
- Lab-only kill-process requires explicit `--execute-protection` and `--lab-allow-execute` flags.
- ML anomaly detection is deterministic heuristic scoring, not trained production ML.
- Behavioral correlation is local deterministic sequence matching, not graph database backed endpoint analytics or streaming state.
- ATT&CK Navigator scores are demo communication scores, not production detection maturity.
- ATT&CK Navigator export is not a claim of full enterprise ATT&CK coverage.
- Elasticsearch, Kafka, Kibana, and the Windows VM are optional manual lab paths, not CI requirements.
- Stubbed roadmap modules are documented in [Known Stubs and Future Work](docs/known_stubs_and_future_work.md) and are not current MVP claims.

## Safety Boundaries

- Do not run Atomic Red Team tests on production endpoints.
- SOAR remains dry-run response planning.
- Kill-process is lab-only, safe-by-default, and requires explicit execution flags.
- No production containment, host isolation, or network block is implemented.
- No TheHive or external ticketing integration is implemented.
- Docker/Kafka/Elasticsearch checks are manual unless explicitly requested.

## Documentation Index

- [Architecture](docs/architecture.md)
- [Docker Lab Setup](docs/docker_lab_setup.md)
- [Windows VM / Sysmon Lab Setup](docs/windows_vm_lab_setup.md)
- [Windows VM Atomic Red Team Demo](docs/windows_vm_atomic_red_team_demo.md)
- [Atomic Attack Case Catalog](docs/atomic_attack_case_catalog.md)
- [Sysmon Event XML Export](docs/sysmon_event_export.md)
- [Sysmon Event Coverage](docs/sysmon_event_coverage.md)
- [Multi-technique Detection Coverage](docs/multi_technique_detection_coverage.md)
- [Behavioral Correlation Detection](docs/behavioral_correlation_detection.md)
- [ATT&CK Navigator Coverage Export](docs/attack_navigator_coverage.md)
- [Kibana Dashboard Validation](docs/kibana_dashboard_validation.md)
- [Demo Dashboard Design](docs/demo_dashboard_design.md)
- [Demo Evidence Checklist](docs/demo_evidence_checklist.md)
- [CI/CD](docs/cicd.md)
- [Final Demo Script](docs/final_demo_script.md)
- [Final Teacher Demo Rehearsal](docs/final_teacher_demo_rehearsal.md)
- [Final Teacher Demo Talk Track](docs/final_teacher_demo_talk_track.md)
- [Final Submission Checklist](docs/final_submission_checklist.md)
- [Final Demo Report MVP](docs/final_demo_report_mvp.md)
- [Protection Action MVP](docs/protection_action_mvp.md)
- [Known Stubs and Future Work](docs/known_stubs_and_future_work.md)
- [Phase 1 Operator Runbook](docs/phase_1_operator_runbook.md)
- [Phase 2 Detection Engine MVP](docs/phase_2_detection_engine_mvp.md)
- [Live Telemetry Pipeline MVP](docs/live_telemetry_pipeline_mvp.md)
- [Sigma-like Detection MVP](docs/sigma_detection_mvp.md)
- [Kafka Pipeline MVP](docs/kafka_pipeline_mvp.md)
- [SOAR Response MVP](docs/soar_response_mvp.md)
- [ML Anomaly MVP](docs/ml_anomaly_mvp.md)

## License

MIT License. See [LICENSE](LICENSE).
