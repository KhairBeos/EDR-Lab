# Final Demo Script

This is a 5-minute operator flow for the final EDR MVP demo.

## 1. Generate Final Report

```powershell
python scripts\reporting\generate_final_demo_report.py
```

Point to:

- `reports/final_demo_report.json`
- `reports/final_demo_report.md`

## 2. Show Full Regression

```powershell
python -m pytest tests
```

Explain that tests use deterministic fixture and in-memory paths. Docker, Kafka, Elasticsearch, Kibana, and the Windows VM are not required.

## 3. Run Live Telemetry Fixture With Both Detection Engines

```powershell
python scripts\pipeline\run_live_telemetry_pipeline.py --input fixture --fixture-detectable-powershell --engine all --output summary
```

Expected result: native and Sigma-like PowerShell alerts.

## 4. Run Kafka Dry-Run Producer And Consumer

Producer dry-run:

```powershell
python scripts\kafka\produce_normalized_event.py --input fixture --fixture-detectable-powershell --dry-run
```

Consumer dry-run:

```powershell
python scripts\kafka\consume_and_detect.py --dry-run-fixture --engine all
```

Expected result: in-memory Kafka path produces native and Sigma-like alerts without a live broker.

## 5. Run SOAR Fixture Response

```powershell
python scripts\response\run_soar_response.py --input fixture-alert --output summary
```

Expected result: one dry-run response record with planned actions only.

## 6. Run ML Benign Fixture

```powershell
python scripts\ml\run_process_anomaly_detection.py --input fixture --output summary
```

Expected result: low score and no alert for the benign fixture.

## 7. Optional Elasticsearch Count Report

Run only if Elasticsearch is available:

```powershell
python scripts\reporting\generate_final_demo_report.py --include-elasticsearch --elasticsearch-url http://localhost:9200
```

Expected result: final report includes counts for:

- `edr-normalized-events-*`
- `edr-alerts-native-*`
- `edr-response-actions-*`
- `edr-protection-actions-*`

## 8. Generate Phase 9 Case Matrix And Dashboard Data

```powershell
python scripts\demo\run_demo_case_matrix.py --output reports\demo_cases\case_matrix.json
python scripts\demo\generate_demo_dashboard_data.py --case-matrix reports\demo_cases\case_matrix.json --output reports\demo_cases\dashboard_data.json
```

Expected result: a 10-case matrix that keeps true positives, true negatives, false positives, and false negatives visible as evaluation evidence.

Point to:

- `reports/demo_cases/case_matrix.json`
- `reports/demo_cases/dashboard_data.json`

## 9. Show Phase 10 Lab-only Protection Record

Default dry-run:

```powershell
python scripts\response\run_protection_action.py --input fixture-alert --action kill-process --output summary
```

Expected result: a planned protection action record. Real kill-process execution is lab-only and requires both `--execute-protection` and `--lab-allow-execute`.

Protection evidence can be indexed into:

- `edr-protection-actions-*`

## 10. Close With Artifacts

Open:

```powershell
Get-Content reports\final_demo_report.md
```

Summarize:

- Phase 1 through Phase 10 are implemented.
- Core validations pass without live infrastructure.
- Phase 9 FP/FN entries are kept visible as evaluation evidence, not hidden.
- SOAR remains dry-run response planning.
- Kill-process is lab-only, safe-by-default, and requires explicit execution flags.
- Live Docker/Kafka/Elasticsearch/Windows VM paths remain manual lab extensions.
