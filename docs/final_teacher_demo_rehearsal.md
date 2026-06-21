# Final Teacher Demo Rehearsal

Timing target: 7 to 10 minutes.

Use this as the operator checklist for the final EDR Advanced teacher demo. Run the deterministic core first. Treat Elasticsearch, Kibana, Windows VM, and Atomic Red Team as optional evidence enhancements, not as required proof that the project works.

## Prerequisites

- Python environment is ready for the repo.
- Run commands from the repository root.
- Deterministic fixtures and reports are present in the repo.
- Optional only: Elasticsearch/Kibana is running if you want live indexed evidence.
- Optional only: an isolated Windows VM is ready if you want live Sysmon/Atomic Red Team evidence.
- Optional only: ATT&CK Navigator is available in a browser for manual import of the generated layer.

## Deterministic Core Command Order

Run these commands exactly in this order:

```powershell
python -m pytest tests --basetemp=.pytest_tmp_demo
python scripts\reporting\generate_detection_coverage_report.py
python scripts\reporting\generate_final_demo_report.py
python scripts\demo\run_demo_case_matrix.py --output reports\demo_cases\case_matrix.json
python scripts\demo\generate_demo_dashboard_data.py --case-matrix reports\demo_cases\case_matrix.json --output reports\demo_cases\dashboard_data.json
python scripts\reporting\generate_attack_navigator_layer.py
python scripts\demo\build_demo_evidence_bundle.py --output-dir reports\demo_evidence
```

## Expected Outputs

- Test run completes successfully. Current target snapshot is `375 passed`.
- Detection coverage report is regenerated:
  - `reports/detection_coverage_report.json`
  - `reports/detection_coverage_report.md`
- Final demo report is regenerated:
  - `reports/final_demo_report.json`
  - `reports/final_demo_report.md`
- Case matrix is regenerated at `reports/demo_cases/case_matrix.json`.
- Dashboard data is regenerated at `reports/demo_cases/dashboard_data.json`.
- ATT&CK Navigator layer is regenerated:
  - `reports/attack_navigator/edr_attack_layer.json`
  - `reports/attack_navigator/coverage_summary.md`
- Evidence bundle is regenerated under `reports/demo_evidence`.

## Demo Flow

1. Show `README.md` and explain the project status.
2. Show `docs/architecture.md` and summarize the path:
   `collection -> normalization -> detection -> correlation -> response -> reporting`.
3. Show the generated final report at `reports/final_demo_report.md`.
4. Show the case matrix at `reports/demo_cases/case_matrix.md` or the regenerated JSON output.
5. Show `reports/attack_navigator/coverage_summary.md`.
6. Import `reports/attack_navigator/edr_attack_layer.json` into ATT&CK Navigator and show the four covered techniques.
7. Show the evidence bundle contents in `reports/demo_evidence`.
8. Close with limitations: selected ATT&CK coverage only, deterministic demo rules, constrained `T1218-lite`, no production containment.

## Kibana Screens To Show

If Elasticsearch/Kibana is available, show:

- Discover view for `edr-normalized-events-*`.
- Discover view for `edr-alerts-native-*`.
- Discover view for `edr-response-actions-*`.
- Discover view for `edr-protection-actions-*` if protection dry-run evidence was indexed.
- Dashboard panels or saved searches that reflect the demo case matrix and alert evidence.

If Kibana is unavailable, use the generated reports and JSON files instead. The deterministic core is enough for the final demo because tests and report generation do not require live infrastructure.

## ATT&CK Navigator Step

1. Open ATT&CK Navigator.
2. Import `reports/attack_navigator/edr_attack_layer.json`.
3. Show covered techniques:
   - `T1059.001`
   - `T1105`
   - `T1547.001`
   - `T1218` as constrained `T1218-lite` demo coverage.
4. Explain that Navigator scores are demo communication scores, not production detection maturity.

## Optional Live Elasticsearch/Kibana Commands

Run these only when Elasticsearch/Kibana is available:

```powershell
python scripts\demo\run_art_sysmon_demo_validation.py --input xml --xml-path .\samples\sysmon\art_t1059_001_powershell_event.xml --engine all --output summary --write-events --write-alerts --write-response
python scripts\response\run_protection_action.py --input fixture-alert --action kill-process --output summary --write-protection
```

Expected output:

- Sysmon XML is normalized.
- Native and Sigma-like alerts are produced.
- SOAR dry-run response is planned.
- Indexed event, alert, response, and protection counts are visible when Elasticsearch accepts writes.

## Optional Windows VM / Atomic Red Team Step

Use the Windows VM only if it is isolated and prepared for lab activity.

```powershell
python scripts\demo\run_art_sysmon_demo_validation.py --input xml --xml-path .\samples\sysmon\art_t1059_001_powershell_event.xml --engine all --output summary
```

Optional lab-only kill-process execution must be used only in an isolated VM and only with explicit intent:

```powershell
python scripts\response\run_protection_action.py --input alert-json --alert-path .\alert.json --action kill-process --pid <PID> --execute-protection --lab-allow-execute --output summary
```

## Fallback Plans

If Elasticsearch or Kibana is unavailable:

- Skip live indexing and Kibana screens.
- Show `reports/final_demo_report.md`.
- Show `reports/demo_cases/case_matrix.md` and `reports/demo_cases/dashboard_data.json`.
- Show `reports/attack_navigator/coverage_summary.md`.
- Show `reports/demo_evidence/manifest.json` with `missing_optional_files`.

If the Windows VM or Atomic Red Team is unavailable:

- Use deterministic fixture commands only.
- Explain that fixtures preserve the same normalized event and detection paths.
- Show the case matrix rows that explicitly label VM fallback and deterministic samples.

## Safety Notes

- Do not run Atomic Red Team tests on production endpoints.
- SOAR is dry-run response planning only.
- Protection is lab-only and safe by default.
- Kill-process execution requires both `--execute-protection` and `--lab-allow-execute`.
- No production containment, host isolation, or network blocking is implemented.
- No real credential dumping, malware payloads, or destructive payloads are required for this demo.
