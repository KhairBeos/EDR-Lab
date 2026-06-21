# Demo Case Catalog: Phase 9 + Phase 13 + Phase 14 Cases

Phase 9 expands the single Phase 8 PowerShell validation into a teacher-friendly case matrix. Phase 13 extends the same catalog with deterministic multi-technique ATT&CK coverage for `T1105`, `T1547.001`, and `T1218`. Phase 14 adds behavioral sequence cases that correlate multiple normalized events without changing single-event rule semantics.

The goal is to show detection validation honestly: true positives, true negatives, false positives, and false negatives are all visible.

Safety boundaries:

- No malware payloads.
- No malware downloads.
- No real containment.
- SOAR remains dry-run only.
- Existing native, Sigma-like, ML, Kafka, and SOAR semantics are not changed to make the matrix look better.

## Classification Rules

| Expected alert | Actual alert | Classification |
| --- | --- | --- |
| true | true | true_positive |
| false | false | true_negative |
| false | true | false_positive |
| true | false | false_negative |

## Case Matrix

| Case ID | Name | Category | Expected | Engines / rules | Response | Expected classification | Source | Teacher notes |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `attack_t1059_001_art_powershell_xml` | Atomic Red Team T1059.001 PowerShell XML | attack | alert | native + Sigma-like, `det.t1059_001.powershell_process_start`, `sigma_like.t1059_001.powershell_process_start` | dry-run | true_positive | Windows VM / Atomic Red Team export or Phase 8 sample | Main live VM path. |
| `attack_t1059_001_fixture_powershell` | Detectable PowerShell fixture | attack | alert | native + Sigma-like | dry-run | true_positive | deterministic local fixture | Backup when VM is unavailable. |
| `attack_ml_encoded_download_json` | ML-style encoded/download indicators | attack | alert | `ml-anomaly`, `ml.process_anomaly` | none | true_positive | deterministic local JSON | Shows anomaly path without executing code. |
| `attack_t1059_001_safe_manual_marker_xml` | Safe manual PowerShell marker XML | attack | alert | native + Sigma-like | dry-run | true_positive | safe manual command XML | Fallback command, not primary simulator. |
| `attack_t1059_001_atomic_marker_json` | Atomic marker suspicious normalized JSON | attack | alert | `ml-anomaly`, `ml.process_anomaly` | none | true_positive | deterministic local JSON | Data-only Atomic marker style sample. |
| `benign_cmd_whoami_fixture` | Benign cmd whoami fixture | benign | no alert | none | none | true_negative | deterministic local fixture | Normal command execution. |
| `benign_explorer_cmd_json` | Benign explorer-launched cmd JSON | benign | no alert | none | none | true_negative | deterministic local JSON | Normal ML path event below threshold. |
| `analysis_fp_admin_powershell_inventory` | Admin PowerShell inventory analysis FP | benign | no alert | current rules may alert | none | false_positive | safe Sysmon XML sample | Explains broad PowerShell rule trade-off and future tuning. |
| `limitation_fn_non_powershell_execution` | Non-PowerShell script host limitation FN | limitation | alert | future non-PowerShell coverage | none | false_negative | safe Sysmon XML sample | Explains current MVP coverage limitation. |
| `benign_ml_common_process_json` | Benign ML common process JSON | benign | no alert | none | none | true_negative | deterministic local JSON | Second true negative for ML-style path. |
| `attack_t1105_process_lolbin_download_json` | T1105 LOLBin process download marker JSON | attack | alert | native + Sigma-like, `det.t1105.lolbin_download`, `sigma_like.t1105.lolbin_download` | none | true_positive | deterministic local JSON | Safe process marker for Ingress Tool Transfer. |
| `attack_t1105_network_lolbin_download_json` | T1105 LOLBin network connection JSON | attack | alert | native + Sigma-like, `det.t1105.lolbin_download`, `sigma_like.t1105.lolbin_download` | none | true_positive | deterministic local JSON | Event ID 3 evidence for transfer behavior. |
| `attack_t1105_file_create_download_json` | T1105 downloaded file create JSON | attack | alert | native + Sigma-like, `det.t1105.lolbin_download`, `sigma_like.t1105.lolbin_download` | none | true_positive | deterministic local JSON | Event ID 11 evidence for downloaded file creation. |
| `attack_t1547_001_registry_run_key_json` | T1547.001 Registry Run key persistence JSON | attack | alert | native + Sigma-like, `det.t1547_001.registry_run_key_persistence`, `sigma_like.t1547_001.registry_run_key_persistence` | none | true_positive | deterministic local JSON | Event ID 13 evidence for Run key persistence. |
| `attack_t1218_rundll32_lolbin_json` | T1218 rundll32 LOLBin marker JSON | attack | alert | native + Sigma-like, `det.t1218.lolbin_suspicious_execution`, `sigma_like.t1218.lolbin_suspicious_execution` | none | true_positive | deterministic local JSON | T1218-lite demo coverage, not comprehensive LOLBin analytics. |
| `attack_behavioral_t1105_sequence_json` | Behavioral T1105 process/network/file sequence JSON | attack | alert | behavioral, `det.behavioral.t1105_download_sequence` | none | true_positive | deterministic local JSON array | Correlates process, network, and file evidence into one sequence alert. |
| `attack_behavioral_t1547_001_sequence_json` | Behavioral T1547.001 process/registry sequence JSON | attack | alert | behavioral, `det.behavioral.t1547_001_registry_persistence_sequence` | none | true_positive | deterministic local JSON array | Correlates process and registry evidence into one persistence alert. |
| `benign_behavioral_unrelated_sequence_json` | Benign unrelated behavioral sequence JSON | benign | no alert | none | none | true_negative | deterministic local JSON array | True negative for behavioral correlation. |
| `benign_phase13_network_json` | Benign network connection JSON | benign | no alert | none | none | true_negative | deterministic local JSON | True negative for Event ID 3 telemetry. |
| `benign_phase13_file_create_json` | Benign file create JSON | benign | no alert | none | none | true_negative | deterministic local JSON | True negative for Event ID 11 telemetry. |

## VM / Atomic Red Team Driven Cases

- `attack_t1059_001_art_powershell_xml`
- `attack_t1059_001_safe_manual_marker_xml`, when exported from a VM instead of using the sample.
- `analysis_fp_admin_powershell_inventory`, when recorded from a real admin command.
- `limitation_fn_non_powershell_execution`, when recorded from a safe script-host marker.

## Deterministic Local Samples

- `attack_t1059_001_fixture_powershell`
- `attack_ml_encoded_download_json`
- `attack_t1059_001_atomic_marker_json`
- `benign_cmd_whoami_fixture`
- `benign_explorer_cmd_json`
- `benign_ml_common_process_json`
- `attack_t1105_process_lolbin_download_json`
- `attack_t1105_network_lolbin_download_json`
- `attack_t1105_file_create_download_json`
- `attack_t1547_001_registry_run_key_json`
- `attack_t1218_rundll32_lolbin_json`
- `attack_behavioral_t1105_sequence_json`
- `attack_behavioral_t1547_001_sequence_json`
- `benign_behavioral_unrelated_sequence_json`
- `benign_phase13_network_json`
- `benign_phase13_file_create_json`

## Commands

```powershell
python scripts\demo\run_demo_case_matrix.py --output reports\demo_cases\case_matrix.json
python scripts\demo\generate_demo_dashboard_data.py --case-matrix reports\demo_cases\case_matrix.json --output reports\demo_cases\dashboard_data.json
```

The matrix should be regenerated before the live teacher demo so the evidence reflects the current code.
