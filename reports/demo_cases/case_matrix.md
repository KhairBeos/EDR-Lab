# Demo Case Matrix

Generated at: `2026-06-19T16:12:46Z`

## Summary

- Total cases: 20
- True positives: 12
- True negatives: 6
- False positives: 1
- False negatives: 1

## Cases

| Case | Category | Expected | Actual | Classification | Alerts | Responses | Notes |
| --- | --- | --- | --- | --- | ---: | ---: | --- |
| `attack_t1059_001_art_powershell_xml` | attack | True | True | true_positive | 2 | 0 | Main live VM path: ART activity -> Sysmon XML -> native/Sigma-like alerts -> SOAR dry-run. |
| `attack_t1059_001_fixture_powershell` | attack | True | True | true_positive | 2 | 0 | Use this when the VM is unavailable; it proves the same detection engines deterministically. |
| `attack_ml_encoded_download_json` | attack | True | True | true_positive | 1 | 0 | Shows the ML-style heuristic path without downloading or executing anything. |
| `attack_t1059_001_safe_manual_marker_xml` | attack | True | True | true_positive | 2 | 0 | Clearly label this as fallback, not the primary attack simulator. |
| `attack_t1059_001_atomic_marker_json` | attack | True | True | true_positive | 1 | 0 | A local sample for the teacher demo; it is data only and does not execute commands. |
| `benign_cmd_whoami_fixture` | benign | False | False | true_negative | 0 | 0 | Demonstrates a true negative for normal command execution. |
| `benign_explorer_cmd_json` | benign | False | False | true_negative | 0 | 0 | Demonstrates a true negative in the ML-style path. |
| `analysis_fp_admin_powershell_inventory` | benign | False | True | false_positive | 2 | 0 | Intentional false positive; future tuning could add context, allowlists, or risk scoring. |
| `limitation_fn_non_powershell_execution` | limitation | True | False | false_negative | 0 | 0 | Intentional false negative; use it to explain scoped detection coverage. |
| `benign_ml_common_process_json` | benign | False | False | true_negative | 0 | 0 | A second true negative for the local deterministic ML path. |
| `attack_t1105_process_lolbin_download_json` | attack | True | True | true_positive | 2 | 0 | Shows Command and Control transfer semantics without downloading anything external. |
| `attack_t1105_network_lolbin_download_json` | attack | True | True | true_positive | 2 | 0 | Highlights Event ID 3 evidence for transfer behavior. |
| `attack_t1105_file_create_download_json` | attack | True | True | true_positive | 2 | 0 | Highlights file evidence for an ingress transfer story. |
| `attack_t1547_001_registry_run_key_json` | attack | True | True | true_positive | 2 | 0 | Shows Persistence coverage without creating a real registry value. |
| `attack_t1218_rundll32_lolbin_json` | attack | True | True | true_positive | 2 | 0 | Label this as T1218-lite; it is deterministic demo coverage, not complete LOLBin analytics. |
| `attack_behavioral_t1105_sequence_json` | attack | True | True | true_positive | 1 | 0 | Shows Phase 14 behavioral correlation without changing single-event T1105 rules. |
| `attack_behavioral_t1547_001_sequence_json` | attack | True | True | true_positive | 1 | 0 | Shows Phase 14 persistence correlation with deterministic local JSON events. |
| `benign_behavioral_unrelated_sequence_json` | benign | False | False | true_negative | 0 | 0 | True negative for the Phase 14 behavioral engine. |
| `benign_phase13_network_json` | benign | False | False | true_negative | 0 | 0 | True negative for Event ID 3 style telemetry. |
| `benign_phase13_file_create_json` | benign | False | False | true_negative | 0 | 0 | True negative for Event ID 11 style telemetry. |
