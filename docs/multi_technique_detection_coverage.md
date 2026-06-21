# Multi-technique Detection Coverage

Phase 13 expands deterministic ATT&CK demo coverage beyond `T1059.001` PowerShell by using the Sysmon Event ID `1`, `3`, `11`, and `13` telemetry added in Phase 12.

## Rules

| Rule ID | Engine | ATT&CK | Tactic | Sysmon evidence | Severity | Confidence |
| --- | --- | --- | --- | --- | --- | --- |
| `det.t1105.lolbin_download` | native | `T1105` Ingress Tool Transfer | Command and Control | Event ID `1`, `3`, `11` | medium | medium |
| `sigma_like.t1105.lolbin_download` | sigma-like | `T1105` Ingress Tool Transfer | Command and Control | Event ID `1`, `3`, `11` | medium | medium |
| `det.t1547_001.registry_run_key_persistence` | native | `T1547.001` Registry Run Keys / Startup Folder | Persistence | Event ID `13` | high | high |
| `sigma_like.t1547_001.registry_run_key_persistence` | sigma-like | `T1547.001` Registry Run Keys / Startup Folder | Persistence | Event ID `13` | high | high |
| `det.t1218.lolbin_suspicious_execution` | native | `T1218` System Binary Proxy Execution | Defense Evasion | Event ID `1` | medium | medium |
| `sigma_like.t1218.lolbin_suspicious_execution` | sigma-like | `T1218` System Binary Proxy Execution | Defense Evasion | Event ID `1` | medium | medium |

## Safe Demo Samples

The Phase 13 samples live under `samples/demo_cases/` and are normalized ECS-like JSON documents. They are data only; they do not execute commands.

- `t1105_certutil_process_event.json`: true positive process marker for `T1105`.
- `t1105_certutil_network_event.json`: true positive Event ID `3` network evidence for `T1105`.
- `t1105_file_create_event.json`: true positive Event ID `11` file evidence for `T1105`.
- `t1547_registry_run_key_event.json`: true positive Event ID `13` registry evidence for `T1547.001`.
- `t1218_rundll32_process_event.json`: true positive process marker for `T1218`.
- `benign_network_event.json`: true negative network event.
- `benign_file_create_event.json`: true negative file create event.

Safety boundaries:

- Samples use `127.0.0.1` or `example.test`.
- Samples use explicit markers: `EDR_DEMO_T1105`, `EDR_DEMO_T1547`, and `EDR_DEMO_T1218`.
- Samples do not contain malware payloads, credential dumping, external downloads, or production containment.
- Automated tests do not require Windows, Sysmon, Elasticsearch, Docker, Kafka, Kibana, or Atomic Red Team.

## Known Limitations

`T1218` coverage is intentionally `T1218-lite`. It detects constrained rundll32/regsvr32/mshta demo markers, not comprehensive LOLBin behavior.

`T1105` coverage is marker-driven and demo-safe. It should not be treated as production-ready transfer detection without tuning, allowlists, reputation context, and broader telemetry correlation.

`T1547.001` coverage focuses on Run and RunOnce value set events with explicit suspicious/demo data. It does not model every Windows startup persistence location.

## Regeneration Commands

```powershell
python -m pytest tests\test_multi_technique_detection.py
python -m pytest tests --basetemp=.pytest_tmp_phase13
python scripts\reporting\generate_detection_coverage_report.py
python scripts\reporting\generate_final_demo_report.py
python scripts\demo\run_demo_case_matrix.py --output reports\demo_cases\case_matrix.json
python scripts\demo\generate_demo_dashboard_data.py --case-matrix reports\demo_cases\case_matrix.json --output reports\demo_cases\dashboard_data.json
```
