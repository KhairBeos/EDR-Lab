# Detection Coverage Report

Generated: 2026-06-19T16:30:44Z
Project phase: Phase 14 Behavioral Correlation Detection

## Coverage Summary

- Native rules: 4
- Sigma-like rules: 4
- Behavioral rules: 3
- Total rules: 11

## Covered Techniques

| Technique | Name | Tactic | Dataset | Event ID | Event Type | Engines |
| --- | --- | --- | --- | --- | --- | --- |
| T1059.001 | PowerShell | Execution | windows.sysmon_operational | 1 | process_creation | native, sigma-like |
| T1105 | Ingress Tool Transfer | Command and Control | windows.sysmon_operational | 1/3/11 | process_creation, network_connection, file_creation | native, sigma-like, behavioral |
| T1547.001 | Registry Run Keys / Startup Folder | Persistence | windows.sysmon_operational | 1/13 | process_creation, registry_value_set | native, sigma-like, behavioral |
| T1218 | System Binary Proxy Execution | Defense Evasion | windows.sysmon_operational | 1 | process_creation | native, sigma-like, behavioral |

## Rule Inventory

| Rule ID | Engine | Name | Severity | Confidence | Technique | Datasource |
| --- | --- | --- | --- | --- | --- | --- |
| det.t1059_001.powershell_process_start | native | PowerShell Process Execution | medium | high | T1059.001 PowerShell | windows.sysmon_operational / 1 |
| det.t1105.lolbin_download | native | T1105 LOLBin Download Marker | medium | medium | T1105 Ingress Tool Transfer | windows.sysmon_operational / 1/3/11 |
| det.t1547_001.registry_run_key_persistence | native | T1547.001 Registry Run Key Persistence Marker | high | high | T1547.001 Registry Run Keys / Startup Folder | windows.sysmon_operational / 13 |
| det.t1218.lolbin_suspicious_execution | native | T1218 LOLBin Suspicious Execution Marker | medium | medium | T1218 System Binary Proxy Execution | windows.sysmon_operational / 1 |
| sigma_like.t1059_001.powershell_process_start | sigma-like | PowerShell Process Execution | medium | high | T1059.001 PowerShell | windows.sysmon_operational / 1 |
| sigma_like.t1105.lolbin_download | sigma-like | T1105 LOLBin Download Marker | medium | medium | T1105 Ingress Tool Transfer | windows.sysmon_operational / 1 |
| sigma_like.t1218.lolbin_suspicious_execution | sigma-like | T1218 LOLBin Suspicious Execution Marker | medium | medium | T1218 System Binary Proxy Execution | windows.sysmon_operational / 1 |
| sigma_like.t1547_001.registry_run_key_persistence | sigma-like | T1547.001 Registry Run Key Persistence Marker | high | high | T1547.001 Registry Run Keys / Startup Folder | windows.sysmon_operational / 13 |
| det.behavioral.t1105_download_sequence | behavioral | T1105 behavioral t1105 download sequence | high | high | T1105 Ingress Tool Transfer | windows.sysmon_operational / 1/3/11 |
| det.behavioral.t1547_001_registry_persistence_sequence | behavioral | T1547.001 behavioral t1547 001 registry persistence sequence | high | high | T1547.001 Registry Run Keys / Startup Folder | windows.sysmon_operational / 1/13 |
| det.behavioral.t1218_lolbin_sequence | behavioral | T1218 behavioral t1218 lolbin sequence | medium | medium | T1218 System Binary Proxy Execution | windows.sysmon_operational / 1/3/11 |

## Deterministic Fixture Validation

| Fixture | Engine | Normalized Events | Expected Alerts | Actual Alerts | Passed |
| --- | --- | --- | --- | --- | --- |
| sysmon_event_1_process_create.xml | all | 1 | 2 | 2 | true |
| behavioral_sequence_samples | behavioral | 6 | 3 | 3 | true |

## Acceptance Result

Deterministic validation passed: true

## Scope Boundaries

- Fixture validation covers `T1059.001` single-event native and Sigma-like rules.
- Behavioral validation covers deterministic local `T1105`, `T1547.001`, and `T1218-lite` sequences.
- The report command does not write normalized events.
- The report command does not write alerts.
- Elasticsearch alert counts are optional.
- Kafka, ML, SOAR, TheHive, graph analytics, streaming state, full SigmaHQ import, and production containment are out of scope.
