# Kibana Dashboard Validation

Phase 8 uses Kibana for manual evidence review. Tests do not require Kibana or saved object import.

## Level 1: Discover Validation

Create or select data views for:

- `edr-normalized-events-*`
- `edr-alerts-native-*`
- `edr-response-actions-*`

Useful filters:

- `event.dataset: windows.sysmon_operational`
- `event.code: 1`
- `process.name: powershell.exe`
- `rule.id: det.t1059_001.powershell_process_start`
- `rule.id: sigma_like.t1059_001.powershell_process_start`
- `detection.engine: ml-anomaly`
- `playbook.id: soar.playbook.powershell_execution`

Recommended evidence screenshots:

- Normalized Sysmon Event ID 1 document.
- Native PowerShell alert.
- Sigma-like PowerShell alert.
- ML anomaly alert, when the JSON demo case is run.
- SOAR dry-run response action.

## Level 2: Optional Dashboard Panels

Useful panels:

- Normalized events over time.
- Alert count by `rule.id`.
- Alert count by `detection.engine`.
- Response count by `playbook.id`.
- Recent alerts table.
- Recent response actions table.

Optional saved objects may live at:

```text
kibana/saved_objects/edr_demo_dashboard.ndjson
```

Saved object import is optional and must not be required for automated tests.

