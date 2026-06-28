# EDR Operator Dashboard Demo

## Purpose

The EDR Advanced Operator Dashboard is a local static UI for explaining the final teacher demo. It visualizes existing reports and demo case data; it is not a production EDR console and it does not run new detection logic.

The dashboard sits after the existing reporting flow:

```text
collection -> normalization -> detection -> correlation -> response -> reporting -> static dashboard
```

## Generate Reports

Run the deterministic report pipeline first:

```powershell
python scripts\demo\run_demo_case_matrix.py --output reports\demo_cases\case_matrix.json
python scripts\demo\generate_demo_dashboard_data.py --case-matrix reports\demo_cases\case_matrix.json --output reports\demo_cases\dashboard_data.json
python scripts\reporting\generate_detection_coverage_report.py
python scripts\reporting\generate_final_demo_report.py
```

These commands regenerate the existing source reports. They do not require Elasticsearch, Kibana, Docker, Windows, Sysmon service, or Atomic Red Team execution.

## Run Attack Or Simulation First

For the final demo, choose the path that matches the available lab environment:

- Deterministic local path: run the report commands above. This is the safest classroom fallback.
- Optional Windows VM path: execute the safe Atomic Red Team or manual marker workflow, export Sysmon XML, then run the existing validation/report commands.
- Optional live lab evidence: use Kibana screenshots only as supporting evidence, not as a dependency for this dashboard.

Keep protection actions dry-run unless an isolated lab execution is explicitly intended.

## Export Dashboard Data

Copy the generated report JSON into the static dashboard data directory:

```powershell
python scripts\demo\export_static_dashboard_data.py
```

The export writes:

- `dashboard/static/data/dashboard_data.json`
- `dashboard/static/data/case_matrix.json`
- `dashboard/static/data/final_demo_report.json`
- `dashboard/static/data/detection_coverage_report.json`

The export script is only a copy/normalization layer. It does not regenerate reports, recompute TP/TN/FP/FN, change ML scoring, or change behavioral correlation.

## Open Dashboard

Serve the static files:

```powershell
python -m http.server 8088 -d dashboard/static
```

Open:

```text
http://localhost:8088
```

Opening `dashboard/static/index.html` directly can work only when the browser allows local JSON loading. The Python HTTP server is the reliable path.

## Panel Guide

### Header

Shows `EDR Advanced Operator Dashboard`, project status from the final report, the last generated timestamp when available, and the `Local deterministic demo` badge.

### Summary Cards

Fields used:

- `dashboard_data.total_cases`
- sum of `dashboard_data.case_rows[].alert_count`
- `detection_coverage_report.engine_coverage_summary.total_rule_count`
- `detection_coverage_report.covered_techniques`
- `dashboard_data.true_positive_count`
- `dashboard_data.true_negative_count`
- `dashboard_data.false_positive_count`
- `dashboard_data.false_negative_count`
- `dashboard_data.correlated_sequence_count`
- `final_demo_report.capability_matrix[]` for SOAR/protection scope
- `final_demo_report.validation_results[]` for the SOAR dry-run fixture response
- `dashboard_data.protection_count`

Use these cards to give the teacher the demo scope before opening details.

### Response Scope

Shows the safety boundary for the response layer:

- `SOAR response`: dry-run planning only.
- `Protection mode`: lab-only dry-run by default.
- `Production containment`: not implemented.

Use this panel when the teacher asks whether the project actually blocks an attack. The correct explanation is that the dashboard demonstrates detection evidence and response planning, not production endpoint blocking. Protection evidence is kept as dry-run/lab-only records unless an isolated lab execution is explicitly intended.

### ATT&CK Technique

Uses `dashboard_data.alert_count_by_technique` and case `technique_id` fields. The expected final demo techniques are:

- `T1059.001`
- `T1105`
- `T1547.001`
- `T1218`

Explain that this is selected deterministic coverage, not full ATT&CK coverage.

### Detection Engine

Uses `dashboard_data.alert_count_by_engine` and existing row `actual_engines`.

Expected engines:

- `native`
- `sigma-like`
- `ml-anomaly`
- `behavioral`

The panel groups existing alerts only. It does not infer new engine semantics.

### Severity

Uses row severity when present, otherwise maps existing `actual_rule_ids` to `detection_coverage_report.rule_inventory[].severity`.

Expected buckets:

- `low`
- `medium`
- `high`
- `critical`
- `unknown`

Missing severity is displayed as `unknown` so sparse rows do not break the dashboard.

### Sysmon Event ID

Uses `event_code`, `event.code`, or normalized equivalent fields from the exported rows.

Why Sysmon Event ID 1, 3, 11, and 13 are used:

- Event ID 1: process creation, useful for PowerShell, rundll32, certutil, and parent/child process evidence.
- Event ID 3: network connection, useful for transfer and command-and-control style demo evidence.
- Event ID 11: file creation, useful for downloaded file or ingress transfer evidence.
- Event ID 13: registry value set, useful for Run key persistence evidence.

### Case Matrix

TP/TN/FP/FN are computed by comparing expected alert behavior with actual alert behavior:

- TP: expected malicious and alert fired.
- TN: expected benign and no alert fired.
- FP: expected benign but alert fired.
- FN: expected malicious but no alert fired.

Do not hide FP/FN. They are honest demo evidence and useful for discussing current coverage limits.

### Recent Alerts

The table uses:

- `case_id`
- `classification`
- `actual_rule_ids`
- `technique_id`
- `actual_engines`
- `severity`
- process/name fallback fields
- `event_code`
- `expected_protection`
- `expected_alert`
- `alert_count`

Rows include alerting and non-alerting cases so the matrix remains explainable.

### Alert Detail

Click a row to show:

- Rule ID.
- Technique.
- Engine.
- Matched fields.
- Source log fields.
- Why this alert fired.
- TP/TN/FP/FN explanation.
- Related Sysmon Event IDs.

This panel explains existing results only. It does not run detection logic in the browser.

## Demo Talk Track

1. Start with the summary cards to show project scope.
2. Use the ATT&CK technique and engine panels to connect detections to coverage.
3. Use Sysmon Event ID evidence to explain why endpoint telemetry matters.
4. Open the Case Matrix and explicitly mention TP/TN/FP/FN.
5. Point to Response Scope to clarify that SOAR/protection is dry-run/lab-only, not production blocking.
6. Click one TP, one FP, and one FN row in Recent Alerts.
7. Close by saying this is a local deterministic demo dashboard, not a production EDR console.

## Limitations

- Local static visualization only.
- No live endpoint telemetry.
- No browser-side detection engine.
- No production containment.
- No full enterprise ATT&CK coverage claim.
- No internet, npm, external CDN, or framework dependency.
