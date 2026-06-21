# Demo Dashboard Design

Phase 9 produces `reports/demo_cases/dashboard_data.json` for the 10-case TP/TN/FP/FN case matrix and uses Kibana to validate event, alert, response, and Phase 10 protection evidence.

## Data Sources

Case matrix counts:

- `reports/demo_cases/case_matrix.json`
- `reports/demo_cases/dashboard_data.json`

Kibana evidence indexes:

- `edr-normalized-events-*`
- `edr-alerts-native-*`
- `edr-response-actions-*`
- `edr-protection-actions-*`

If case metadata is not indexed into Elasticsearch yet, use `dashboard_data.json` as the source for TP/TN/FP/FN counts. Kibana validates the underlying normalized events, alert documents, dry-run response actions, and lab-only protection records.

## Panels

### TP/TN/FP/FN Count

Show four metric panels:

- `true_positive_count`
- `true_negative_count`
- `false_positive_count`
- `false_negative_count`

These values come from `dashboard_data.json`.

### Case Result Table

Table fields:

- `case_id`
- `name`
- `category`
- `technique_id`
- `classification`
- `expected_alert`
- `actual_alert`
- `alert_count`
- `actual_rule_ids`
- `actual_engines`
- `response_count`
- `expected_protection`
- `teacher_demo_notes`

### Alerts By Rule

Use `alert_count_by_rule` from `dashboard_data.json` or Kibana terms on:

- `rule.id`

Useful filters:

- `rule.id: det.t1059_001.powershell_process_start`
- `rule.id: sigma_like.t1059_001.powershell_process_start`
- `rule.id: ml.process_anomaly`

### Alerts By Detection Engine

Use `alert_count_by_engine` from `dashboard_data.json` or Kibana terms on:

- `detection.engine`

Native alerts may omit `detection.engine`; dashboard data normalizes them as `native`.

### Response Actions

Use `edr-response-actions-*` and fields:

- `response.status`
- `response.mode`
- `playbook.id`
- `alert.rule_id`

Expected status is planned dry-run response only.

### Protection Actions

Use `expected_protection` in `dashboard_data.json`:

- `none`
- `dry-run`
- `execute-lab-only`

`execute-lab-only` means guarded Phase 10 lab execution only. The safe default remains dry-run, and real kill-process execution requires both `--execute-protection` and `--lab-allow-execute`.

Validate Phase 10 protection records in `edr-protection-actions-*` with:

- `protection.action: kill_process`
- `protection.status`
- `protection.mode`
- `target.pid`
- `alert.rule_id`

No production containment is implemented. Protection evidence should be described as lab-only, safe-by-default demo evidence.

## Useful Kibana Fields

- `case.case_id`, if case metadata is indexed later.
- `rule.id`
- `detection.engine`
- `response.status`
- `playbook.id`
- `protection.status`
- `protection.mode`
- `protection.action`
- `event.dataset`
- `event.code`
- `process.name`

## Teacher Demo Flow

1. Generate the case matrix.
2. Generate dashboard data.
3. Open the Markdown matrix for explanation.
4. Use Kibana Discover to show normalized events, alerts, and response actions.
5. Use `edr-protection-actions-*` to show Phase 10 protection records when generated.
6. Explain TP/TN/FP/FN honestly, including why the FP and FN are useful learning evidence.
