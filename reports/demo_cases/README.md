# Demo Case Reports

Phase 9 demo reports live in this directory. Phase 14 behavioral sequence cases are included in the same matrix.

## Artifacts

- `case_matrix.json`: machine-readable run result for every demo case, including expected vs actual alert behavior, TP/TN/FP/FN classification, alert rule IDs, engines, response counts, and indexing counts.
- `case_matrix.md`: teacher-friendly Markdown table for live walkthrough.
- `dashboard_data.json`: compact aggregate data for dashboard panels, including classification counts, alerts by rule, alerts by engine, correlated sequence count, response count, protection count, and case rows.

## Regenerate

```powershell
python scripts\demo\run_demo_case_matrix.py --output reports\demo_cases\case_matrix.json
python scripts\demo\generate_demo_dashboard_data.py --case-matrix reports\demo_cases\case_matrix.json --output reports\demo_cases\dashboard_data.json
```

Optional live indexing:

```powershell
python scripts\demo\run_demo_case_matrix.py --output reports\demo_cases\case_matrix.json --write-events --write-alerts --write-response --elasticsearch-url http://localhost:9200
```

## Teacher Demo Evidence

Use these files:

- `case_matrix.md` for the walkthrough.
- `dashboard_data.json` for TP/TN/FP/FN counts.
- Kibana Discover screenshots for `edr-normalized-events-*`, `edr-alerts-native-*`, and `edr-response-actions-*`.

False positives and false negatives are intentionally visible. They show the current MVP's detection trade-offs and coverage limits instead of hiding them.
