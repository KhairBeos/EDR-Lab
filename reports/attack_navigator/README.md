# ATT&CK Navigator Reports

This directory stores generated MITRE ATT&CK Navigator coverage artifacts for the local EDR demo.

Generated files:

- `edr_attack_layer.json`: Navigator-compatible Enterprise ATT&CK layer JSON.
- `coverage_summary.md`: local Markdown summary with scores, colors, rule IDs, engines, telemetry Event IDs, demo stats, and limitations.

Regenerate:

```powershell
python scripts\reporting\generate_attack_navigator_layer.py
```

Input reports:

- `reports/detection_coverage_report.json` required
- `reports/demo_cases/case_matrix.json` optional
- `reports/demo_cases/dashboard_data.json` optional
- `reports/final_demo_report.json` optional for project status

Manual import:

1. Open ATT&CK Navigator.
2. Import `edr_attack_layer.json`.
3. Use technique comments and metadata to explain the demo coverage.

Generation and tests do not require internet or live infrastructure.
