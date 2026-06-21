# EDR Advanced Operator Dashboard

This directory contains a pure static dashboard for the final local EDR demo.

It visualizes existing generated evidence only:

- `reports/demo_cases/dashboard_data.json`
- `reports/demo_cases/case_matrix.json`
- `reports/final_demo_report.json`
- `reports/detection_coverage_report.json`

The dashboard does not run detection logic, change detection semantics, call live infrastructure, or claim to be a production EDR console. It should not claim to be a production EDR console.

## Export Data

From the repository root:

```powershell
python scripts\demo\export_static_dashboard_data.py
```

This writes:

- `dashboard/static/data/dashboard_data.json`
- `dashboard/static/data/case_matrix.json`
- `dashboard/static/data/final_demo_report.json`
- `dashboard/static/data/detection_coverage_report.json`

## Run Locally

Reliable local server mode:

```powershell
python -m http.server 8088 -d dashboard/static
```

Then open:

```text
http://localhost:8088
```

Opening `dashboard/static/index.html` directly may work in browsers that allow local JSON loading, but the Python HTTP server is the recommended path.

## Requirements

- No npm.
- No build step.
- No internet.
- No external CDN.
- No external fonts.
- No framework dependency.

This is a local deterministic demo dashboard for explaining TP/TN/FP/FN, ATT&CK mapping, detection engines, and Sysmon Event ID 1/3/11/13 evidence.
