Status: done

# Static EDR operator dashboard UI

## Goal

Create a local EDR-like operator dashboard UI for the final teacher demo.

The dashboard should make the existing deterministic demo evidence easy to explain through visual panels:

- Summary cards.
- Alert charts.
- TP/TN/FP/FN case matrix.
- Recent alert table.
- Clickable alert detail and investigation panel.
- Short explanation sidebar for teacher-facing narration.

This phase is visualization only. It must not add detection rules or change detection, ML, behavioral correlation, SOAR, protection, or reporting semantics.

## Context

Current project capabilities and evidence:

- `reports/demo_cases/dashboard_data.json`
- `reports/demo_cases/case_matrix.json`
- `reports/final_demo_report.json`
- `reports/detection_coverage_report.json`
- ATT&CK Navigator layer export.
- `11` detection rules.
- `4` covered ATT&CK techniques.
- Demo matrix snapshot: `TP=12`, `TN=6`, `FP=1`, `FN=1`.
- `correlated_sequence_count=2`.
- Sysmon Event ID `1`, `3`, `11`, and `13` normalization.
- Native, Sigma-like, ML anomaly, and behavioral detection engines.

The project domain describes the EDR learning pipeline as:

```text
collection -> normalization -> detection -> correlation -> response -> reporting
```

This dashboard sits on top of the reporting/demo evidence layer. It should present what already exists; it should not introduce new analysis behavior.

## Problem

The project has generated dashboard data and reports, but it does not yet have a visual EDR-style interface for the final teacher demo.

Without a static dashboard, the demo depends on reading JSON/Markdown reports directly. That is accurate, but not ideal for explaining attack simulation results quickly on a projector. The final demo needs a lightweight SOC/EDR console where the same deterministic evidence can be explored through panels, charts, tables, and detail views.

## What to build

Create:

- `dashboard/static/index.html`
- `dashboard/static/app.js`
- `dashboard/static/styles.css`
- `dashboard/static/README.md`
- `scripts/demo/export_static_dashboard_data.py`
- `tests/test_static_edr_dashboard.py`
- `docs/edr_operator_dashboard_demo.md`

Generated static dashboard data should be written to:

- `dashboard/static/data/dashboard_data.json`
- `dashboard/static/data/case_matrix.json`
- `dashboard/static/data/final_demo_report.json`
- `dashboard/static/data/detection_coverage_report.json`

The dashboard must run with no build step, no npm, no internet, and no external CDN.

Supported local run modes:

```powershell
python scripts\demo\export_static_dashboard_data.py
python -m http.server 8088 -d dashboard/static
```

It should also be reasonable to open `dashboard/static/index.html` directly when the browser allows local JSON loading. The documented, reliable path should be the local Python server.

## Technical Design

### Static App Shape

Build a pure static HTML/CSS/JS app:

- `index.html` defines semantic regions and empty mount points.
- `styles.css` owns the dark EDR/SOC visual language and responsive layout.
- `app.js` loads local JSON, normalizes view-model data, renders panels, and handles row-click detail state.

No framework should be introduced for this phase.

Best practice: keep data shaping functions separate from DOM rendering functions inside `app.js`.

Example structure:

```javascript
async function loadJson(path) {
  const response = await fetch(path);

  if (!response.ok) {
    throw new Error(`Failed to load ${path}: ${response.status}`);
  }

  return response.json();
}

function countBy(items, getKey) {
  return items.reduce((acc, item) => {
    const key = getKey(item) || "unknown";
    acc[key] = (acc[key] || 0) + 1;
    return acc;
  }, {});
}

function renderAlertDetail(alert, matrixEntry) {
  // Show the existing evidence and classification explanation.
  // Do not recompute detection semantics here.
}
```

Trade-off: vanilla JS means more manual DOM code than React, but it keeps this phase dependency-free, deterministic, and easy to open on a school/demo machine.

### Header

The first screen should clearly identify the project:

- Project name: `EDR Advanced Operator Dashboard`
- Project status from the report/dashboard data where available.
- Last generated timestamp from exported data where available.
- Badge: `Local deterministic demo`.

The header must avoid production claims. This is a local demo dashboard, not a production EDR console.

### Summary Cards

Render compact cards for:

- Total demo cases.
- Total alerts.
- Detection rules.
- Covered ATT&CK techniques.
- `TP/TN/FP/FN`.
- Correlated sequences.

Use the existing reports as the source of truth:

- Prefer explicit totals from `dashboard_data.json`.
- Fall back to computed totals only for display convenience.
- Do not hide `FP` or `FN`.

### Alert by ATT&CK Technique

Render a simple bar chart or proportional list for techniques:

- `T1059.001`
- `T1105`
- `T1547.001`
- `T1218`

Use `attack.technique.id`, `technique_id`, or existing dashboard aggregation fields. Keep labels visible enough for a `1366x768` projector.

### Alert by Detection Engine

Render a chart/list for:

- `native`
- `sigma-like`
- `ml-anomaly`
- `behavioral`

Do not infer new engine semantics. Only group the exported alert/demo data.

### Severity Distribution

Render severity counts when severity exists:

- `low`
- `medium`
- `high`
- `critical`

If some alerts do not have severity, group them as `unknown` or show a small note in the panel. Do not fail the dashboard because an optional severity field is missing.

### Sysmon Event ID Evidence

Show Sysmon Event IDs as evidence categories:

- Event ID `1`: process creation.
- Event ID `3`: network connection.
- Event ID `11`: file creation.
- Event ID `13`: registry value set.

Use available fields such as `event.code`, `event_code`, or normalized equivalents.

### TP/TN/FP/FN Case Matrix

Render the case matrix with counts and short explanations:

- `TP`: expected malicious and alert fired.
- `TN`: expected benign and no alert fired.
- `FP`: expected benign but alert fired.
- `FN`: expected malicious but no alert fired.

False positives and false negatives must remain visible. The dashboard should treat them as honest demo evidence, not as UI errors.

### Recent Alerts Table

Create a table with these columns:

- `case_id`
- `classification`
- `rule_id`
- `technique_id`
- `engine`
- `severity`
- `process`
- `event_code`
- `expected_malicious`
- `alert_count`

Rows should be clickable. The selected row should update the alert detail/investigation panel without navigating away.

Implementation note: use stable fallback display values like `-` for missing optional fields. Do not crash rendering when one row is sparse.

### Alert Detail / Investigation Panel

When clicking a row, show:

- Rule ID.
- Technique.
- Engine.
- Matched fields.
- Source log fields.
- Why this alert fired.
- TP/TN/FP/FN explanation.
- Related Sysmon Event IDs.

This panel should explain existing results only. It must not run detection logic in the browser.

Example data-shaping helper:

```javascript
function explainClassification(row) {
  if (row.classification === "TP") {
    return "Expected malicious and at least one alert fired.";
  }

  if (row.classification === "TN") {
    return "Expected benign and no alert fired.";
  }

  if (row.classification === "FP") {
    return "Expected benign but an alert fired. Keep visible for demo honesty.";
  }

  if (row.classification === "FN") {
    return "Expected malicious but no alert fired. Keep visible for coverage discussion.";
  }

  return "Classification was not available in the exported case matrix.";
}
```

### Explanation Sidebar

Include short teacher-facing explanation text for:

- What each panel means.
- Which fields are used.
- Why Sysmon is used.
- How rules map to ATT&CK.
- How `TP/TN/FP/FN` are classified.

Keep the text concise. The dashboard is a demo console first, not a documentation page.

### Responsive Layout

Target a `1366x768` projector first, with acceptable behavior on narrower screens.

Recommended layout:

- Header at top.
- Summary cards in a compact responsive grid.
- Charts in a two or three column grid.
- Table and detail panel as the main lower section.
- Sidebar collapses below or stacks on smaller widths.

Best practice: avoid overly tall hero sections. This is an operator dashboard, so the first viewport should show real data immediately.

### Styling

Use a dark EDR/SOC theme:

- Dark neutral background.
- High contrast text.
- Muted grid lines.
- Distinct colors for severity/classification.
- Clear selected-row state.

Keep it professional and readable. Avoid external fonts, CDN icons, or image dependencies.

Trade-off: CSS/SVG/HTML charts are less interactive than a charting library, but they preserve the no-internet/no-npm requirement.

## Data Export Script

Create `scripts/demo/export_static_dashboard_data.py`.

It should:

- Read `reports/demo_cases/dashboard_data.json`.
- Read `reports/demo_cases/case_matrix.json`.
- Read `reports/final_demo_report.json`.
- Read `reports/detection_coverage_report.json`.
- Write copies or simplified normalized JSON into `dashboard/static/data/`.
- Create the output directory if missing.
- Print output paths.
- Fail with a clear message if any required report is missing.

CLI:

```powershell
python scripts\demo\export_static_dashboard_data.py
```

Suggested implementation shape:

```python
from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SOURCES = {
    "dashboard_data.json": ROOT / "reports/demo_cases/dashboard_data.json",
    "case_matrix.json": ROOT / "reports/demo_cases/case_matrix.json",
    "final_demo_report.json": ROOT / "reports/final_demo_report.json",
    "detection_coverage_report.json": ROOT / "reports/detection_coverage_report.json",
}
OUTPUT_DIR = ROOT / "dashboard/static/data"


def read_json(path: Path) -> object:
    if not path.exists():
        raise FileNotFoundError(
            f"Required dashboard source report is missing: {path}"
        )

    return json.loads(path.read_text(encoding="utf-8"))


def export_static_dashboard_data(output_dir: Path = OUTPUT_DIR) -> list[Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    written = []

    for filename, source in SOURCES.items():
        data = read_json(source)
        target = output_dir / filename
        target.write_text(
            json.dumps(data, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        written.append(target)

    return written
```

Tests may call `export_static_dashboard_data(output_dir=temp_path / "static" / "data")` to avoid writing into the real dashboard directory.

Best practice: keep the script as a copy/normalization layer only. It should not regenerate reports and should not recompute detection outcomes.

## Docs

Create `docs/edr_operator_dashboard_demo.md`.

Document:

- How to generate reports.
- How to export dashboard data.
- How to open the dashboard.
- How to run attack/simulation first.
- How to explain each panel.
- What fields each panel uses.
- Why Sysmon Event ID `1`, `3`, `11`, and `13` are used.
- How `TP/TN/FP/FN` are computed.
- Limitation: this is a local demo dashboard, not a production EDR console.

Required command examples:

```powershell
python scripts\demo\run_demo_case_matrix.py --output reports\demo_cases\case_matrix.json
python scripts\demo\generate_demo_dashboard_data.py --case-matrix reports\demo_cases\case_matrix.json --output reports\demo_cases\dashboard_data.json
python scripts\reporting\generate_detection_coverage_report.py
python scripts\reporting\generate_final_demo_report.py
python scripts\demo\export_static_dashboard_data.py
python -m http.server 8088 -d dashboard/static
```

Trade-off: the docs may repeat parts of the final demo rehearsal docs. That is acceptable because this page is dashboard-specific.

## Tests

Create `tests/test_static_edr_dashboard.py`.

Tests should inspect files and script behavior only. They must not require:

- Browser automation.
- Internet.
- Elasticsearch.
- Kibana.
- Docker.
- Kafka.
- Windows.
- Sysmon service.
- Atomic Red Team execution.

Cover:

- `dashboard/static/index.html` exists.
- `dashboard/static/app.js` exists.
- `dashboard/static/styles.css` exists.
- Dashboard mentions `EDR Advanced Operator Dashboard`.
- Dashboard includes sections for techniques, engines, severity, Sysmon Event IDs, case matrix, alert table, and alert detail.
- Dashboard docs mention `TP/TN/FP/FN`.
- Dashboard docs mention Sysmon Event ID `1`, `3`, `11`, and `13`.
- Export script writes required JSON files to a temp static data directory.
- `index.html` has no external CDN links.

Suggested test helper:

```python
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_dashboard_shell_mentions_required_sections() -> None:
    html = read("dashboard/static/index.html")
    app = read("dashboard/static/app.js")
    combined = f"{html}\n{app}"

    assert "EDR Advanced Operator Dashboard" in combined
    assert "ATT&CK Technique" in combined
    assert "Detection Engine" in combined
    assert "Severity" in combined
    assert "Sysmon Event ID" in combined
    assert "Case Matrix" in combined
    assert "Recent Alerts" in combined
    assert "Alert Detail" in combined
```

Keep assertions strict enough to prevent missing panels, but resilient to copy changes.

## Commands

Focused test:

```powershell
python -m pytest tests\test_static_edr_dashboard.py
```

Full regression:

```powershell
python -m pytest tests --basetemp=.pytest_tmp_phase17
```

Data export:

```powershell
python scripts\demo\export_static_dashboard_data.py
```

Local dashboard server:

```powershell
python -m http.server 8088 -d dashboard/static
```

## Acceptance Criteria

- [ ] `dashboard/static/index.html` exists.
- [ ] `dashboard/static/app.js` exists.
- [ ] `dashboard/static/styles.css` exists.
- [ ] `dashboard/static/README.md` exists.
- [ ] `dashboard/static/index.html` loads only local assets and has no external CDN links.
- [ ] Dashboard header shows `EDR Advanced Operator Dashboard`.
- [ ] Dashboard header shows project status, last generated timestamp when available, and `Local deterministic demo`.
- [ ] Summary cards show total demo cases, total alerts, detection rules, covered ATT&CK techniques, `TP/TN/FP/FN`, and correlated sequences.
- [ ] Dashboard visualizes alerts by ATT&CK technique for `T1059.001`, `T1105`, `T1547.001`, and `T1218`.
- [ ] Dashboard visualizes alerts by detection engine for native, sigma-like, ML anomaly, and behavioral engines.
- [ ] Dashboard visualizes severity distribution when severity data is available.
- [ ] Dashboard shows Sysmon Event ID `1`, `3`, `11`, and `13` evidence categories.
- [ ] Dashboard shows TP/TN/FP/FN case matrix counts and explanations.
- [ ] Dashboard does not hide `FP` or `FN`.
- [ ] Recent alerts table includes `case_id`, `classification`, `rule_id`, `technique_id`, `engine`, `severity`, `process`, `event_code`, `expected_malicious`, and `alert_count`.
- [ ] Clicking a recent alert row updates an alert detail/investigation panel.
- [ ] Alert detail panel shows rule ID, technique, engine, matched fields, source log fields, why the alert fired, TP/TN/FP/FN explanation, and related Sysmon Event IDs.
- [ ] Explanation sidebar describes panel meaning, fields used, Sysmon usage, ATT&CK mapping, and TP/TN/FP/FN classification.
- [ ] UI is responsive enough for a `1366x768` projector.
- [ ] `scripts/demo/export_static_dashboard_data.py` exists.
- [ ] Export script reads the four required source reports.
- [ ] Export script writes the four required JSON files into `dashboard/static/data/`.
- [ ] Export script creates the output directory if missing.
- [ ] Export script prints output paths.
- [ ] Export script fails with a clear message if required reports are missing.
- [ ] `docs/edr_operator_dashboard_demo.md` exists.
- [ ] Dashboard docs explain report generation, dashboard data export, opening the dashboard, running attack/simulation first, panel meanings, fields used, Sysmon Event IDs, TP/TN/FP/FN, and local-demo limitations.
- [ ] `tests/test_static_edr_dashboard.py` exists.
- [ ] Focused dashboard tests pass with `python -m pytest tests\test_static_edr_dashboard.py`.
- [ ] Full regression passes with `python -m pytest tests --basetemp=.pytest_tmp_phase17`.
- [ ] The dashboard requires no npm, no build step, no internet, and no external CDN.
- [ ] Tests do not require browser automation, internet, Elasticsearch, Kibana, Docker, Windows, Sysmon, or Atomic Red Team.
- [ ] No new detection rules are added.
- [ ] Detection semantics remain unchanged.
- [ ] ML scoring remains unchanged.
- [ ] Behavioral correlation remains unchanged.
- [ ] SOAR behavior remains unchanged.
- [ ] Protection behavior remains unchanged.
- [ ] Reporting semantics remain unchanged except for copying/normalizing existing report data for static UI consumption.

## Blocked by

- `.scratch/phase-16-final-teacher-demo-package/issues/01-final-demo-rehearsal-and-submission-pack.md`

This blocker is already marked `Status: done`, so this issue can start immediately.

## Out-of-scope boundaries

- Do not add detection rules.
- Do not change detection semantics.
- Do not change ML scoring.
- Do not change behavioral correlation.
- Do not change SOAR behavior.
- Do not change protection behavior.
- Do not require internet.
- Do not require npm.
- Do not require live infrastructure.
- Do not require Elasticsearch, Kibana, Docker, Kafka, Windows, Sysmon, or Atomic Red Team for tests.
- Do not hide false positives.
- Do not hide false negatives.
- Do not claim this is a production EDR dashboard.
- Do not introduce real malware, credential dumping, destructive actions, or containment side effects.

## Implementation Notes

Recommended implementation flow:

```text
export_static_dashboard_data.py
  -> dashboard/static/data/*.json export
  -> index.html shell
  -> styles.css dark operator layout
  -> app.js data loading/rendering/detail state
  -> dashboard/static/README.md
  -> docs/edr_operator_dashboard_demo.md
  -> tests/test_static_edr_dashboard.py
```

Prefer small, deterministic functions:

- `loadJson(path)`
- `countBy(items, getKey)`
- `normalizeAlerts(dashboardData, caseMatrix)`
- `renderSummary(model)`
- `renderBarChart(container, rows)`
- `renderAlertsTable(rows)`
- `renderAlertDetail(row)`

Use fallback values for missing optional fields. Missing optional display fields should produce `-` or `unknown`, not a broken dashboard.

Use explicit error UI if required JSON cannot be loaded:

```javascript
function showError(error) {
  document.querySelector("#app-error").textContent =
    `Dashboard data could not be loaded: ${error.message}`;
}
```

The most important best practice for this phase: preserve the truth boundary. The dashboard should make existing evidence easier to explain, not make the project look more capable than the reports prove.

## Comments
