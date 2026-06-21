"""Export existing demo reports for the static EDR operator dashboard."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
OUTPUT_DIR = ROOT / "dashboard" / "static" / "data"
SOURCES = {
    "dashboard_data.json": ROOT / "reports" / "demo_cases" / "dashboard_data.json",
    "case_matrix.json": ROOT / "reports" / "demo_cases" / "case_matrix.json",
    "final_demo_report.json": ROOT / "reports" / "final_demo_report.json",
    "detection_coverage_report.json": ROOT / "reports" / "detection_coverage_report.json",
}


class StaticDashboardExportError(RuntimeError):
    """Raised when required static dashboard source data cannot be exported."""


def read_required_json(path: Path) -> Any:
    if not path.exists():
        raise StaticDashboardExportError(f"Required dashboard source report is missing: {path}")

    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise StaticDashboardExportError(f"Required dashboard source report is not valid JSON: {path}") from exc


def export_static_dashboard_data(output_dir: Path = OUTPUT_DIR) -> list[Path]:
    """Copy the existing report JSON files into the static dashboard data directory."""

    output_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []

    for filename, source in SOURCES.items():
        data = read_required_json(source)
        target = output_dir / filename
        target.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        written.append(target)

    return written


def main() -> int:
    try:
        written = export_static_dashboard_data()
    except StaticDashboardExportError as exc:
        print(f"Static dashboard export failed: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"Static dashboard export failed while writing output: {exc}", file=sys.stderr)
        return 3

    for path in written:
        print(f"Wrote static dashboard data: {path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
