"""Generate the ATT&CK Navigator coverage layer."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from reporting.attack_navigator_layer import (
    AttackNavigatorLayerError,
    build_attack_navigator_layer,
    build_coverage_summary_markdown,
    render_json_layer,
)


DEFAULT_COVERAGE_REPORT = Path("reports") / "detection_coverage_report.json"
DEFAULT_CASE_MATRIX = Path("reports") / "demo_cases" / "case_matrix.json"
DEFAULT_DASHBOARD_DATA = Path("reports") / "demo_cases" / "dashboard_data.json"
DEFAULT_FINAL_DEMO_REPORT = Path("reports") / "final_demo_report.json"
DEFAULT_LAYER_OUTPUT = Path("reports") / "attack_navigator" / "edr_attack_layer.json"
DEFAULT_MARKDOWN_OUTPUT = Path("reports") / "attack_navigator" / "coverage_summary.md"


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate a MITRE ATT&CK Navigator layer for EDR coverage.")
    parser.add_argument("--coverage-report", type=Path, default=DEFAULT_COVERAGE_REPORT)
    parser.add_argument("--case-matrix", type=Path, default=DEFAULT_CASE_MATRIX)
    parser.add_argument("--dashboard-data", type=Path, default=DEFAULT_DASHBOARD_DATA)
    parser.add_argument("--output", type=Path, default=DEFAULT_LAYER_OUTPUT)
    parser.add_argument("--markdown-output", type=Path, default=DEFAULT_MARKDOWN_OUTPUT)
    parser.add_argument("--project-status")
    parser.add_argument("--output-summary", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or [])

    try:
        coverage_report = read_required_json(args.coverage_report, label="coverage report")
        case_matrix = read_optional_json(args.case_matrix, label="case matrix")
        dashboard_data = read_optional_json(args.dashboard_data, label="dashboard data")
        project_status = args.project_status or read_project_status(DEFAULT_FINAL_DEMO_REPORT)

        enriched_coverage_report = dict(coverage_report)
        if case_matrix is not None:
            enriched_coverage_report["case_matrix"] = case_matrix
        if dashboard_data is not None:
            enriched_coverage_report["dashboard_data"] = dashboard_data

        layer = build_attack_navigator_layer(enriched_coverage_report)
        markdown = build_coverage_summary_markdown(
            coverage_report,
            layer,
            case_matrix=case_matrix,
            dashboard_data=dashboard_data,
            project_status=project_status,
        )

        write_text(args.output, render_json_layer(layer) + "\n")
        write_text(args.markdown_output, markdown)
    except AttackNavigatorLayerError as exc:
        print(f"ATT&CK Navigator layer failed: {exc}", file=sys.stderr)
        return 2
    except (OSError, json.JSONDecodeError, ValueError, TypeError) as exc:
        print(f"ATT&CK Navigator layer failed: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # pragma: no cover - defensive CLI boundary
        print(f"Unexpected ATT&CK Navigator layer failure: {exc}", file=sys.stderr)
        return 3

    print(render_operator_summary(layer, output_path=args.output, markdown_output_path=args.markdown_output))
    return 0


def read_required_json(path: Path, *, label: str) -> dict[str, Any]:
    if not path.exists():
        raise AttackNavigatorLayerError(f"Required {label} is missing: {path}")
    parsed = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(parsed, dict):
        raise AttackNavigatorLayerError(f"Required {label} must contain a JSON object: {path}")
    return parsed


def read_optional_json(path: Path, *, label: str) -> dict[str, Any] | None:
    if not path.exists():
        return None
    parsed = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(parsed, dict):
        raise AttackNavigatorLayerError(f"Optional {label} must contain a JSON object when present: {path}")
    return parsed


def read_project_status(path: Path = DEFAULT_FINAL_DEMO_REPORT) -> str | None:
    if not path.exists():
        return None
    parsed = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(parsed, dict):
        return None
    status = parsed.get("project_status")
    return str(status) if status else None


def write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def render_operator_summary(
    layer: dict[str, Any],
    *,
    output_path: Path,
    markdown_output_path: Path,
) -> str:
    techniques = layer.get("techniques", [])
    engines = {
        metadata["value"]
        for technique in techniques
        for metadata in technique.get("metadata", [])
        if metadata.get("name") == "engines"
    }
    rule_ids = {
        rule_id.strip()
        for technique in techniques
        for metadata in technique.get("metadata", [])
        if metadata.get("name") == "rule_ids"
        for rule_id in metadata.get("value", "").split(",")
        if rule_id.strip()
    }
    engine_values = {
        engine.strip()
        for engine_group in engines
        for engine in engine_group.split(",")
        if engine.strip()
    }

    return "\n".join(
        [
            "ATT&CK Navigator coverage layer",
            f"Technique count: {len(techniques)}",
            f"Engine count: {len(engine_values)}",
            f"Rule count: {len(rule_ids)}",
            "Written files:",
            f"- {output_path}",
            f"- {markdown_output_path}",
        ]
    )


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
