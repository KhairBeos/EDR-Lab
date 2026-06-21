"""Generate the detection coverage report."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from reporting.detection_coverage import (
    DetectionCoverageReportError,
    build_detection_coverage_report,
    render_json_report,
    render_markdown_report,
    report_validation_passed,
)
from scripts.lab_config import default_elasticsearch_url


JSON_REPORT_NAME = "detection_coverage_report.json"
MARKDOWN_REPORT_NAME = "detection_coverage_report.md"


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate the EDR detection coverage report.")
    parser.add_argument("--output-dir", type=Path, default=Path("reports"))
    parser.add_argument("--format", choices=("json", "markdown", "all"), default="all")
    parser.add_argument("--include-elasticsearch", action="store_true")
    parser.add_argument("--elasticsearch-url", default=default_elasticsearch_url())
    parser.add_argument("--alert-index-pattern", default="edr-alerts-native-*")
    parser.add_argument("--engine", choices=("native", "sigma-like", "all"), default="all")
    return parser.parse_args(argv)


def write_report_files(*, report: dict, output_dir: Path, output_format: str) -> list[Path]:
    """Write selected report artifacts and return written paths."""

    output_dir.mkdir(parents=True, exist_ok=True)
    written_paths: list[Path] = []

    if output_format in {"json", "all"}:
        json_path = output_dir / JSON_REPORT_NAME
        json_path.write_text(render_json_report(report) + "\n", encoding="utf-8")
        written_paths.append(json_path)

    if output_format in {"markdown", "all"}:
        markdown_path = output_dir / MARKDOWN_REPORT_NAME
        markdown_path.write_text(render_markdown_report(report), encoding="utf-8")
        written_paths.append(markdown_path)

    return written_paths


def render_operator_summary(report: dict, written_paths: list[Path]) -> str:
    """Render a short command summary for operators."""

    summary = report["engine_coverage_summary"]
    validation_passed = report_validation_passed(report)
    lines = [
        "Detection coverage report",
        f"Project phase: {report['project_phase']}",
        f"Validation passed: {str(validation_passed).lower()}",
        f"Native rules: {summary['native_rule_count']}",
        f"Sigma-like rules: {summary['sigma_like_rule_count']}",
        f"Behavioral rules: {summary['behavioral_rule_count']}",
        f"Total rules: {summary['total_rule_count']}",
        "Written files:",
    ]
    lines.extend(f"- {path}" for path in written_paths)
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or [])

    try:
        report = build_detection_coverage_report(
            engine=args.engine,
            include_elasticsearch=args.include_elasticsearch,
            elasticsearch_url=args.elasticsearch_url,
            alert_index_pattern=args.alert_index_pattern,
        )
        written_paths = write_report_files(
            report=report,
            output_dir=args.output_dir,
            output_format=args.format,
        )
    except DetectionCoverageReportError as exc:
        print(f"Detection coverage report failed: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"Detection coverage report failed: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # pragma: no cover - defensive CLI boundary
        print(f"Unexpected detection coverage report failure: {exc}", file=sys.stderr)
        return 3

    print(render_operator_summary(report, written_paths))
    return 0 if report_validation_passed(report) else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
