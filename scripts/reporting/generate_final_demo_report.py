"""Generate the final Phase 1-10 demo report artifacts."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from detection.kafka.consumer import KafkaConsumerError
from detection.rules.native.alert_indexer import AlertIndexingError
from reporting.detection_coverage import DetectionCoverageReportError
from reporting.final_demo_report import (
    FinalDemoReportError,
    build_final_demo_report,
    render_operator_summary,
    write_report_artifacts,
)
from scripts.lab_config import default_elasticsearch_url


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate the final EDR demo report.")
    parser.add_argument("--output-dir", type=Path, default=Path("reports"))
    parser.add_argument("--format", choices=("json", "markdown", "all"), default="all")
    parser.add_argument("--include-elasticsearch", action="store_true")
    parser.add_argument("--elasticsearch-url", default=default_elasticsearch_url())
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or [])

    try:
        report = build_final_demo_report(
            include_elasticsearch=args.include_elasticsearch,
            elasticsearch_url=args.elasticsearch_url,
        )
        written_paths = write_report_artifacts(
            report=report,
            output_dir=args.output_dir,
            output_format=args.format,
        )
    except (
        FinalDemoReportError,
        DetectionCoverageReportError,
        KafkaConsumerError,
        AlertIndexingError,
        OSError,
    ) as exc:
        print(f"Final demo report failed: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # pragma: no cover - defensive CLI boundary
        print(f"Unexpected final demo report failure: {exc}", file=sys.stderr)
        return 3

    print(render_operator_summary(report, written_paths))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
