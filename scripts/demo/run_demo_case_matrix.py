"""Generate the Phase 9 multi-case demo matrix."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from detection.demo.case_catalog import DemoCaseCatalogError
from detection.demo.case_runner import DEFAULT_OUTPUT, DemoCaseRunnerError, run_case_matrix, write_case_matrix
from scripts.lab_config import default_elasticsearch_url


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the Phase 9 EDR demo case matrix.")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--markdown-output", type=Path)
    parser.add_argument("--write-events", action="store_true")
    parser.add_argument("--write-alerts", action="store_true")
    parser.add_argument("--write-response", action="store_true")
    parser.add_argument("--elasticsearch-url", default=default_elasticsearch_url())
    parser.add_argument("--case-id", action="append", default=[])
    parser.add_argument("--include-failures", action=argparse.BooleanOptionalAction, default=True)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])
    try:
        matrix = run_case_matrix(
            case_ids=args.case_id,
            write_events=args.write_events,
            write_alerts=args.write_alerts,
            write_response=args.write_response,
            elasticsearch_url=args.elasticsearch_url,
            include_failures=args.include_failures,
        )
        write_case_matrix(matrix, output=args.output, markdown_output=args.markdown_output)
    except (DemoCaseCatalogError, DemoCaseRunnerError, OSError) as exc:
        print(f"Demo case matrix failed: {exc}", file=sys.stderr)
        return 2
    except (ValueError, KeyError, TypeError) as exc:
        print(f"Unexpected demo case matrix failure: {exc}", file=sys.stderr)
        return 3

    markdown_output = args.markdown_output or args.output.with_suffix(".md")
    print(f"Wrote case matrix JSON: {args.output}")
    print(f"Wrote case matrix Markdown: {markdown_output}")
    print(
        "Classifications: "
        f"TP={matrix['true_positive_count']} "
        f"TN={matrix['true_negative_count']} "
        f"FP={matrix['false_positive_count']} "
        f"FN={matrix['false_negative_count']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
