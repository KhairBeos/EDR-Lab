"""Generate dashboard-ready data from a Phase 9 case matrix."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from detection.demo.case_runner import DemoCaseRunnerError, write_dashboard_data


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate dashboard data from a demo case matrix.")
    parser.add_argument("--case-matrix", type=Path, default=Path("reports") / "demo_cases" / "case_matrix.json")
    parser.add_argument("--output", type=Path, default=Path("reports") / "demo_cases" / "dashboard_data.json")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])
    try:
        data = write_dashboard_data(case_matrix_path=args.case_matrix, output=args.output)
    except (DemoCaseRunnerError, OSError) as exc:
        print(f"Dashboard data generation failed: {exc}", file=sys.stderr)
        return 2
    except (ValueError, KeyError, TypeError) as exc:
        print(f"Unexpected dashboard data failure: {exc}", file=sys.stderr)
        return 3

    print(f"Wrote dashboard data: {args.output}")
    print(
        "Dashboard counts: "
        f"total={data['total_cases']} "
        f"TP={data['true_positive_count']} "
        f"TN={data['true_negative_count']} "
        f"FP={data['false_positive_count']} "
        f"FN={data['false_negative_count']} "
        f"correlated_sequences={data.get('correlated_sequence_count', 0)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
