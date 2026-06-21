"""Build a local evidence bundle for the Phase 8 VM attack demo."""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


DEFAULT_OUTPUT_DIR = REPO_ROOT / "reports" / "demo_evidence"

OPTIONAL_REPORTS = [
    REPO_ROOT / "reports" / "final_demo_report.json",
    REPO_ROOT / "reports" / "final_demo_report.md",
    REPO_ROOT / "reports" / "detection_coverage_report.json",
    REPO_ROOT / "reports" / "detection_coverage_report.md",
    REPO_ROOT / "reports" / "attack_navigator" / "edr_attack_layer.json",
    REPO_ROOT / "reports" / "attack_navigator" / "coverage_summary.md",
]

CHECKLIST_PATH = REPO_ROOT / "docs" / "demo_evidence_checklist.md"
COMMAND_LOG_NAME = "command_log_template.md"


class DemoEvidenceBundleError(RuntimeError):
    """Raised for predictable evidence bundle failures."""


def build_demo_evidence_bundle(*, output_dir: Path = DEFAULT_OUTPUT_DIR) -> dict[str, Any]:
    """Create a deterministic local evidence bundle manifest."""

    output_dir.mkdir(parents=True, exist_ok=True)

    included_files: list[str] = []
    missing_optional_files: list[str] = []

    for source in OPTIONAL_REPORTS:
        if source.exists():
            included_files.append(_copy_into_bundle(source, output_dir))
        else:
            missing_optional_files.append(_relative(source))

    if CHECKLIST_PATH.exists():
        included_files.append(_copy_into_bundle(CHECKLIST_PATH, output_dir))
    else:
        missing_optional_files.append(_relative(CHECKLIST_PATH))

    command_log_path = output_dir / COMMAND_LOG_NAME
    command_log_path.write_text(_command_log_template(), encoding="utf-8")
    included_files.append(COMMAND_LOG_NAME)

    manifest = {
        "generated_at": _now(),
        "included_files": included_files,
        "missing_optional_files": missing_optional_files,
    }
    manifest_path = output_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    included_files.append("manifest.json")
    manifest["included_files"] = included_files
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")

    return manifest


def render_result(manifest: dict[str, Any]) -> str:
    lines = [
        "Demo evidence bundle",
        f"Generated at: {manifest['generated_at']}",
        f"Included files: {len(manifest['included_files'])}",
        f"Missing optional files: {len(manifest['missing_optional_files'])}",
    ]
    for filename in manifest["included_files"]:
        lines.append(f"- {filename}")
    return "\n".join(lines)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build the Phase 8 demo evidence bundle.")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])
    try:
        manifest = build_demo_evidence_bundle(output_dir=args.output_dir)
    except OSError as exc:
        print(f"Evidence bundle failed: {exc}", file=sys.stderr)
        return 2

    print(render_result(manifest))
    return 0


def _copy_into_bundle(source: Path, output_dir: Path) -> str:
    target = output_dir / source.name
    shutil.copy2(source, target)
    return target.name


def _command_log_template() -> str:
    return """# Demo Command Log Template

Record commands and observations during the live VM demo. This template is not generated from executed commands.

| Step | Command | Expected result | Observed result | Notes |
| --- | --- | --- | --- | --- |
| Sysmon service check |  | Sysmon service is running |  |  |
| Atomic Red Team T1059.001 |  | Safe lab test executed |  |  |
| XML export |  | Sysmon Event ID 1 XML saved |  |  |
| Demo validation CLI |  | Native and Sigma-like alerts produced |  |  |
| SOAR dry-run |  | Planned response record created |  |  |
| Kibana validation |  | Discover/dashboard evidence captured |  |  |
"""


def _relative(path: Path) -> str:
    try:
        return str(path.relative_to(REPO_ROOT))
    except ValueError:
        return str(path)


def _now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


if __name__ == "__main__":
    raise SystemExit(main())
