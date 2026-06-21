"""Load and validate local process anomaly baseline profiles."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


DEFAULT_BASELINE_PATH = Path(__file__).parent / "baselines" / "process_baseline.json"


class ProcessBaselineError(ValueError):
    """Raised when a process anomaly baseline is invalid."""


def load_process_baseline(path: Path | str | None = None) -> dict[str, Any]:
    """Load and validate the local process anomaly baseline profile."""

    baseline_path = Path(path) if path is not None else DEFAULT_BASELINE_PATH
    try:
        parsed = json.loads(baseline_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ProcessBaselineError(f"Could not read process baseline {baseline_path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ProcessBaselineError(f"Process baseline JSON is malformed: {exc}") from exc

    if not isinstance(parsed, dict):
        raise ProcessBaselineError("Process baseline must be a JSON object.")

    return validate_process_baseline(parsed)


def validate_process_baseline(baseline: dict[str, Any]) -> dict[str, Any]:
    """Validate baseline fields and return the original baseline."""

    common_process_names = _require_string_list(baseline, "common_process_names")
    baseline["common_process_names"] = [item.lower() for item in common_process_names]

    pairs = baseline.get("allowed_parent_child_pairs")
    if not isinstance(pairs, list) or not pairs:
        raise ProcessBaselineError("Baseline field 'allowed_parent_child_pairs' must be a non-empty list.")
    for index, pair in enumerate(pairs):
        if not isinstance(pair, dict):
            raise ProcessBaselineError(f"allowed_parent_child_pairs[{index}] must be a mapping.")
        parent = pair.get("parent")
        child = pair.get("child")
        if not isinstance(parent, str) or not parent or not isinstance(child, str) or not child:
            raise ProcessBaselineError(
                f"allowed_parent_child_pairs[{index}] must contain non-empty parent and child strings."
            )
        pair["parent"] = parent.lower()
        pair["child"] = child.lower()

    _require_positive_number(baseline, "max_command_line_length")
    _require_positive_number(baseline, "max_args_count")
    suspicious_keywords = _require_string_list(baseline, "suspicious_keywords")
    baseline["suspicious_keywords"] = [item.lower() for item in suspicious_keywords]

    normal_hours = baseline.get("normal_hours")
    if normal_hours is not None:
        if not isinstance(normal_hours, list):
            raise ProcessBaselineError("Baseline field 'normal_hours' must be a list of integers.")
        for hour in normal_hours:
            if not isinstance(hour, int) or hour < 0 or hour > 23:
                raise ProcessBaselineError("Baseline field 'normal_hours' must contain integers from 0 to 23.")

    return baseline


def _require_string_list(parent: dict[str, Any], key: str) -> list[str]:
    value = parent.get(key)
    if not isinstance(value, list) or not value:
        raise ProcessBaselineError(f"Baseline field {key!r} must be a non-empty list.")
    if not all(isinstance(item, str) and item for item in value):
        raise ProcessBaselineError(f"Baseline field {key!r} must contain non-empty strings.")
    return value


def _require_positive_number(parent: dict[str, Any], key: str) -> int | float:
    value = parent.get(key)
    if not isinstance(value, (int, float)) or value <= 0:
        raise ProcessBaselineError(f"Baseline field {key!r} must be a positive number.")
    return value
