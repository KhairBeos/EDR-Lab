"""Deterministic heuristic scoring for process anomaly features."""

from __future__ import annotations

import re
from typing import Any


DEFAULT_THRESHOLD = 0.7

WEIGHTS = {
    "uncommon_process": 0.18,
    "unusual_parent_child": 0.20,
    "long_command_line": 0.12,
    "too_many_args": 0.10,
    "encoded_command": 0.25,
    "suspicious_keyword": 0.20,
    "unusual_executable_path": 0.12,
    "outside_normal_hours": 0.08,
}

NORMAL_WINDOWS_ROOTS = (
    "c:\\windows\\",
    "c:\\program files\\",
    "c:\\program files (x86)\\",
)


def score_process_features(
    features: dict[str, Any],
    baseline: dict[str, Any],
    threshold: float = DEFAULT_THRESHOLD,
) -> dict[str, Any]:
    """Return deterministic anomaly score metadata for extracted process features."""

    score = 0.0
    reasons: list[str] = []

    process_name = _lower(features.get("process_name"))
    parent_name = _lower(features.get("parent_process_name"))
    command_line = _lower(features.get("process_command_line"))
    executable = _lower(features.get("process_executable"))

    common_names = set(_lower_list(baseline.get("common_process_names")))
    if process_name and process_name not in common_names:
        score += WEIGHTS["uncommon_process"]
        reasons.append(f"process name is not common: {process_name}")

    allowed_pairs = {
        (_lower(pair.get("parent")), _lower(pair.get("child")))
        for pair in baseline.get("allowed_parent_child_pairs", [])
        if isinstance(pair, dict)
    }
    if parent_name and process_name and (parent_name, process_name) not in allowed_pairs:
        score += WEIGHTS["unusual_parent_child"]
        reasons.append(f"parent-child pair is unusual: {parent_name} -> {process_name}")

    command_line_length = _number(features.get("command_line_length"))
    max_command_line_length = _number(baseline.get("max_command_line_length"))
    if command_line_length > max_command_line_length:
        score += WEIGHTS["long_command_line"]
        reasons.append(
            f"command line length {int(command_line_length)} exceeds baseline {int(max_command_line_length)}"
        )

    args_count = _number(features.get("args_count"))
    max_args_count = _number(baseline.get("max_args_count"))
    if args_count > max_args_count:
        score += WEIGHTS["too_many_args"]
        reasons.append(f"args count {int(args_count)} exceeds baseline {int(max_args_count)}")

    if bool(features.get("has_encoded_command")):
        score += WEIGHTS["encoded_command"]
        reasons.append("encoded command flag present")

    for keyword in _lower_list(baseline.get("suspicious_keywords")):
        if _contains_keyword(command_line, keyword):
            score += WEIGHTS["suspicious_keyword"]
            reasons.append(f"suspicious keyword matched: {keyword}")
            break

    if executable and not executable.startswith(NORMAL_WINDOWS_ROOTS):
        score += WEIGHTS["unusual_executable_path"]
        reasons.append(f"executable path is unusual: {features.get('process_executable')}")

    normal_hours = baseline.get("normal_hours")
    hour_of_day = features.get("hour_of_day")
    if isinstance(normal_hours, list) and isinstance(hour_of_day, int) and hour_of_day not in normal_hours:
        score += WEIGHTS["outside_normal_hours"]
        reasons.append(f"hour {hour_of_day} is outside baseline normal hours")

    clamped_score = min(1.0, max(0.0, round(score, 4)))
    return {
        "score": clamped_score,
        "threshold": threshold,
        "is_anomaly": clamped_score >= threshold,
        "reasons": reasons,
    }


def _lower(value: Any) -> str:
    return value.lower() if isinstance(value, str) else ""


def _lower_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item.lower() for item in value if isinstance(item, str)]


def _number(value: Any) -> float:
    return float(value) if isinstance(value, (int, float)) else 0.0


def _contains_keyword(text: str, keyword: str) -> bool:
    if keyword in {"nc", "iwr", "irm"}:
        return re.search(rf"(?<![a-z0-9_-]){re.escape(keyword)}(?![a-z0-9_-])", text) is not None
    return keyword in text
