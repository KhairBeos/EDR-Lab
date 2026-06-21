"""TP/TN/FP/FN classification helpers for demo cases."""

from __future__ import annotations

from typing import Any


CLASSIFICATIONS = ("true_positive", "true_negative", "false_positive", "false_negative")


def classify_case(*, expected_alert: bool, actual_alert: bool) -> str:
    """Classify one demo case from expected and actual alert presence."""

    if expected_alert and actual_alert:
        return "true_positive"
    if not expected_alert and not actual_alert:
        return "true_negative"
    if not expected_alert and actual_alert:
        return "false_positive"
    return "false_negative"


def summarize_classifications(case_results: list[dict[str, Any]]) -> dict[str, int]:
    """Count TP/TN/FP/FN values in case result rows."""

    counts = {f"{name}_count": 0 for name in CLASSIFICATIONS}
    for result in case_results:
        classification = result.get("classification")
        key = f"{classification}_count"
        if key in counts:
            counts[key] += 1
    return counts

