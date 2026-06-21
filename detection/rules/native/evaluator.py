"""Evaluate native detection rules against normalized ECS events."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class MatchResult:
    """Result of evaluating one native rule against one event."""

    matched: bool
    rule_id: str
    matched_fields: tuple[str, ...]


def evaluate_rule(rule: dict[str, Any], event: dict[str, Any]) -> MatchResult:
    """Evaluate a native rule against one normalized ECS event."""

    rule_id = str(rule.get("id", ""))
    if not _is_supported_data_source(rule, event):
        return MatchResult(matched=False, rule_id=rule_id, matched_fields=())

    matched_fields: list[str] = []
    for condition in rule.get("match", {}).get("any", []):
        if not isinstance(condition, dict):
            continue
        field = condition.get("field")
        if not isinstance(field, str):
            continue

        value = _get_field(event, field)
        if value is None:
            continue

        if _condition_matches(condition, str(value)):
            matched_fields.append(field)

    return MatchResult(matched=bool(matched_fields), rule_id=rule_id, matched_fields=tuple(matched_fields))


def _is_supported_data_source(rule: dict[str, Any], event: dict[str, Any]) -> bool:
    data_source = rule.get("data_source", {})
    event_meta = event.get("event", {})

    if not isinstance(data_source, dict) or not isinstance(event_meta, dict):
        return False

    return (
        event_meta.get("dataset") == data_source.get("event_dataset")
        and event_meta.get("code") == data_source.get("event_code")
    )


def _condition_matches(condition: dict[str, Any], value: str) -> bool:
    normalized_value = value.casefold()

    if "equals_any" in condition:
        return any(normalized_value == expected.casefold() for expected in _string_values(condition["equals_any"]))

    if "endswith_any" in condition:
        return any(normalized_value.endswith(expected.casefold()) for expected in _string_values(condition["endswith_any"]))

    if "contains_any" in condition:
        return any(expected.casefold() in normalized_value for expected in _string_values(condition["contains_any"]))

    return False


def _string_values(values: Any) -> list[str]:
    if not isinstance(values, list):
        return []
    return [value for value in values if isinstance(value, str)]


def _get_field(event: dict[str, Any], field_path: str) -> Any:
    current: Any = event
    for part in field_path.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current
