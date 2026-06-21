"""Evaluate Sigma-like rules against normalized ECS events."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from detection.rules.demo_semantics import (
    match_t1105_lolbin_download,
    match_t1218_lolbin_suspicious,
    match_t1547_registry_run_key,
)


@dataclass(frozen=True)
class SigmaLikeMatchResult:
    """Result of evaluating one Sigma-like rule against one event."""

    matched: bool
    rule_id: str
    matched_fields: tuple[str, ...]
    engine: str = "sigma-like"


def evaluate_sigma_like_rule(rule: dict[str, Any], event: dict[str, Any]) -> SigmaLikeMatchResult:
    """Evaluate a Sigma-like rule against one normalized ECS event."""

    rule_id = str(rule.get("id", ""))
    custom_matcher = _CUSTOM_MATCHERS.get(rule_id)
    if custom_matcher is not None:
        matched, matched_fields = custom_matcher(event)
        return SigmaLikeMatchResult(matched=matched, rule_id=rule_id, matched_fields=matched_fields)

    selection = rule.get("detection", {}).get("selection", {})
    if not isinstance(selection, dict):
        return SigmaLikeMatchResult(matched=False, rule_id=rule_id, matched_fields=())

    if not _hard_gate_matches(selection, event):
        return SigmaLikeMatchResult(matched=False, rule_id=rule_id, matched_fields=())

    matched_fields: list[str] = []
    for key, expected in selection.items():
        field, operator = _split_selection_key(key)
        if operator is None:
            continue

        value = _get_field(event, field)
        if value is None:
            continue
        if _operator_matches(operator, str(value), expected):
            matched_fields.append(field)

    return SigmaLikeMatchResult(matched=bool(matched_fields), rule_id=rule_id, matched_fields=tuple(matched_fields))


def _hard_gate_matches(selection: dict[str, Any], event: dict[str, Any]) -> bool:
    return (
        _get_field(event, "event.dataset") == selection.get("event.dataset")
        and _get_field(event, "event.code") == selection.get("event.code")
    )


def _operator_matches(operator: str, value: str, expected: Any) -> bool:
    values = [item for item in expected if isinstance(item, str)] if isinstance(expected, list) else []
    normalized_value = value.casefold()

    if operator == "equals":
        return any(normalized_value == item.casefold() for item in values)

    if operator == "endswith":
        return any(normalized_value.endswith(item.casefold()) for item in values)

    if operator == "contains":
        return any(item.casefold() in normalized_value for item in values)

    return False


def _split_selection_key(key: str) -> tuple[str, str | None]:
    field, separator, operator = key.partition("|")
    return field, operator if separator else None


def _get_field(event: dict[str, Any], field_path: str) -> Any:
    current: Any = event
    for part in field_path.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


_CUSTOM_MATCHERS = {
    "sigma_like.t1105.lolbin_download": match_t1105_lolbin_download,
    "sigma_like.t1547_001.registry_run_key_persistence": match_t1547_registry_run_key,
    "sigma_like.t1218.lolbin_suspicious_execution": match_t1218_lolbin_suspicious,
}
