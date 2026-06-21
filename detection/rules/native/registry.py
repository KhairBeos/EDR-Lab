"""Native rule registry for YAML and Python-backed demo rules."""

from __future__ import annotations

import copy
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from detection.rules.native import t1105_lolbin_download, t1218_lolbin_suspicious, t1547_001_registry_run_key
from detection.rules.native.alerts import build_alert_document
from detection.rules.native.evaluator import MatchResult, evaluate_rule
from detection.rules.native.loader import load_rule


Matcher = Callable[[dict[str, Any]], tuple[bool, tuple[str, ...]]]
PYTHON_RULE_MODULES = (
    t1105_lolbin_download,
    t1547_001_registry_run_key,
    t1218_lolbin_suspicious,
)


@dataclass(frozen=True)
class NativeRuleSpec:
    """A native rule plus its optional Python matcher."""

    rule: dict[str, Any]
    matcher: Matcher | None = None


def load_native_rule_specs() -> list[NativeRuleSpec]:
    """Load the existing YAML rule and Phase 13 Python native rules."""

    specs = [NativeRuleSpec(rule=load_rule())]
    for module in PYTHON_RULE_MODULES:
        rule = copy.deepcopy(module.RULE)
        _validate_python_rule(rule)
        specs.append(NativeRuleSpec(rule=rule, matcher=module.match))
    return specs


def load_native_rules() -> list[dict[str, Any]]:
    """Return native rule metadata for reporting and tests."""

    return [spec.rule for spec in load_native_rule_specs()]


def evaluate_native_rule_spec(spec: NativeRuleSpec, event: dict[str, Any]) -> MatchResult:
    """Evaluate one native rule spec against one normalized ECS event."""

    if spec.matcher is None:
        return evaluate_rule(spec.rule, event)

    matched, matched_fields = spec.matcher(event)
    return MatchResult(matched=matched, rule_id=spec.rule["id"], matched_fields=matched_fields)


def build_native_alerts(
    *,
    event: dict[str, Any],
    source: dict[str, str] | None = None,
    specs: list[NativeRuleSpec] | None = None,
) -> list[dict[str, Any]]:
    """Evaluate all native rules and build alert documents for matches."""

    alerts: list[dict[str, Any]] = []
    for spec in specs or load_native_rule_specs():
        match = evaluate_native_rule_spec(spec, event)
        if match.matched:
            alerts.append(build_alert_document(match=match, rule=spec.rule, event=event, source=source))
    return alerts


def _validate_python_rule(rule: dict[str, Any]) -> None:
    for field in ("id", "name", "description", "severity", "confidence"):
        if not isinstance(rule.get(field), str) or not rule[field]:
            raise ValueError(f"Python native rule field {field!r} must be a non-empty string.")
    if not isinstance(rule.get("version"), int):
        raise ValueError("Python native rule field 'version' must be an integer.")
    attack = rule.get("attack")
    if not isinstance(attack, dict):
        raise ValueError("Python native rule field 'attack' must be a mapping.")
    for field in ("technique_id", "technique_name"):
        if not isinstance(attack.get(field), str) or not attack[field]:
            raise ValueError(f"Python native rule attack.{field} must be a non-empty string.")
    tactic = attack.get("tactic")
    if not isinstance(tactic, list) or not all(isinstance(item, str) and item for item in tactic):
        raise ValueError("Python native rule attack.tactic must contain non-empty strings.")
