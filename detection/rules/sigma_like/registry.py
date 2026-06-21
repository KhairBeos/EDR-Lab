"""Sigma-like rule registry for deterministic demo rules."""

from __future__ import annotations

from typing import Any

from detection.rules.sigma_like.alerts import build_sigma_like_alert_document
from detection.rules.sigma_like.evaluator import evaluate_sigma_like_rule
from detection.rules.sigma_like.loader import load_sigma_like_rules


def build_sigma_like_alerts(
    *,
    event: dict[str, Any],
    source: dict[str, str] | None = None,
    rules: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Evaluate all Sigma-like rules and build alert documents for matches."""

    alerts: list[dict[str, Any]] = []
    for rule in rules or load_sigma_like_rules():
        match = evaluate_sigma_like_rule(rule, event)
        if match.matched:
            alerts.append(build_sigma_like_alert_document(match=match, rule=rule, event=event, source=source))
    return alerts
