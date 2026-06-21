"""Sigma-like detection rules for the detection layer."""

from detection.rules.sigma_like.alerts import SigmaLikeAlertError, build_sigma_like_alert_document
from detection.rules.sigma_like.evaluator import SigmaLikeMatchResult, evaluate_sigma_like_rule
from detection.rules.sigma_like.loader import (
    SigmaLikeRuleValidationError,
    load_sigma_like_rule,
    load_sigma_like_rules,
    validate_sigma_like_rule,
)
from detection.rules.sigma_like.registry import build_sigma_like_alerts

__all__ = [
    "SigmaLikeAlertError",
    "SigmaLikeMatchResult",
    "SigmaLikeRuleValidationError",
    "build_sigma_like_alert_document",
    "build_sigma_like_alerts",
    "evaluate_sigma_like_rule",
    "load_sigma_like_rule",
    "load_sigma_like_rules",
    "validate_sigma_like_rule",
]
