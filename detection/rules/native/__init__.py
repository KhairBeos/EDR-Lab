"""Native detection rules for the detection layer."""

from detection.rules.native.alerts import AlertDocumentError, build_alert_document
from detection.rules.native.elasticsearch import (
    ElasticsearchConfig,
    ElasticsearchQueryError,
    SearchCandidate,
    build_powershell_candidate_query,
    parse_search_hits,
    search_powershell_candidates,
)
from detection.rules.native.evaluator import MatchResult, evaluate_rule
from detection.rules.native.loader import RuleValidationError, load_rule, validate_rule
from detection.rules.native.registry import (
    NativeRuleSpec,
    build_native_alerts,
    evaluate_native_rule_spec,
    load_native_rule_specs,
    load_native_rules,
)

__all__ = [
    "AlertDocumentError",
    "ElasticsearchConfig",
    "ElasticsearchQueryError",
    "MatchResult",
    "RuleValidationError",
    "SearchCandidate",
    "NativeRuleSpec",
    "build_alert_document",
    "build_native_alerts",
    "build_powershell_candidate_query",
    "evaluate_rule",
    "evaluate_native_rule_spec",
    "load_native_rule_specs",
    "load_rule",
    "load_native_rules",
    "parse_search_hits",
    "search_powershell_candidates",
    "validate_rule",
]
