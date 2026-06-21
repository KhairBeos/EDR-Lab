"""Load and validate minimal Sigma-like rules."""

from __future__ import annotations

from pathlib import Path
from typing import Any


DEFAULT_SIGMA_LIKE_RULE_PATH = Path(__file__).with_name("t1059_001_powershell_process_start.yml")
SIGMA_LIKE_RULES_DIR = Path(__file__).with_name("rules")
SUPPORTED_SELECTION_OPERATORS = {"equals", "endswith", "contains"}


class SigmaLikeRuleValidationError(ValueError):
    """Raised when a Sigma-like detection rule is malformed."""


def load_sigma_like_rule(path: Path | str = DEFAULT_SIGMA_LIKE_RULE_PATH) -> dict[str, Any]:
    """Load and validate a Sigma-like detection rule file."""

    rule_path = Path(path)
    rule = _parse_sigma_like_yaml(rule_path.read_text(encoding="utf-8"))
    validate_sigma_like_rule(rule)
    return rule


def load_sigma_like_rules() -> list[dict[str, Any]]:
    """Load the default Sigma-like rule plus deterministic Phase 13 rules."""

    rules = [load_sigma_like_rule(DEFAULT_SIGMA_LIKE_RULE_PATH)]
    if SIGMA_LIKE_RULES_DIR.exists():
        for rule_path in sorted(SIGMA_LIKE_RULES_DIR.glob("*.yml")):
            rules.append(load_sigma_like_rule(rule_path))
    return rules


def validate_sigma_like_rule(rule: dict[str, Any]) -> None:
    """Validate the narrow Sigma-like rule schema used by the MVP."""

    _require_string(rule, "id")
    if not (isinstance(rule.get("title"), str) and rule["title"]) and not (
        isinstance(rule.get("name"), str) and rule["name"]
    ):
        raise SigmaLikeRuleValidationError("Sigma-like rule requires non-empty 'title' or 'name'.")
    _require_string(rule, "status")
    _require_string(rule, "description")
    _require_string(rule, "level")
    _require_string(rule, "confidence")

    logsource = _require_mapping(rule, "logsource")
    _require_string(logsource, "product")
    _require_string(logsource, "service")
    _require_string(logsource, "category")

    detection = _require_mapping(rule, "detection")
    selection = _require_mapping(detection, "selection")
    condition = _require_string(detection, "condition")
    if condition != "selection":
        raise SigmaLikeRuleValidationError(f"Unsupported Sigma-like condition {condition!r}; only 'selection' is supported.")

    if not selection:
        raise SigmaLikeRuleValidationError("Sigma-like detection.selection must not be empty.")

    for raw_key, raw_value in selection.items():
        field, operator = _split_selection_key(raw_key)
        if not field:
            raise SigmaLikeRuleValidationError(f"Invalid empty Sigma-like selection field in {raw_key!r}.")
        if operator is not None and operator not in SUPPORTED_SELECTION_OPERATORS:
            raise SigmaLikeRuleValidationError(
                f"Unsupported Sigma-like operator {operator!r}; supported operators are "
                f"{sorted(SUPPORTED_SELECTION_OPERATORS)}."
            )
        if operator is None:
            if not isinstance(raw_value, (str, int)):
                raise SigmaLikeRuleValidationError(f"Sigma-like selection {raw_key!r} must be a scalar value.")
        else:
            if not isinstance(raw_value, list) or not raw_value:
                raise SigmaLikeRuleValidationError(f"Sigma-like selection {raw_key!r} must be a non-empty list.")
            if not all(isinstance(item, str) and item for item in raw_value):
                raise SigmaLikeRuleValidationError(f"Sigma-like selection {raw_key!r} must contain non-empty strings.")

    attack = _require_mapping(rule, "attack")
    _require_string(attack, "technique_id")
    _require_string(attack, "technique_name")
    tactic = _require_list(attack, "tactic")
    if not all(isinstance(item, str) and item for item in tactic):
        raise SigmaLikeRuleValidationError("Sigma-like attack.tactic must contain non-empty strings.")


def _split_selection_key(key: str) -> tuple[str, str | None]:
    field, separator, operator = key.partition("|")
    return field, operator if separator else None


def _require_mapping(parent: dict[str, Any], key: str) -> dict[str, Any]:
    value = parent.get(key)
    if not isinstance(value, dict):
        raise SigmaLikeRuleValidationError(f"Sigma-like rule field {key!r} must be a mapping.")
    return value


def _require_list(parent: dict[str, Any], key: str) -> list[Any]:
    value = parent.get(key)
    if not isinstance(value, list):
        raise SigmaLikeRuleValidationError(f"Sigma-like rule field {key!r} must be a list.")
    return value


def _require_string(parent: dict[str, Any], key: str) -> str:
    value = parent.get(key)
    if not isinstance(value, str) or not value:
        raise SigmaLikeRuleValidationError(f"Sigma-like rule field {key!r} must be a non-empty string.")
    return value


def _parse_sigma_like_yaml(text: str) -> dict[str, Any]:
    """Parse the small YAML subset used by the Sigma-like MVP rule."""

    lines = [line.rstrip() for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")]
    root: dict[str, Any] = {}
    index = 0

    while index < len(lines):
        raw_line = lines[index]
        indent = _indent(raw_line)
        if indent != 0:
            raise SigmaLikeRuleValidationError(f"Unexpected indentation at line {index + 1}: {raw_line!r}.")

        key, value = _parse_key_value(raw_line.strip(), index + 1)
        if value:
            root[key] = _parse_scalar(value)
            index += 1
            continue

        if key == "detection":
            detection, index = _parse_detection(lines, index + 1)
            root[key] = detection
        else:
            mapping, index = _parse_simple_mapping(lines, index + 1, parent_indent=2)
            root[key] = mapping

    return root


def _parse_detection(lines: list[str], index: int) -> tuple[dict[str, Any], int]:
    detection: dict[str, Any] = {}

    while index < len(lines):
        raw_line = lines[index]
        indent = _indent(raw_line)
        if indent == 0:
            break
        if indent != 2:
            raise SigmaLikeRuleValidationError(f"Unsupported detection indentation at line {index + 1}: {raw_line!r}.")

        key, value = _parse_key_value(raw_line.strip(), index + 1)
        if key == "selection" and not value:
            selection, index = _parse_simple_mapping(lines, index + 1, parent_indent=4)
            detection[key] = selection
        elif value:
            detection[key] = _parse_scalar(value)
            index += 1
        else:
            raise SigmaLikeRuleValidationError(f"Unsupported detection block at line {index + 1}: {raw_line!r}.")

    return detection, index


def _parse_simple_mapping(lines: list[str], index: int, *, parent_indent: int) -> tuple[dict[str, Any], int]:
    mapping: dict[str, Any] = {}

    while index < len(lines):
        raw_line = lines[index]
        indent = _indent(raw_line)
        if indent < parent_indent:
            break
        if indent != parent_indent:
            raise SigmaLikeRuleValidationError(f"Unsupported indentation at line {index + 1}: {raw_line!r}.")

        key, value = _parse_key_value(raw_line.strip(), index + 1)
        if value:
            mapping[key] = _parse_scalar(value)
            index += 1
            continue

        values: list[Any] = []
        index += 1
        while index < len(lines):
            list_line = lines[index]
            list_indent = _indent(list_line)
            if list_indent <= indent:
                break
            if list_indent != indent + 2 or not list_line.strip().startswith("- "):
                raise SigmaLikeRuleValidationError(f"Unsupported list item at line {index + 1}: {list_line!r}.")
            values.append(_parse_scalar(list_line.strip()[2:]))
            index += 1
        mapping[key] = values

    return mapping, index


def _parse_key_value(line: str, line_number: int) -> tuple[str, str]:
    key, separator, value = line.partition(":")
    if not separator or not key.strip():
        raise SigmaLikeRuleValidationError(f"Expected key/value pair at Sigma-like rule line {line_number}.")
    return key.strip(), value.strip()


def _parse_scalar(value: str) -> str | int:
    if value.isdigit():
        return int(value)
    return value.strip("\"'")


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))
