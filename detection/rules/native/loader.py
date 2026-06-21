"""Load and validate native detection rules."""

from __future__ import annotations

from pathlib import Path
from typing import Any


DEFAULT_RULE_PATH = Path(__file__).with_name("t1059_001_powershell_process_start.yml")

VALID_SEVERITIES = {"low", "medium", "high", "critical"}
VALID_CONFIDENCES = {"low", "medium", "high"}
SUPPORTED_OPERATORS = {"equals_any", "endswith_any", "contains_any"}


class RuleValidationError(ValueError):
    """Raised when a native detection rule is malformed."""


def load_rule(path: Path | str = DEFAULT_RULE_PATH) -> dict[str, Any]:
    """Load and validate a native detection rule file."""

    rule_path = Path(path)
    rule = _parse_rule_yaml(rule_path.read_text(encoding="utf-8"))
    validate_rule(rule)
    return rule


def validate_rule(rule: dict[str, Any]) -> None:
    """Validate the narrow native rule schema used by the MVP detector."""

    _require_string(rule, "id")
    _require_int(rule, "version")
    _require_string(rule, "name")
    _require_string(rule, "description")

    severity = _require_string(rule, "severity")
    if severity not in VALID_SEVERITIES:
        raise RuleValidationError(f"Rule severity must be one of {sorted(VALID_SEVERITIES)}, got {severity!r}.")

    confidence = _require_string(rule, "confidence")
    if confidence not in VALID_CONFIDENCES:
        raise RuleValidationError(f"Rule confidence must be one of {sorted(VALID_CONFIDENCES)}, got {confidence!r}.")

    attack = _require_mapping(rule, "attack")
    _require_string(attack, "technique_id")
    _require_string(attack, "technique_name")
    tactic = _require_list(attack, "tactic")
    if not all(isinstance(item, str) and item for item in tactic):
        raise RuleValidationError("Rule attack.tactic must contain non-empty strings.")

    data_source = _require_mapping(rule, "data_source")
    _require_string(data_source, "event_dataset")
    _require_int(data_source, "event_code")

    match = _require_mapping(rule, "match")
    any_conditions = _require_list(match, "any")
    if not any_conditions:
        raise RuleValidationError("Rule match.any must contain at least one condition.")

    for index, condition in enumerate(any_conditions):
        if not isinstance(condition, dict):
            raise RuleValidationError(f"Rule match.any[{index}] must be a mapping.")

        _require_string(condition, "field")
        operators = [key for key in condition if key in SUPPORTED_OPERATORS]
        if len(operators) != 1:
            raise RuleValidationError(
                f"Rule match.any[{index}] must contain exactly one supported operator: "
                f"{sorted(SUPPORTED_OPERATORS)}."
            )

        values = condition[operators[0]]
        if not isinstance(values, list) or not values:
            raise RuleValidationError(f"Rule match.any[{index}].{operators[0]} must be a non-empty list.")
        if not all(isinstance(value, str) and value for value in values):
            raise RuleValidationError(f"Rule match.any[{index}].{operators[0]} must contain non-empty strings.")


def _require_mapping(parent: dict[str, Any], key: str) -> dict[str, Any]:
    value = parent.get(key)
    if not isinstance(value, dict):
        raise RuleValidationError(f"Rule field {key!r} must be a mapping.")
    return value


def _require_list(parent: dict[str, Any], key: str) -> list[Any]:
    value = parent.get(key)
    if not isinstance(value, list):
        raise RuleValidationError(f"Rule field {key!r} must be a list.")
    return value


def _require_string(parent: dict[str, Any], key: str) -> str:
    value = parent.get(key)
    if not isinstance(value, str) or not value:
        raise RuleValidationError(f"Rule field {key!r} must be a non-empty string.")
    return value


def _require_int(parent: dict[str, Any], key: str) -> int:
    value = parent.get(key)
    if not isinstance(value, int):
        raise RuleValidationError(f"Rule field {key!r} must be an integer.")
    return value


def _parse_rule_yaml(text: str) -> dict[str, Any]:
    """Parse the small YAML subset used by native rule files.

    This avoids adding PyYAML for one static MVP rule. It supports only the
    indentation and scalar/list shapes used by the committed rule format.
    """

    root: dict[str, Any] = {}
    current_section: dict[str, Any] | None = None
    current_list: list[Any] | None = None
    current_condition: dict[str, Any] | None = None
    current_operator_values: list[str] | None = None

    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue

        indent = len(raw_line) - len(raw_line.lstrip(" "))
        line = raw_line.strip()

        if indent == 0:
            key, value = _parse_key_value(line, line_number)
            if value == "":
                root[key] = {}
                current_section = root[key]
            else:
                root[key] = _parse_scalar(value)
                current_section = None
            current_list = None
            current_condition = None
            current_operator_values = None
            continue

        if current_section is None:
            raise RuleValidationError(f"Invalid indentation at rule line {line_number}.")

        if indent == 2:
            key, value = _parse_key_value(line, line_number)
            if value == "":
                current_section[key] = []
                current_list = current_section[key]
            else:
                current_section[key] = _parse_scalar(value)
                current_list = None
            current_condition = None
            current_operator_values = None
            continue

        if indent == 4 and line.startswith("- "):
            item = line[2:]
            if current_list is None:
                raise RuleValidationError(f"Unexpected list item at rule line {line_number}.")
            if ":" in item:
                key, value = _parse_key_value(item, line_number)
                current_condition = {key: _parse_scalar(value)}
                current_list.append(current_condition)
                current_operator_values = None
            else:
                current_list.append(_parse_scalar(item))
                current_condition = None
                current_operator_values = None
            continue

        if indent == 6 and current_condition is not None:
            key, value = _parse_key_value(line, line_number)
            if value != "":
                current_condition[key] = _parse_scalar(value)
                current_operator_values = None
            else:
                current_condition[key] = []
                current_operator_values = current_condition[key]
            continue

        if indent == 8 and line.startswith("- ") and current_operator_values is not None:
            current_operator_values.append(str(_parse_scalar(line[2:])))
            continue

        raise RuleValidationError(f"Unsupported native rule syntax at line {line_number}: {raw_line!r}.")

    return root


def _parse_key_value(line: str, line_number: int) -> tuple[str, str]:
    key, separator, value = line.partition(":")
    if not separator or not key.strip():
        raise RuleValidationError(f"Expected key/value pair at rule line {line_number}.")
    return key.strip(), value.strip()


def _parse_scalar(value: str) -> str | int:
    if value.isdigit():
        return int(value)
    return value.strip("\"'")
