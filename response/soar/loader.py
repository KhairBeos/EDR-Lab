"""Load and validate minimal SOAR dry-run playbooks."""

from __future__ import annotations

from pathlib import Path
from typing import Any


DEFAULT_PLAYBOOK_PATH = Path(__file__).parent / "playbooks" / "powershell_execution.yml"


class SoarPlaybookValidationError(ValueError):
    """Raised when a local SOAR playbook is malformed."""


def load_playbook(path: Path | str = DEFAULT_PLAYBOOK_PATH) -> dict[str, Any]:
    """Load and validate the minimal local YAML playbook subset."""

    playbook_path = Path(path)
    playbook = _parse_playbook_yaml(playbook_path.read_text(encoding="utf-8"))
    validate_playbook(playbook)
    return playbook


def validate_playbook(playbook: dict[str, Any]) -> None:
    """Validate the production-shaped dry-run playbook schema used by Phase 5."""

    _require_string(playbook, "id")
    _require_string(playbook, "name")
    status = _require_string(playbook, "status")
    if status != "dry-run":
        raise SoarPlaybookValidationError(f"Playbook status must be 'dry-run', got {status!r}.")
    _require_string(playbook, "description")

    match = _require_mapping(playbook, "match")
    rule_ids = _optional_string_list(match, "rule_ids")
    technique_ids = _optional_string_list(match, "technique_ids")
    if not rule_ids and not technique_ids:
        raise SoarPlaybookValidationError("Playbook match must include rule_ids or technique_ids.")

    actions = _require_list(playbook, "actions")
    if not actions:
        raise SoarPlaybookValidationError("Playbook actions must be non-empty.")

    for index, action in enumerate(actions):
        if not isinstance(action, dict):
            raise SoarPlaybookValidationError(f"Playbook actions[{index}] must be a mapping.")

        _require_string(action, "id")
        _require_string(action, "type")
        action_status = _require_string(action, "status")
        if action_status != "planned":
            raise SoarPlaybookValidationError(
                f"Playbook actions[{index}].status must be 'planned', got {action_status!r}."
            )
        _require_string(action, "description")


def _require_mapping(parent: dict[str, Any], key: str) -> dict[str, Any]:
    value = parent.get(key)
    if not isinstance(value, dict):
        raise SoarPlaybookValidationError(f"Playbook field {key!r} must be a mapping.")
    return value


def _require_list(parent: dict[str, Any], key: str) -> list[Any]:
    value = parent.get(key)
    if not isinstance(value, list):
        raise SoarPlaybookValidationError(f"Playbook field {key!r} must be a list.")
    return value


def _require_string(parent: dict[str, Any], key: str) -> str:
    value = parent.get(key)
    if not isinstance(value, str) or not value:
        raise SoarPlaybookValidationError(f"Playbook field {key!r} must be a non-empty string.")
    return value


def _optional_string_list(parent: dict[str, Any], key: str) -> list[str]:
    value = parent.get(key)
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise SoarPlaybookValidationError(f"Playbook field match.{key} must be a list of non-empty strings.")
    return value


def _parse_playbook_yaml(text: str) -> dict[str, Any]:
    """Parse only the YAML subset used by the local Phase 5 playbook."""

    root: dict[str, Any] = {}
    current_section: dict[str, Any] | None = None
    current_list: list[Any] | None = None
    current_action: dict[str, Any] | None = None

    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue

        indent = len(raw_line) - len(raw_line.lstrip(" "))
        line = raw_line.strip()

        if indent == 0:
            key, value = _parse_key_value(line, line_number)
            if value == "":
                root[key] = [] if key == "actions" else {}
                current_section = root[key] if isinstance(root[key], dict) else None
                current_list = root[key] if isinstance(root[key], list) else None
            else:
                root[key] = _parse_scalar(value)
                current_section = None
                current_list = None
            current_action = None
            continue

        if indent == 2 and current_section is not None:
            key, value = _parse_key_value(line, line_number)
            if value == "":
                current_section[key] = []
                current_list = current_section[key]
            else:
                current_section[key] = _parse_scalar(value)
                current_list = None
            current_action = None
            continue

        if indent == 4 and line.startswith("- ") and current_list is not None:
            current_list.append(_parse_scalar(line[2:]))
            continue

        if indent == 2 and line.startswith("- ") and current_list is not None:
            key, value = _parse_key_value(line[2:], line_number)
            current_action = {key: _parse_scalar(value)}
            current_list.append(current_action)
            continue

        if indent == 4 and current_action is not None:
            key, value = _parse_key_value(line, line_number)
            current_action[key] = _parse_scalar(value)
            continue

        raise SoarPlaybookValidationError(f"Unsupported playbook syntax at line {line_number}: {raw_line!r}.")

    return root


def _parse_key_value(line: str, line_number: int) -> tuple[str, str]:
    key, separator, value = line.partition(":")
    if not separator or not key.strip():
        raise SoarPlaybookValidationError(f"Expected key/value pair at playbook line {line_number}.")
    return key.strip(), value.strip()


def _parse_scalar(value: str) -> str:
    return value.strip("\"'")
