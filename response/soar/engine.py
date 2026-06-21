"""Plan dry-run SOAR responses from alert documents."""

from __future__ import annotations

import copy
import hashlib
import json
from datetime import UTC, datetime
from typing import Any


class SoarResponseError(ValueError):
    """Raised when a SOAR response record cannot be planned."""


def find_matching_playbook(alert: dict[str, Any], playbooks: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Return the first playbook matching alert rule ID or ATT&CK technique ID."""

    rule_id = _alert_rule_id(alert)
    technique_id = _alert_technique_id(alert)

    for playbook in playbooks:
        match = playbook.get("match", {})
        rule_ids = match.get("rule_ids", []) if isinstance(match, dict) else []
        technique_ids = match.get("technique_ids", []) if isinstance(match, dict) else []

        if rule_id and rule_id in rule_ids:
            return playbook
        if technique_id and technique_id in technique_ids:
            return playbook

    return None


def build_response_record(
    alert: dict[str, Any],
    playbook: dict[str, Any],
    created_at: datetime | str | None = None,
) -> dict[str, Any]:
    """Build one dry-run response record for a matching alert/playbook pair."""

    alert_id = _required_alert_id(alert)
    rule_id = _alert_rule_id(alert)
    technique_id = _alert_technique_id(alert)
    actions = copy.deepcopy(playbook.get("actions"))
    if not isinstance(actions, list) or not actions:
        raise SoarResponseError("Matching playbook must contain planned actions.")

    for index, action in enumerate(actions):
        if not isinstance(action, dict):
            raise SoarResponseError(f"Response action {index} must be a mapping.")
        if action.get("status") != "planned":
            raise SoarResponseError(f"Response action {index} must remain planned.")

    response_id = _build_response_id(
        playbook_id=_required_playbook_string(playbook, "id"),
        alert_id=alert_id,
        action_ids=[str(action["id"]) for action in actions],
    )

    response = {
        "response": {
            "id": response_id,
            "status": "planned",
            "mode": "dry-run",
            "created": _format_created_at(created_at),
        },
        "alert": {
            "id": alert_id,
            "rule_id": rule_id,
            "technique_id": technique_id,
        },
        "playbook": {
            "id": playbook["id"],
            "name": _required_playbook_string(playbook, "name"),
        },
        "actions": actions,
    }

    severity = _alert_severity(alert)
    if severity is not None:
        response["response"]["severity"] = severity

    return response


def plan_responses(
    alerts: list[dict[str, Any]],
    playbooks: list[dict[str, Any]],
    created_at: datetime | str | None = None,
) -> list[dict[str, Any]]:
    """Plan exactly one response record for each alert with a matching playbook."""

    response_records: list[dict[str, Any]] = []
    for alert in alerts:
        playbook = find_matching_playbook(alert, playbooks)
        if playbook is None:
            continue
        response_records.append(build_response_record(alert, playbook, created_at=created_at))
    return response_records


def _build_response_id(*, playbook_id: str, alert_id: str, action_ids: list[str]) -> str:
    material = {
        "playbook_id": playbook_id,
        "alert_id": alert_id,
        "action_ids": action_ids,
    }
    digest = hashlib.sha256(json.dumps(material, sort_keys=True).encode("utf-8")).hexdigest()[:16]
    return f"soar-response-{digest}"


def _format_created_at(created_at: datetime | str | None) -> str:
    if created_at is None:
        return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    if isinstance(created_at, str):
        return created_at
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=UTC)
    return created_at.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _required_alert_id(alert: dict[str, Any]) -> str:
    alert_meta = alert.get("alert")
    if isinstance(alert_meta, dict):
        alert_id = alert_meta.get("id")
    else:
        alert_id = alert.get("id")

    if not isinstance(alert_id, str) or not alert_id:
        raise SoarResponseError("Alert document must contain non-empty alert.id.")
    return alert_id


def _alert_rule_id(alert: dict[str, Any]) -> str | None:
    alert_meta = alert.get("alert")
    if isinstance(alert_meta, dict):
        nested_rule = alert_meta.get("rule")
        if isinstance(nested_rule, dict) and isinstance(nested_rule.get("id"), str):
            return nested_rule["id"]

    rule = alert.get("rule")
    if isinstance(rule, dict) and isinstance(rule.get("id"), str):
        return rule["id"]
    return None


def _alert_technique_id(alert: dict[str, Any]) -> str | None:
    attack = alert.get("attack")
    if isinstance(attack, dict):
        technique = attack.get("technique")
        if isinstance(technique, dict) and isinstance(technique.get("id"), str):
            return technique["id"]
        if isinstance(attack.get("technique_id"), str):
            return attack["technique_id"]

    art = alert.get("art")
    if isinstance(art, dict) and isinstance(art.get("technique_id"), str):
        return art["technique_id"]
    return None


def _alert_severity(alert: dict[str, Any]) -> str | None:
    alert_meta = alert.get("alert")
    if isinstance(alert_meta, dict) and isinstance(alert_meta.get("severity"), str):
        return alert_meta["severity"]
    return None


def _required_playbook_string(playbook: dict[str, Any], key: str) -> str:
    value = playbook.get(key)
    if not isinstance(value, str) or not value:
        raise SoarResponseError(f"Playbook must contain non-empty {key}.")
    return value
