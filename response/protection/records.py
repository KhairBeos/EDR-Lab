"""Build protection action records."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any


def build_protection_record(
    alert_or_response: dict[str, Any],
    decision: dict[str, Any],
    action_result: dict[str, Any],
    *,
    created_at: datetime | str | None = None,
) -> dict[str, Any]:
    """Build a deterministic protection record from a policy decision and action result."""

    action = action_result.get("action") or "kill_process"
    mode = str(decision.get("mode") or ("execute" if not action_result.get("dry_run", True) else "dry-run"))
    status = _status(decision, action_result)
    alert_id = _alert_id(alert_or_response)
    rule_id = decision.get("rule_id") or _rule_id(alert_or_response)
    technique_id = _technique_id(alert_or_response)
    pid = decision.get("pid")
    process_name = decision.get("process_name") or _process_name(alert_or_response)
    host = _host_name(alert_or_response)
    reason = str(decision.get("reason") or "")

    return {
        "protection": {
            "id": _protection_id(alert_id=alert_id, action=action, pid=pid, mode=mode, reason=reason),
            "action": action,
            "mode": mode,
            "status": status,
            "created": _format_created_at(created_at),
            "reason": reason,
        },
        "target": {
            "pid": pid,
            "process_name": process_name,
            "host": host,
        },
        "alert": {
            "id": alert_id,
            "rule_id": rule_id,
            "technique_id": technique_id,
        },
        "safety": {
            "checks": list(decision.get("safety_checks", [])),
        },
        "result": action_result,
    }


def _status(decision: dict[str, Any], action_result: dict[str, Any]) -> str:
    if not bool(decision.get("allowed")):
        return "blocked"
    result_status = action_result.get("status")
    if result_status in {"planned", "executed", "failed"}:
        return str(result_status)
    if action_result.get("error"):
        return "failed"
    return "planned"


def _protection_id(*, alert_id: str | None, action: Any, pid: Any, mode: str, reason: str) -> str:
    material = {
        "alert_id": alert_id,
        "action": action,
        "pid": pid,
        "mode": mode,
        "reason": reason,
    }
    digest = hashlib.sha256(json.dumps(material, sort_keys=True).encode("utf-8")).hexdigest()[:16]
    return f"protection-kill-process-{digest}"


def _format_created_at(created_at: datetime | str | None) -> str:
    if created_at is None:
        return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    if isinstance(created_at, str):
        return created_at
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=UTC)
    return created_at.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _alert_id(alert_or_response: dict[str, Any]) -> str | None:
    alert = alert_or_response.get("alert")
    if isinstance(alert, dict) and isinstance(alert.get("id"), str):
        return alert["id"]
    if isinstance(alert_or_response.get("id"), str):
        return alert_or_response["id"]
    nested = alert.get("alert") if isinstance(alert, dict) else None
    if isinstance(nested, dict) and isinstance(nested.get("id"), str):
        return nested["id"]
    return None


def _rule_id(alert_or_response: dict[str, Any]) -> str | None:
    rule = alert_or_response.get("rule")
    if isinstance(rule, dict) and isinstance(rule.get("id"), str):
        return rule["id"]
    alert = alert_or_response.get("alert")
    if isinstance(alert, dict) and isinstance(alert.get("rule_id"), str):
        return alert["rule_id"]
    return None


def _technique_id(alert_or_response: dict[str, Any]) -> str | None:
    attack = alert_or_response.get("attack")
    if isinstance(attack, dict):
        technique = attack.get("technique")
        if isinstance(technique, dict) and isinstance(technique.get("id"), str):
            return technique["id"]
        if isinstance(attack.get("technique_id"), str):
            return attack["technique_id"]
    art = alert_or_response.get("art")
    if isinstance(art, dict) and isinstance(art.get("technique_id"), str):
        return art["technique_id"]
    alert = alert_or_response.get("alert")
    if isinstance(alert, dict) and isinstance(alert.get("technique_id"), str):
        return alert["technique_id"]
    return None


def _process_name(alert_or_response: dict[str, Any]) -> str | None:
    process = alert_or_response.get("process")
    if isinstance(process, dict) and isinstance(process.get("name"), str):
        return process["name"]
    return None


def _host_name(alert_or_response: dict[str, Any]) -> str | None:
    host = alert_or_response.get("host")
    if isinstance(host, dict) and isinstance(host.get("name"), str):
        return host["name"]
    return None
