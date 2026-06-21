"""Safety policy for lab-only protection actions."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


APPROVED_RULE_IDS = {
    "det.t1059_001.powershell_process_start",
    "sigma_like.t1059_001.powershell_process_start",
    "ml.process_anomaly",
}

SAFE_DEMO_MARKERS = (
    "EDR_DEMO_T1059_001",
    "EDR_SAFE_MANUAL_T1059_001",
    "phase_8_demo",
    "phase_9_demo",
)

PROTECTED_PROCESS_NAMES = {
    "system",
    "registry",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "services.exe",
    "lsass.exe",
    "svchost.exe",
    "winlogon.exe",
    "explorer.exe",
}


class ProtectionPolicyError(ValueError):
    """Raised when protection policy input is malformed."""


@dataclass(frozen=True)
class ProtectionDecision:
    allowed: bool
    mode: str
    reason: str
    pid: int | None
    process_name: str | None
    rule_id: str | None
    safety_checks: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def evaluate_kill_process_policy(
    alert_or_response: dict[str, Any],
    *,
    execute: bool = False,
    lab_allow_execute: bool = False,
    force_lab_demo: bool = False,
    explicit_pid: int | None = None,
) -> dict[str, Any]:
    """Evaluate whether kill_process is allowed for one alert or response record."""

    pid = _resolve_pid(alert_or_response, explicit_pid)
    process_name = _process_name(alert_or_response)
    rule_id = _rule_id(alert_or_response)
    command_line = _command_line(alert_or_response)
    mode = "execute" if execute else "dry-run"
    safety_checks: list[str] = []

    if not execute:
        safety_checks.append("dry_run_default")
    if force_lab_demo:
        safety_checks.append("force_lab_demo")

    if pid is None:
        safety_checks.append("pid_missing")
    else:
        safety_checks.append("pid_present")

    if process_name and process_name.casefold() in PROTECTED_PROCESS_NAMES:
        safety_checks.append("protected_process_blocked")
        return _decision(
            False,
            mode,
            f"protected process cannot be killed: {process_name}",
            pid,
            process_name,
            rule_id,
            safety_checks,
        )
    safety_checks.append("process_not_protected")

    approved_rule = rule_id in APPROVED_RULE_IDS
    marker_present = _has_demo_marker(command_line, alert_or_response)
    if approved_rule:
        safety_checks.append("approved_rule_id")
    elif marker_present:
        safety_checks.append("safe_demo_marker")
    elif force_lab_demo:
        safety_checks.append("unsupported_rule_forced_lab_demo")
    else:
        safety_checks.append("unsupported_rule_blocked")
        return _decision(
            False,
            mode,
            "rule id is not approved and no safe demo marker is present",
            pid,
            process_name,
            rule_id,
            safety_checks,
        )

    if not execute:
        if pid is None:
            return _decision(
                True,
                mode,
                "dry-run planned for approved detection alert; PID missing so execution would be blocked",
                pid,
                process_name,
                rule_id,
                safety_checks,
            )
        return _decision(
            True,
            mode,
            "dry-run planned for approved detection alert",
            pid,
            process_name,
            rule_id,
            safety_checks,
        )

    safety_checks.append("execute_requested")
    if not lab_allow_execute:
        safety_checks.append("lab_allow_execute_missing")
        return _decision(
            False,
            mode,
            "execute blocked because lab_allow_execute is required",
            pid,
            process_name,
            rule_id,
            safety_checks,
        )
    safety_checks.append("lab_allow_execute")

    if pid is None:
        return _decision(False, mode, "execute blocked because PID is missing", pid, process_name, rule_id, safety_checks)

    return _decision(
        True,
        mode,
        "execute allowed for approved lab protection action",
        pid,
        process_name,
        rule_id,
        safety_checks,
    )


def _decision(
    allowed: bool,
    mode: str,
    reason: str,
    pid: int | None,
    process_name: str | None,
    rule_id: str | None,
    safety_checks: list[str],
) -> dict[str, Any]:
    return ProtectionDecision(
        allowed=allowed,
        mode=mode,
        reason=reason,
        pid=pid,
        process_name=process_name,
        rule_id=rule_id,
        safety_checks=safety_checks,
    ).to_dict()


def _resolve_pid(alert_or_response: dict[str, Any], explicit_pid: int | None) -> int | None:
    if explicit_pid is not None:
        return _validate_pid(explicit_pid)
    process = _process_mapping(alert_or_response)
    raw_pid = process.get("pid") if isinstance(process, dict) else None
    if raw_pid is None:
        return None
    return _validate_pid(raw_pid)


def _validate_pid(value: Any) -> int:
    if isinstance(value, bool):
        raise ProtectionPolicyError("PID must be a positive integer.")
    try:
        pid = int(value)
    except (TypeError, ValueError) as exc:
        raise ProtectionPolicyError(f"PID must be a positive integer, got {value!r}.") from exc
    if pid <= 0:
        raise ProtectionPolicyError(f"PID must be a positive integer, got {pid}.")
    return pid


def _process_mapping(alert_or_response: dict[str, Any]) -> dict[str, Any]:
    process = alert_or_response.get("process")
    if isinstance(process, dict):
        return process
    alert = alert_or_response.get("alert")
    if isinstance(alert, dict):
        nested = alert.get("process")
        if isinstance(nested, dict):
            return nested
    return {}


def _process_name(alert_or_response: dict[str, Any]) -> str | None:
    process = _process_mapping(alert_or_response)
    value = process.get("name")
    return value if isinstance(value, str) and value else None


def _command_line(alert_or_response: dict[str, Any]) -> str:
    process = _process_mapping(alert_or_response)
    value = process.get("command_line")
    return value if isinstance(value, str) else ""


def _rule_id(alert_or_response: dict[str, Any]) -> str | None:
    rule = alert_or_response.get("rule")
    if isinstance(rule, dict) and isinstance(rule.get("id"), str):
        return rule["id"]
    alert = alert_or_response.get("alert")
    if isinstance(alert, dict):
        rule_id = alert.get("rule_id")
        if isinstance(rule_id, str):
            return rule_id
        nested_rule = alert.get("rule")
        if isinstance(nested_rule, dict) and isinstance(nested_rule.get("id"), str):
            return nested_rule["id"]
    return None


def _has_demo_marker(command_line: str, alert_or_response: dict[str, Any]) -> bool:
    haystack = command_line
    tags = alert_or_response.get("tags")
    if isinstance(tags, list):
        haystack += " " + " ".join(tag for tag in tags if isinstance(tag, str))
    art = alert_or_response.get("art")
    if isinstance(art, dict):
        haystack += " " + " ".join(str(value) for value in art.values() if isinstance(value, str))
    lowered = haystack.casefold()
    return any(marker.casefold() in lowered for marker in SAFE_DEMO_MARKERS)

