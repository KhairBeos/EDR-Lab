import copy

import pytest

from detection.rules.native import build_alert_document, evaluate_rule, load_rule
from detection.rules.sigma_like import (
    SigmaLikeRuleValidationError,
    build_sigma_like_alert_document,
    evaluate_sigma_like_rule,
    load_sigma_like_rule,
    validate_sigma_like_rule,
)
from scripts.smoke.end_to_end_art_telemetry_smoke import build_smoke_payloads, load_fixture


def normalized_smoke_payload() -> dict:
    _, normalized_payload = build_smoke_payloads(load_fixture())
    return normalized_payload


def powershell_process_event() -> dict:
    payload = copy.deepcopy(normalized_smoke_payload())
    payload["process"]["name"] = "powershell.exe"
    payload["process"]["executable"] = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    payload["process"]["command_line"] = "powershell.exe -NoLogo"
    payload["process"]["args"] = ["powershell.exe", "-NoLogo"]
    return payload


def test_loads_sigma_like_rule_metadata() -> None:
    rule = load_sigma_like_rule()

    assert rule["id"] == "sigma_like.t1059_001.powershell_process_start"
    assert rule["title"] == "PowerShell Process Execution"
    assert rule["status"] == "experimental"
    assert rule["logsource"] == {
        "product": "windows",
        "service": "sysmon",
        "category": "process_creation",
    }
    assert rule["detection"]["condition"] == "selection"
    assert rule["level"] == "medium"
    assert rule["confidence"] == "high"
    assert rule["attack"]["technique_id"] == "T1059.001"


def test_loader_rejects_missing_rule_id() -> None:
    rule = copy.deepcopy(load_sigma_like_rule())
    del rule["id"]

    with pytest.raises(SigmaLikeRuleValidationError, match="id"):
        validate_sigma_like_rule(rule)


def test_loader_rejects_unsupported_condition() -> None:
    rule = copy.deepcopy(load_sigma_like_rule())
    rule["detection"]["condition"] = "selection and filter"

    with pytest.raises(SigmaLikeRuleValidationError, match="condition"):
        validate_sigma_like_rule(rule)


def test_evaluator_matches_process_name() -> None:
    rule = load_sigma_like_rule()
    event = powershell_process_event()
    event["process"]["executable"] = r"C:\Windows\System32\notepad.exe"
    event["process"]["command_line"] = "notepad.exe"

    result = evaluate_sigma_like_rule(rule, event)

    assert result.matched is True
    assert result.engine == "sigma-like"
    assert result.matched_fields == ("process.name",)


def test_evaluator_matches_process_executable() -> None:
    rule = load_sigma_like_rule()
    event = powershell_process_event()
    event["process"]["name"] = "notepad.exe"
    event["process"]["command_line"] = "notepad.exe"

    result = evaluate_sigma_like_rule(rule, event)

    assert result.matched is True
    assert result.matched_fields == ("process.executable",)


def test_evaluator_matches_process_command_line() -> None:
    rule = load_sigma_like_rule()
    event = powershell_process_event()
    event["process"]["name"] = "notepad.exe"
    event["process"]["executable"] = r"C:\Windows\System32\notepad.exe"

    result = evaluate_sigma_like_rule(rule, event)

    assert result.matched is True
    assert result.matched_fields == ("process.command_line",)


def test_evaluator_matching_is_case_insensitive() -> None:
    rule = load_sigma_like_rule()
    event = powershell_process_event()
    event["process"]["name"] = "PowerShell.EXE"
    event["process"]["executable"] = r"C:\Windows\System32\WindowsPowerShell\v1.0\PowerShell.EXE"
    event["process"]["command_line"] = "PowerShell.EXE -NoLogo"

    result = evaluate_sigma_like_rule(rule, event)

    assert result.matched is True
    assert result.matched_fields == ("process.name", "process.executable", "process.command_line")


def test_raw_payload_does_not_match() -> None:
    rule = load_sigma_like_rule()
    raw_payload, _ = build_smoke_payloads(load_fixture())
    raw_payload["process"] = {"name": "powershell.exe"}

    result = evaluate_sigma_like_rule(rule, raw_payload)

    assert result.matched is False


def test_non_event_id_1_does_not_match() -> None:
    rule = load_sigma_like_rule()
    event = powershell_process_event()
    event["event"]["code"] = 3

    result = evaluate_sigma_like_rule(rule, event)

    assert result.matched is False


def test_cmd_with_parent_powershell_does_not_match() -> None:
    rule = load_sigma_like_rule()
    event = normalized_smoke_payload()

    assert event["process"]["name"] == "cmd.exe"
    assert event["process"]["parent"]["name"] == "powershell.exe"

    result = evaluate_sigma_like_rule(rule, event)

    assert result.matched is False


def test_missing_optional_process_fields_do_not_crash() -> None:
    rule = load_sigma_like_rule()
    event = {
        "event": {
            "dataset": "windows.sysmon_operational",
            "code": 1,
        },
        "process": {
            "name": "cmd.exe",
        },
    }

    result = evaluate_sigma_like_rule(rule, event)

    assert result.matched is False
    assert result.matched_fields == ()


def test_alert_builder_sets_sigma_like_engine() -> None:
    rule = load_sigma_like_rule()
    event = powershell_process_event()
    match = evaluate_sigma_like_rule(rule, event)

    alert = build_sigma_like_alert_document(match=match, rule=rule, event=event, created_at="2026-06-17T00:00:00Z")

    assert alert["detection"]["engine"] == "sigma-like"
    assert alert["detection"]["matched_fields"] == [
        "process.name",
        "process.executable",
        "process.command_line",
    ]
    assert alert["rule"]["id"] == "sigma_like.t1059_001.powershell_process_start"


def test_sigma_like_alert_id_differs_from_native_for_same_event() -> None:
    event = powershell_process_event()
    native_rule = load_rule()
    sigma_rule = load_sigma_like_rule()
    native_match = evaluate_rule(native_rule, event)
    sigma_match = evaluate_sigma_like_rule(sigma_rule, event)

    native_alert = build_alert_document(
        match=native_match,
        rule=native_rule,
        event=event,
        created_at="2026-06-17T00:00:00Z",
    )
    sigma_alert = build_sigma_like_alert_document(
        match=sigma_match,
        rule=sigma_rule,
        event=event,
        created_at="2026-06-17T00:00:00Z",
    )

    assert sigma_alert["alert"]["id"].startswith("det-sigma-like-t1059-001-powershell-process-start-")
    assert sigma_alert["alert"]["id"] != native_alert["alert"]["id"]
