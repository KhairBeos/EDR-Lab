import copy

import pytest

from detection.rules.native import RuleValidationError, evaluate_rule, load_rule, validate_rule
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


def test_loads_native_powershell_rule_metadata() -> None:
    rule = load_rule()

    assert rule["id"] == "det.t1059_001.powershell_process_start"
    assert rule["version"] == 1
    assert rule["severity"] == "medium"
    assert rule["confidence"] == "high"
    assert rule["attack"]["technique_id"] == "T1059.001"
    assert rule["attack"]["technique_name"] == "PowerShell"
    assert rule["attack"]["tactic"] == ["Execution"]
    assert rule["data_source"]["event_dataset"] == "windows.sysmon_operational"
    assert rule["data_source"]["event_code"] == 1


def test_matches_powershell_process_name() -> None:
    rule = load_rule()
    payload = powershell_process_event()
    payload["process"]["executable"] = r"C:\Windows\System32\notepad.exe"
    payload["process"]["command_line"] = "notepad.exe"

    result = evaluate_rule(rule, payload)

    assert result.matched is True
    assert result.rule_id == "det.t1059_001.powershell_process_start"
    assert result.matched_fields == ("process.name",)


def test_matches_powershell_process_executable() -> None:
    rule = load_rule()
    payload = powershell_process_event()
    payload["process"]["name"] = "notepad.exe"
    payload["process"]["command_line"] = "notepad.exe"

    result = evaluate_rule(rule, payload)

    assert result.matched is True
    assert result.matched_fields == ("process.executable",)


def test_matches_powershell_process_command_line() -> None:
    rule = load_rule()
    payload = powershell_process_event()
    payload["process"]["name"] = "notepad.exe"
    payload["process"]["executable"] = r"C:\Tools\notepad.exe"

    result = evaluate_rule(rule, payload)

    assert result.matched is True
    assert result.matched_fields == ("process.command_line",)


def test_matching_is_case_insensitive() -> None:
    rule = load_rule()
    payload = powershell_process_event()
    payload["process"]["name"] = "PowerShell.EXE"
    payload["process"]["executable"] = r"C:\Windows\System32\WindowsPowerShell\v1.0\PowerShell.EXE"
    payload["process"]["command_line"] = "PowerShell.EXE -NoLogo"

    result = evaluate_rule(rule, payload)

    assert result.matched is True
    assert result.matched_fields == ("process.name", "process.executable", "process.command_line")


def test_raw_payload_does_not_match() -> None:
    rule = load_rule()
    raw_payload, _ = build_smoke_payloads(load_fixture())
    raw_payload["process"] = {"name": "powershell.exe"}

    result = evaluate_rule(rule, raw_payload)

    assert result.matched is False
    assert result.matched_fields == ()


def test_non_event_id_1_does_not_match() -> None:
    rule = load_rule()
    payload = powershell_process_event()
    payload["event"]["code"] = 3

    result = evaluate_rule(rule, payload)

    assert result.matched is False
    assert result.matched_fields == ()


def test_cmd_with_parent_powershell_does_not_match() -> None:
    rule = load_rule()
    payload = normalized_smoke_payload()

    assert payload["process"]["name"] == "cmd.exe"
    assert payload["process"]["parent"]["name"] == "powershell.exe"

    result = evaluate_rule(rule, payload)

    assert result.matched is False
    assert result.matched_fields == ()


def test_missing_optional_fields_do_not_crash_evaluator() -> None:
    rule = load_rule()
    payload = {
        "event": {
            "dataset": "windows.sysmon_operational",
            "code": 1,
        },
        "process": {
            "name": "cmd.exe",
        },
    }

    result = evaluate_rule(rule, payload)

    assert result.matched is False
    assert result.matched_fields == ()


def test_invalid_rule_metadata_fails_with_clear_validation_error() -> None:
    rule = copy.deepcopy(load_rule())
    del rule["attack"]["technique_id"]

    with pytest.raises(RuleValidationError, match="technique_id"):
        validate_rule(rule)
