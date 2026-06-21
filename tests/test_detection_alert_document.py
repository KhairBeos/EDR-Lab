import copy

import pytest

from detection.rules.native import (
    AlertDocumentError,
    MatchResult,
    RuleValidationError,
    build_alert_document,
    evaluate_rule,
    load_rule,
)
from scripts.smoke.end_to_end_art_telemetry_smoke import build_smoke_payloads, load_fixture


FIXED_CREATED_AT = "2026-06-16T15:30:00Z"


def powershell_process_event() -> dict:
    _, normalized_payload = build_smoke_payloads(load_fixture())
    payload = copy.deepcopy(normalized_payload)
    payload["process"]["name"] = "powershell.exe"
    payload["process"]["executable"] = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    payload["process"]["command_line"] = "powershell.exe -NoLogo"
    payload["process"]["args"] = ["powershell.exe", "-NoLogo"]
    return payload


def matched_powershell_inputs() -> tuple[dict, dict, MatchResult]:
    rule = load_rule()
    event = powershell_process_event()
    match = evaluate_rule(rule, event)
    assert match.matched is True
    return rule, event, match


def test_builds_alert_document_from_matched_powershell_rule() -> None:
    rule, event, match = matched_powershell_inputs()

    alert = build_alert_document(match=match, rule=rule, event=event, created_at=FIXED_CREATED_AT)

    assert alert["alert"]["kind"] == "signal"
    assert alert["alert"]["status"] == "open"
    assert alert["alert"]["created"] == FIXED_CREATED_AT
    assert alert["alert"]["severity"] == "medium"
    assert alert["alert"]["confidence"] == "high"
    assert alert["alert"]["id"].startswith("det-t1059-001-powershell-process-start-")

    assert alert["rule"] == {
        "id": "det.t1059_001.powershell_process_start",
        "name": "PowerShell Process Execution",
        "version": 1,
        "description": "Detects Windows PowerShell process creation from normalized Sysmon Event ID 1 ECS documents.",
    }
    assert alert["attack"] == {
        "technique": {
            "id": "T1059.001",
            "name": "PowerShell",
        },
        "tactic": ["Execution"],
    }
    assert alert["event"]["dataset"] == "windows.sysmon_operational"
    assert alert["event"]["code"] == 1
    assert alert["event"]["kind"] == "event"
    assert alert["event"]["category"] == ["process"]
    assert alert["event"]["type"] == ["start"]
    assert alert["event"]["created"] == "2026-06-08T02:30:00.000Z"
    assert alert["host"]["name"] == "WIN11-EDR-LAB"
    assert alert["user"]["name"] == "edr-lab"
    assert alert["process"]["name"] == "powershell.exe"
    assert alert["process"]["executable"] == r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    assert alert["process"]["command_line"] == "powershell.exe -NoLogo"
    assert alert["process"]["parent"]["name"] == "powershell.exe"
    assert alert["detection"]["matched_fields"] == [
        "process.name",
        "process.executable",
        "process.command_line",
    ]
    assert alert["art"]["technique_id"] == "T1059.001"


def test_non_matching_result_raises_clear_error() -> None:
    rule = load_rule()
    event = powershell_process_event()
    match = MatchResult(matched=False, rule_id=rule["id"], matched_fields=())

    with pytest.raises(AlertDocumentError, match="non-matching rule"):
        build_alert_document(match=match, rule=rule, event=event, created_at=FIXED_CREATED_AT)


def test_invalid_rule_metadata_raises_validation_error() -> None:
    rule, event, match = matched_powershell_inputs()
    del rule["attack"]["technique_id"]

    with pytest.raises(RuleValidationError, match="technique_id"):
        build_alert_document(match=match, rule=rule, event=event, created_at=FIXED_CREATED_AT)


def test_alert_preserves_source_when_present() -> None:
    rule, event, match = matched_powershell_inputs()

    alert = build_alert_document(
        match=match,
        rule=rule,
        event=event,
        created_at=FIXED_CREATED_AT,
        source={"index": "edr-raw-events-2026.06.16", "document_id": "elastic-doc-id"},
    )

    assert alert["source"] == {
        "index": "edr-raw-events-2026.06.16",
        "document_id": "elastic-doc-id",
    }


def test_alert_id_is_deterministic_for_same_input() -> None:
    rule, event, match = matched_powershell_inputs()

    first = build_alert_document(match=match, rule=rule, event=event, created_at=FIXED_CREATED_AT)
    second = build_alert_document(match=match, rule=rule, event=event, created_at=FIXED_CREATED_AT)

    assert first["alert"]["id"] == second["alert"]["id"]


def test_alert_id_changes_when_source_identity_changes() -> None:
    rule, event, match = matched_powershell_inputs()

    first = build_alert_document(
        match=match,
        rule=rule,
        event=event,
        created_at=FIXED_CREATED_AT,
        source={"document_id": "doc-1"},
    )
    second = build_alert_document(
        match=match,
        rule=rule,
        event=event,
        created_at=FIXED_CREATED_AT,
        source={"document_id": "doc-2"},
    )

    assert first["alert"]["id"] != second["alert"]["id"]


def test_missing_optional_evidence_is_omitted_without_crashing() -> None:
    rule = load_rule()
    event = {
        "event": {
            "dataset": "windows.sysmon_operational",
            "code": 1,
        },
        "process": {
            "name": "powershell.exe",
        },
    }
    match = evaluate_rule(rule, event)

    alert = build_alert_document(match=match, rule=rule, event=event, created_at=FIXED_CREATED_AT)

    assert alert["event"] == {
        "dataset": "windows.sysmon_operational",
        "code": 1,
    }
    assert alert["process"] == {
        "name": "powershell.exe",
    }
    assert "host" not in alert
    assert "user" not in alert
    assert "art" not in alert
    assert "source" not in alert


def test_alert_does_not_copy_event_original_or_mutate_input() -> None:
    rule, event, match = matched_powershell_inputs()
    original_event = copy.deepcopy(event)

    alert = build_alert_document(match=match, rule=rule, event=event, created_at=FIXED_CREATED_AT)

    assert "original" not in alert["event"]
    assert event == original_event
