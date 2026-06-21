from pathlib import Path

import pytest

from normalization.sysmon.process_create_normalizer import (
    SysmonNormalizationError,
    UnsupportedSysmonEventError,
    normalize_sysmon_event_1,
)


FIXTURE_PATH = Path("collection/sysmon/fixtures/sysmon_event_1_process_create.xml")


def load_fixture() -> str:
    return FIXTURE_PATH.read_text(encoding="utf-8")


def test_normalizes_sysmon_event_1_process_create_to_ecs() -> None:
    original_xml = load_fixture()

    normalized = normalize_sysmon_event_1(original_xml)

    assert normalized["@timestamp"] == "2026-06-08T02:30:00.0000000Z"
    assert normalized["event"]["kind"] == "event"
    assert normalized["event"]["category"] == ["process"]
    assert normalized["event"]["type"] == ["start"]
    assert normalized["event"]["action"] == "Process Create"
    assert normalized["event"]["code"] == 1
    assert normalized["event"]["module"] == "sysmon"
    assert normalized["event"]["provider"] == "Microsoft-Windows-Sysmon"
    assert normalized["event"]["dataset"] == "windows.sysmon_operational"
    assert normalized["event"]["created"] == "2026-06-08T02:30:00.000Z"

    assert normalized["host"]["name"] == "WIN11-EDR-LAB"
    assert normalized["host"]["os"]["type"] == "windows"
    assert normalized["log"]["channel"] == "Microsoft-Windows-Sysmon/Operational"

    assert normalized["user"]["domain"] == "WIN11-EDR-LAB"
    assert normalized["user"]["name"] == "edr-lab"

    assert normalized["process"]["pid"] == 5824
    assert normalized["process"]["entity_id"] == "{9f7f5c20-1c5d-6666-0100-000000000400}"
    assert normalized["process"]["name"] == "cmd.exe"
    assert normalized["process"]["executable"] == r"C:\Windows\System32\cmd.exe"
    assert normalized["process"]["command_line"] == "cmd.exe /c whoami"
    assert normalized["process"]["args"] == ["cmd.exe", "/c", "whoami"]
    assert normalized["process"]["working_directory"] == "C:\\Users\\edr-lab\\"

    assert normalized["process"]["parent"]["pid"] == 4460
    assert normalized["process"]["parent"]["entity_id"] == "{9f7f5c20-1c58-6666-ff00-000000000400}"
    assert normalized["process"]["parent"]["name"] == "powershell.exe"
    assert normalized["process"]["parent"]["executable"] == (
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    )
    assert normalized["process"]["parent"]["command_line"] == "powershell.exe -NoLogo"
    assert normalized["process"]["parent"]["user"] == {
        "domain": "WIN11-EDR-LAB",
        "name": "edr-lab",
    }

    assert normalized["process"]["hash"]["sha256"] == (
        "3A6B4F0E8F2E0F5C7F1D5153E6C7A2A8069E5D73B98B3B764D0C5E8E5A7F7B1D"
    )
    assert normalized["process"]["hash"]["imphash"] == "272245E2988E1D30F6E9DE0F6FFB6B6B"
    assert normalized["process"]["Ext"]["token"]["integrity_level_name"] == "Medium"

    assert normalized["data_stream"] == {
        "type": "logs",
        "dataset": "windows.sysmon_operational",
        "namespace": "phase1",
    }
    assert normalized["tags"] == ["ecs_normalized", "sysmon_event_1"]


def test_preserves_original_xml_and_sysmon_event_data() -> None:
    original_xml = load_fixture()

    normalized = normalize_sysmon_event_1(original_xml)

    assert normalized["event"]["original"] == original_xml
    assert normalized["sysmon"]["event_data"]["Image"] == r"C:\Windows\System32\cmd.exe"
    assert normalized["sysmon"]["event_data"]["ProcessId"] == "5824"
    assert normalized["sysmon"]["event_data"]["ParentImage"] == (
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    )
    assert normalized["sysmon"]["event_data"]["Hashes"].startswith("SHA256=")


def test_rejects_unsupported_event_ids() -> None:
    unsupported = load_fixture().replace("<EventID>1</EventID>", "<EventID>3</EventID>")

    with pytest.raises(UnsupportedSysmonEventError, match="Only Sysmon Event ID 1 is supported"):
        normalize_sysmon_event_1(unsupported)


def test_malformed_xml_returns_predictable_error() -> None:
    with pytest.raises(SysmonNormalizationError, match="Malformed Sysmon XML"):
        normalize_sysmon_event_1("<Event>")
