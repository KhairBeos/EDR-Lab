from pathlib import Path

import pytest

from normalization.sysmon.process_create_normalizer import UnsupportedSysmonEventError
from normalization.sysmon.registry_value_set_normalizer import normalize_sysmon_event_13


FIXTURE_PATH = Path("samples/sysmon/event_13_registry_value_set.xml")


def load_fixture() -> str:
    return FIXTURE_PATH.read_text(encoding="utf-8")


def test_normalizes_sysmon_event_13_registry_value_set_to_ecs() -> None:
    original_xml = load_fixture()

    normalized = normalize_sysmon_event_13(original_xml)

    assert normalized["@timestamp"] == "2026-06-18T03:13:00.0000000Z"
    assert normalized["event"]["kind"] == "event"
    assert normalized["event"]["category"] == ["registry"]
    assert normalized["event"]["type"] == ["change"]
    assert normalized["event"]["action"] == "Registry value set"
    assert normalized["event"]["code"] == 13
    assert normalized["event"]["module"] == "sysmon"
    assert normalized["event"]["provider"] == "Microsoft-Windows-Sysmon"
    assert normalized["event"]["dataset"] == "windows.sysmon_operational"

    assert normalized["host"]["name"] == "WIN11-EDR-LAB"
    assert normalized["host"]["os"]["type"] == "windows"
    assert normalized["log"]["channel"] == "Microsoft-Windows-Sysmon/Operational"
    assert normalized["user"] == {
        "domain": "WIN11-EDR-LAB",
        "name": "edr-lab",
    }
    assert normalized["process"] == {
        "pid": 6300,
        "entity_id": "{9f7f5c20-1300-6666-0100-000000000403}",
        "name": "reg.exe",
        "executable": r"C:\Windows\System32\reg.exe",
    }
    assert normalized["registry"] == {
        "path": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\EDRDemo",
        "value": "EDRDemo",
        "data": {
            "strings": [r"C:\Users\edr-lab\EDRDemo\edr-demo.exe"],
        },
    }
    assert normalized["data_stream"] == {
        "type": "logs",
        "dataset": "windows.sysmon_operational",
        "namespace": "phase12",
    }
    assert normalized["tags"] == ["ecs_normalized", "sysmon_event_13"]


def test_preserves_event_13_original_xml_and_sysmon_event_data() -> None:
    original_xml = load_fixture()

    normalized = normalize_sysmon_event_13(original_xml)

    assert normalized["event"]["original"] == original_xml
    assert normalized["sysmon"]["event_data"]["TargetObject"] == (
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\EDRDemo"
    )
    assert normalized["sysmon"]["event_data"]["Details"] == (
        r"C:\Users\edr-lab\EDRDemo\edr-demo.exe"
    )


def test_event_13_rejects_other_event_ids() -> None:
    unsupported = load_fixture().replace("<EventID>13</EventID>", "<EventID>3</EventID>")

    with pytest.raises(UnsupportedSysmonEventError, match="Only Sysmon Event ID 13 is supported"):
        normalize_sysmon_event_13(unsupported)
