from pathlib import Path

import pytest

from normalization.sysmon.file_create_normalizer import normalize_sysmon_event_11
from normalization.sysmon.process_create_normalizer import UnsupportedSysmonEventError


FIXTURE_PATH = Path("samples/sysmon/event_11_file_create.xml")


def load_fixture() -> str:
    return FIXTURE_PATH.read_text(encoding="utf-8")


def test_normalizes_sysmon_event_11_file_create_to_ecs() -> None:
    original_xml = load_fixture()

    normalized = normalize_sysmon_event_11(original_xml)

    assert normalized["@timestamp"] == "2026-06-18T03:11:00.0000000Z"
    assert normalized["event"]["kind"] == "event"
    assert normalized["event"]["category"] == ["file"]
    assert normalized["event"]["type"] == ["creation"]
    assert normalized["event"]["action"] == "File created"
    assert normalized["event"]["code"] == 11
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
        "pid": 6244,
        "entity_id": "{9f7f5c20-1100-6666-0100-000000000402}",
        "name": "powershell.exe",
        "executable": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    }
    assert normalized["file"] == {
        "path": r"C:\Users\edr-lab\Downloads\edr_demo.txt",
        "name": "edr_demo.txt",
        "extension": "txt",
    }
    assert normalized["data_stream"] == {
        "type": "logs",
        "dataset": "windows.sysmon_operational",
        "namespace": "phase12",
    }
    assert normalized["tags"] == ["ecs_normalized", "sysmon_event_11"]


def test_preserves_event_11_original_xml_and_sysmon_event_data() -> None:
    original_xml = load_fixture()

    normalized = normalize_sysmon_event_11(original_xml)

    assert normalized["event"]["original"] == original_xml
    assert normalized["sysmon"]["event_data"]["TargetFilename"] == (
        r"C:\Users\edr-lab\Downloads\edr_demo.txt"
    )
    assert normalized["sysmon"]["event_data"]["ProcessId"] == "6244"


def test_event_11_rejects_other_event_ids() -> None:
    unsupported = load_fixture().replace("<EventID>11</EventID>", "<EventID>13</EventID>")

    with pytest.raises(UnsupportedSysmonEventError, match="Only Sysmon Event ID 11 is supported"):
        normalize_sysmon_event_11(unsupported)
