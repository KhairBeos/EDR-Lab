from pathlib import Path

import pytest

from normalization.sysmon.network_connection_normalizer import normalize_sysmon_event_3
from normalization.sysmon.process_create_normalizer import UnsupportedSysmonEventError


FIXTURE_PATH = Path("samples/sysmon/event_3_network_connection.xml")


def load_fixture() -> str:
    return FIXTURE_PATH.read_text(encoding="utf-8")


def test_normalizes_sysmon_event_3_network_connection_to_ecs() -> None:
    original_xml = load_fixture()

    normalized = normalize_sysmon_event_3(original_xml)

    assert normalized["@timestamp"] == "2026-06-18T03:10:00.0000000Z"
    assert normalized["event"]["kind"] == "event"
    assert normalized["event"]["category"] == ["network"]
    assert normalized["event"]["type"] == ["connection"]
    assert normalized["event"]["action"] == "Network connection detected"
    assert normalized["event"]["code"] == 3
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
        "pid": 6120,
        "entity_id": "{9f7f5c20-3000-6666-0100-000000000401}",
        "name": "certutil.exe",
        "executable": r"C:\Windows\System32\certutil.exe",
    }
    assert normalized["source"] == {
        "ip": "127.0.0.1",
        "port": 49712,
    }
    assert normalized["destination"] == {
        "ip": "127.0.0.1",
        "port": 80,
        "domain": "example.test",
    }
    assert normalized["network"] == {
        "transport": "tcp",
        "direction": "outbound",
    }
    assert normalized["data_stream"] == {
        "type": "logs",
        "dataset": "windows.sysmon_operational",
        "namespace": "phase12",
    }
    assert normalized["tags"] == ["ecs_normalized", "sysmon_event_3"]


def test_preserves_event_3_original_xml_and_sysmon_event_data() -> None:
    original_xml = load_fixture()

    normalized = normalize_sysmon_event_3(original_xml)

    assert normalized["event"]["original"] == original_xml
    assert normalized["sysmon"]["event_data"]["Image"] == r"C:\Windows\System32\certutil.exe"
    assert normalized["sysmon"]["event_data"]["DestinationHostname"] == "example.test"
    assert normalized["sysmon"]["event_data"]["Initiated"] == "true"


def test_event_3_rejects_other_event_ids() -> None:
    unsupported = load_fixture().replace("<EventID>3</EventID>", "<EventID>11</EventID>")

    with pytest.raises(UnsupportedSysmonEventError, match="Only Sysmon Event ID 3 is supported"):
        normalize_sysmon_event_3(unsupported)
