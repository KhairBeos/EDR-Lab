from pathlib import Path

import pytest

from normalization.sysmon.event_router import normalize_sysmon_event
from normalization.sysmon.process_create_normalizer import (
    SysmonNormalizationError,
    UnsupportedSysmonEventError,
    normalize_sysmon_event_1,
)


EVENT_1_PATH = Path("collection/sysmon/fixtures/sysmon_event_1_process_create.xml")
EVENT_3_PATH = Path("samples/sysmon/event_3_network_connection.xml")
EVENT_11_PATH = Path("samples/sysmon/event_11_file_create.xml")
EVENT_13_PATH = Path("samples/sysmon/event_13_registry_value_set.xml")


def read_xml(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_routes_event_id_1_to_existing_process_create_normalizer() -> None:
    xml = read_xml(EVENT_1_PATH)

    assert normalize_sysmon_event(xml) == normalize_sysmon_event_1(xml)


@pytest.mark.parametrize(
    ("path", "event_code", "expected_tag"),
    [
        (EVENT_3_PATH, 3, "sysmon_event_3"),
        (EVENT_11_PATH, 11, "sysmon_event_11"),
        (EVENT_13_PATH, 13, "sysmon_event_13"),
    ],
)
def test_routes_supported_multi_event_sysmon_xml(path: Path, event_code: int, expected_tag: str) -> None:
    normalized = normalize_sysmon_event(read_xml(path))

    assert normalized["event"]["code"] == event_code
    assert expected_tag in normalized["tags"]


def test_router_rejects_unsupported_event_id() -> None:
    xml = read_xml(EVENT_3_PATH).replace("<EventID>3</EventID>", "<EventID>22</EventID>")

    with pytest.raises(UnsupportedSysmonEventError, match="Unsupported Sysmon Event ID"):
        normalize_sysmon_event(xml)


def test_router_returns_clear_error_for_invalid_xml() -> None:
    with pytest.raises(SysmonNormalizationError, match="Malformed Sysmon XML"):
        normalize_sysmon_event("<Event>")
