from scripts.smoke.end_to_end_art_telemetry_smoke import ART_METADATA, build_smoke_payloads, load_fixture


def test_smoke_payloads_preserve_art_metadata() -> None:
    raw_payload, normalized_payload = build_smoke_payloads(load_fixture())

    assert raw_payload["art"]["technique_id"] == "T1059.001"
    assert normalized_payload["art"]["technique_id"] == "T1059.001"
    assert raw_payload["art"] == ART_METADATA
    assert normalized_payload["art"] == ART_METADATA


def test_normalized_payload_preserves_original_event_and_process_fields() -> None:
    original_xml = load_fixture()
    _, normalized_payload = build_smoke_payloads(original_xml)

    assert normalized_payload["event"]["original"] == original_xml
    assert normalized_payload["process"]["name"] == "cmd.exe"
    assert normalized_payload["process"]["executable"] == r"C:\Windows\System32\cmd.exe"
    assert normalized_payload["host"]["name"] == "WIN11-EDR-LAB"


def test_raw_and_normalized_payloads_are_distinguishable() -> None:
    raw_payload, normalized_payload = build_smoke_payloads(load_fixture())

    assert raw_payload["event"]["dataset"] == "edr.raw"
    assert normalized_payload["event"]["dataset"] == "windows.sysmon_operational"
    assert "fixture_smoke" in raw_payload["tags"]
    assert "ecs_normalized" in normalized_payload["tags"]
    assert "sysmon_event_1" in normalized_payload["tags"]
    assert "process" not in raw_payload
    assert "process" in normalized_payload


def test_raw_payload_preserves_original_event() -> None:
    original_xml = load_fixture()
    raw_payload, _ = build_smoke_payloads(original_xml)

    assert raw_payload["event"]["original"] == original_xml
    assert raw_payload["sysmon"]["event_data"]["ProcessId"] == "5824"
