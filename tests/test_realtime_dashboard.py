import base64
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from scripts.realtime import run_realtime_dashboard
from scripts.realtime.realtime_core import (
    RealtimeElasticsearchSink,
    RealtimeEvaluationTracker,
    T1105RealtimeCorrelator,
    build_summary,
    normalize_sysmon_message_event,
    parse_sysmon_message,
    run_realtime_rules,
)


ROOT = Path(__file__).resolve().parents[1]


PROCESS_MESSAGE = r"""
Process Create:
RuleName: -
UtcTime: 2026-06-21 01:00:00.000
ProcessGuid: {demo-process}
ProcessId: 4242
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
CommandLine: powershell.exe -NoProfile -Command Write-Output EDR_DEMO_T1059_001
CurrentDirectory: C:\Users\Khai
User: LAB\Khai
ParentProcessGuid: {demo-parent}
ParentProcessId: 4000
ParentImage: C:\Windows\explorer.exe
ParentCommandLine: explorer.exe
ParentUser: LAB\Khai
Hashes: SHA256=abc
"""


NETWORK_MESSAGE = r"""
Network connection detected:
UtcTime: 2026-06-21 01:00:10.000
ProcessGuid: {demo-process}
ProcessId: 4242
Image: C:\Windows\System32\curl.exe
User: LAB\Khai
Protocol: tcp
Initiated: true
SourceIp: 127.0.0.1
SourcePort: 50000
DestinationIp: 127.0.0.1
DestinationHostname: localhost
DestinationPort: 18085
"""


FILE_MESSAGE = r"""
File created:
UtcTime: 2026-06-21 01:00:20.000
ProcessGuid: {demo-process}
ProcessId: 4242
Image: C:\Windows\System32\curl.exe
TargetFilename: C:\Users\Khai\AppData\Local\Temp\edr_demo_t1105_EDR_DEMO_T1105.txt
CreationUtcTime: 2026-06-21 01:00:20.000
User: LAB\Khai
"""


REGISTRY_MESSAGE = r"""
Registry value set:
UtcTime: 2026-06-21 01:00:30.000
ProcessGuid: {demo-reg}
ProcessId: 5000
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
TargetObject: HKU\S-1-5-21\Software\Microsoft\Windows\CurrentVersion\Run\EDRDemoRealtime
Details: powershell.exe -NoProfile -Command Write-Output EDR_DEMO_T1547
User: LAB\Khai
"""


RUNDLL32_MESSAGE = r"""
Process Create:
UtcTime: 2026-06-21 01:00:40.000
ProcessGuid: {demo-rundll32}
ProcessId: 6000
Image: C:\Windows\System32\rundll32.exe
CommandLine: rundll32.exe url.dll,FileProtocolHandler file:///C:/Temp/EDR_DEMO_T1218.txt
CurrentDirectory: C:\Windows\System32
User: LAB\Khai
ParentProcessGuid: {demo-parent}
ParentProcessId: 4000
ParentImage: C:\Windows\explorer.exe
ParentCommandLine: explorer.exe
ParentUser: LAB\Khai
"""


BENIGN_CMD_MESSAGE = r"""
Process Create:
UtcTime: 2026-06-21 01:00:00.000
ProcessGuid: {demo-benign-cmd}
ProcessId: 7000
Image: C:\Windows\System32\cmd.exe
CommandLine: cmd.exe /c echo EDR_BENIGN_CMD
CurrentDirectory: C:\Users\Khai
User: LAB\Khai
ParentProcessGuid: {demo-parent}
ParentProcessId: 4000
ParentImage: C:\Windows\explorer.exe
ParentCommandLine: explorer.exe
ParentUser: LAB\Khai
"""


def normalize_message(event_code: int, message: str, record_id: int) -> dict:
    return normalize_sysmon_message_event(
        event_code=event_code,
        message=message,
        record_id=record_id,
        provider_name="Microsoft-Windows-Sysmon",
        time_created="2026-06-21T01:00:00Z",
    )


def test_parse_sysmon_message_extracts_key_fields() -> None:
    fields = parse_sysmon_message(PROCESS_MESSAGE)

    assert fields["UtcTime"] == "2026-06-21 01:00:00.000"
    assert fields["Image"].endswith(r"powershell.exe")
    assert "EDR_DEMO_T1059_001" in fields["CommandLine"]
    assert fields["ParentImage"] == r"C:\Windows\explorer.exe"


def test_message_fallback_normalizes_sysmon_event_1_3_11_13() -> None:
    process = normalize_message(1, PROCESS_MESSAGE, 101)
    network = normalize_message(3, NETWORK_MESSAGE, 102)
    file_event = normalize_message(11, FILE_MESSAGE, 103)
    registry = normalize_message(13, REGISTRY_MESSAGE, 104)

    assert process["event"]["code"] == 1
    assert process["process"]["name"] == "powershell.exe"
    assert process["process"]["parent"]["name"] == "explorer.exe"

    assert network["event"]["code"] == 3
    assert network["destination"] == {"ip": "127.0.0.1", "port": 18085, "domain": "localhost"}

    assert file_event["event"]["code"] == 11
    assert file_event["file"]["path"].endswith("edr_demo_t1105_EDR_DEMO_T1105.txt")

    assert registry["event"]["code"] == 13
    assert registry["registry"]["value"] == "EDRDemoRealtime"


def test_message_fallback_normalizes_sysmon_event_1_process_create() -> None:
    event = normalize_message(1, PROCESS_MESSAGE, 111)

    assert event["event"]["dataset"] == "windows.sysmon_operational"
    assert event["event"]["code"] == 1
    assert event["process"]["name"] == "powershell.exe"
    assert event["process"]["command_line"].endswith("EDR_DEMO_T1059_001")


def test_message_fallback_normalizes_sysmon_event_3_network_connection() -> None:
    event = normalize_message(3, NETWORK_MESSAGE, 112)

    assert event["event"]["code"] == 3
    assert event["process"]["name"] == "curl.exe"
    assert event["destination"]["ip"] == "127.0.0.1"
    assert event["destination"]["port"] == 18085


def test_message_fallback_normalizes_sysmon_event_11_file_create() -> None:
    event = normalize_message(11, FILE_MESSAGE, 113)

    assert event["event"]["code"] == 11
    assert event["file"]["name"] == "edr_demo_t1105_EDR_DEMO_T1105.txt"
    assert event["file"]["path"].endswith("edr_demo_t1105_EDR_DEMO_T1105.txt")


def test_message_fallback_normalizes_sysmon_event_13_registry_value_set() -> None:
    event = normalize_message(13, REGISTRY_MESSAGE, 114)

    assert event["event"]["code"] == 13
    assert event["registry"]["path"].endswith(r"CurrentVersion\Run\EDRDemoRealtime")
    assert event["registry"]["data"]["strings"] == ["powershell.exe -NoProfile -Command Write-Output EDR_DEMO_T1547"]


def test_realtime_rule_mapping_generates_expected_attack_techniques() -> None:
    events = [
        normalize_message(1, PROCESS_MESSAGE, 201),
        normalize_message(1, PROCESS_MESSAGE.replace("powershell.exe", "curl.exe").replace("EDR_DEMO_T1059_001", "EDR_DEMO_T1105"), 202),
        normalize_message(13, REGISTRY_MESSAGE, 203),
        normalize_message(1, RUNDLL32_MESSAGE, 204),
    ]

    alerts = [alert for event in events for alert in run_realtime_rules(event)]
    techniques = {alert["attack"]["technique"]["id"] for alert in alerts}

    assert {"T1059.001", "T1105", "T1547.001", "T1218"}.issubset(techniques)
    assert all(alert["detection"]["engine"] == "realtime-native" for alert in alerts)


def test_alert_document_contains_dashboard_fields_and_rule_owned_attack_mapping() -> None:
    event = normalize_message(1, PROCESS_MESSAGE, 301)
    event["attack"] = {"technique": {"id": "SHOULD_NOT_BE_TRUSTED"}}

    alert = run_realtime_rules(event)[0]

    assert alert["alert"]["id"]
    assert alert["@timestamp"] == "2026-06-21T01:00:00.000Z"
    assert alert["timestamp"] == "2026-06-21T01:00:00.000Z"
    assert alert["rule"]["id"] == "det.realtime.t1059_001.powershell_execution"
    assert alert["detection"]["engine"] == "realtime-native"
    assert alert["detection"]["matched_fields"] == ["process.name", "process.command_line"]
    assert alert["event"]["code"] == "1"
    assert alert["event"]["dataset"] == "windows.sysmon_operational"
    assert alert["severity"] == "medium"
    assert alert["confidence"] == "high"
    assert alert["attack"]["technique"]["id"] == "T1059.001"
    assert "EDR_DEMO_T1059_001" in alert["evidence"]["process.command_line"]
    assert "reason" in alert


def test_t1105_behavioral_correlation_matches_process_network_file_window() -> None:
    process = normalize_message(1, PROCESS_MESSAGE.replace("powershell.exe", "curl.exe").replace("EDR_DEMO_T1059_001", "EDR_DEMO_T1105"), 401)
    network = normalize_message(3, NETWORK_MESSAGE, 402)
    file_event = normalize_message(11, FILE_MESSAGE, 403)
    correlator = T1105RealtimeCorrelator(window_seconds=300)

    assert correlator.add_event(process) == []
    assert correlator.add_event(network) == []
    alerts = correlator.add_event(file_event)

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert["rule"]["id"] == "behavioral.realtime.t1105.process_network_file"
    assert alert["detection"]["engine"] == "behavioral"
    assert alert["detection"]["sequence_steps"] == ["process", "network", "file"]
    assert alert["attack"]["technique"]["id"] == "T1105"


def test_summary_aggregates_realtime_events_and_alerts() -> None:
    event = normalize_message(1, PROCESS_MESSAGE, 501)
    alert = run_realtime_rules(event)[0]

    summary = build_summary(events=[event], alerts=[alert], started_at="2026-06-21T00:00:00Z")

    assert summary["event_count"] == 1
    assert summary["alert_count"] == 1
    assert summary["event_count_by_code"] == {"1": 1}
    assert summary["alert_count_by_technique"] == {"T1059.001": 1}
    assert summary["alert_count_by_engine"] == {"realtime-native": 1}
    assert summary["collector"] == "stopped"
    assert summary["elasticsearch"] == "disconnected"


def test_realtime_elasticsearch_sink_uses_realtime_index_prefixes(monkeypatch: pytest.MonkeyPatch) -> None:
    captured = []
    event = normalize_message(1, PROCESS_MESSAGE, 601)
    alert = run_realtime_rules(event)[0]

    def fake_index_event(document: dict, config: object) -> object:
        captured.append(("event", config.base_url, config.timeout_seconds, config.index_prefix, document["event"]["id"]))
        return object()

    def fake_index_alert(document: dict, config: object) -> object:
        captured.append(("alert", config.base_url, config.timeout_seconds, config.index_prefix, document["alert"]["id"]))
        return object()

    monkeypatch.setattr("scripts.realtime.realtime_core.index_normalized_event", fake_index_event)
    monkeypatch.setattr("scripts.realtime.realtime_core.index_native_alert", fake_index_alert)

    sink = RealtimeElasticsearchSink(base_url="http://192.168.213.1:9200", timeout_seconds=2)

    assert sink.index_event(event) is True
    assert sink.index_alert(alert) is True
    assert sink.status == "connected"
    assert captured == [
        ("event", "http://192.168.213.1:9200", 2, "edr-realtime-events", "601"),
        ("alert", "http://192.168.213.1:9200", 2, "edr-realtime-alerts", alert["alert"]["id"]),
    ]


def test_realtime_evaluation_marks_expected_alert_as_true_positive() -> None:
    event = normalize_message(1, PROCESS_MESSAGE, 701)
    alert = run_realtime_rules(event)[0]
    tracker = RealtimeEvaluationTracker()

    tracker.observe_event(event)
    pending = tracker.snapshot(now=datetime(2026, 6, 21, 1, 0, 1, tzinfo=UTC))
    tracker.observe_alert(alert)
    evaluated = tracker.snapshot(now=datetime(2026, 6, 21, 1, 0, 2, tzinfo=UTC))

    assert pending["counts"]["pending"] == 1
    assert evaluated["counts"]["true_positive"] == 1
    case = next(item for item in evaluated["cases"] if item["case_id"] == "rt_t1059_001_powershell_marker")
    assert case["classification"] == "true_positive"
    assert case["actual_rule_ids"] == ["det.realtime.t1059_001.powershell_execution"]


def test_realtime_evaluation_marks_benign_marker_as_true_negative_after_window() -> None:
    event = normalize_message(1, BENIGN_CMD_MESSAGE, 702)
    tracker = RealtimeEvaluationTracker()

    tracker.observe_event(event)
    early = tracker.snapshot(now=datetime(2026, 6, 21, 1, 0, 2, tzinfo=UTC))
    evaluated = tracker.snapshot(now=datetime(2026, 6, 21, 1, 0, 7, tzinfo=UTC))

    assert early["counts"]["pending"] == 1
    assert evaluated["counts"]["true_negative"] == 1
    case = next(item for item in evaluated["cases"] if item["case_id"] == "rt_benign_cmd_marker")
    assert case["classification"] == "true_negative"
    assert case["reason"] == "Benign realtime marker produced no alert during the evaluation window."


def test_query_sysmon_events_uses_utf8_decoding_for_powershell_output(monkeypatch: pytest.MonkeyPatch) -> None:
    captured = {}
    payload = [
        {
            "RecordId": 701,
            "Id": 1,
            "TimeCreated": "2026-06-21T01:00:00Z",
            "ProviderName": "Microsoft-Windows-Sysmon",
            "Message": "Process Create: tiếng Việt EDR_DEMO_T1059_001",
            "Xml": "<Event />",
        }
    ]

    class Completed:
        returncode = 0
        stdout = json.dumps(payload, ensure_ascii=False)
        stderr = ""

    def fake_run(command: list[str], **kwargs: object) -> Completed:
        captured["command"] = command
        captured["kwargs"] = kwargs
        encoded_script = command[-1]
        captured["script"] = base64.b64decode(encoded_script).decode("utf-16le")
        return Completed()

    monkeypatch.setattr("subprocess.run", fake_run)

    records = run_realtime_dashboard.query_sysmon_events(
        log_name="Microsoft-Windows-Sysmon/Operational",
        event_ids=(1,),
        start_time=datetime(2026, 6, 21, tzinfo=UTC),
        timeout_seconds=5,
    )

    assert captured["command"][:3] == ["powershell.exe", "-NoProfile", "-NonInteractive"]
    assert captured["kwargs"]["encoding"] == "utf-8"
    assert captured["kwargs"]["errors"] == "replace"
    assert "[Console]::OutputEncoding" in captured["script"]
    assert "$OutputEncoding" in captured["script"]
    assert records[0].message == "Process Create: tiếng Việt EDR_DEMO_T1059_001"


def test_dashboard_realtime_fallback_is_present_without_api() -> None:
    html = (ROOT / "dashboard" / "static" / "index.html").read_text(encoding="utf-8")
    app = (ROOT / "dashboard" / "static" / "app.js").read_text(encoding="utf-8")

    assert "Realtime: disconnected / using static data" in html
    assert "http://localhost:8090" in app
    assert "loadStaticRealtimeSnapshot" in app
    assert "data/realtime_summary.json" in app
    assert "data/realtime_evaluation.json" in app
    assert "/api/evaluation" in app
    assert "Realtime Evaluation" in html
    assert "offline / static snapshot" in app
    assert "window.setInterval(fetchRealtimeSnapshot, REALTIME_REFRESH_MS)" in app
    assert "lastError: error instanceof Error ? error.message : String(error)" in app
