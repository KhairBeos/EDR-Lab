import copy
import json
import sys
from datetime import date

import pytest

from response.soar.engine import build_response_record, find_matching_playbook, plan_responses
from response.soar.loader import SoarPlaybookValidationError, load_playbook
from response.soar.response_indexer import (
    ResponseIndexResult,
    ResponseIndexingConfig,
    ResponseIndexingError,
    build_response_index_name,
    index_response,
)
from scripts.detection import run_native_detection
from scripts.response import run_soar_response


FIXED_CREATED_AT = "2026-06-17T10:00:00Z"


def native_alert() -> dict:
    return run_native_detection.run_native_detection()["alerts"][0]


def sigma_like_alert() -> dict:
    alert = copy.deepcopy(native_alert())
    alert["alert"]["id"] = "det-sigma-like-t1059-001-powershell-process-start-test"
    alert["rule"]["id"] = "sigma_like.t1059_001.powershell_process_start"
    alert["detection"]["engine"] = "sigma-like"
    return alert


def equivalent_attack_alert() -> dict:
    alert = copy.deepcopy(native_alert())
    alert["alert"]["id"] = "equivalent-alert-t1059-001"
    alert.pop("rule")
    return alert


def non_matching_alert() -> dict:
    alert = copy.deepcopy(native_alert())
    alert["alert"]["id"] = "non-matching-alert"
    alert["rule"]["id"] = "det.t0000.not_powershell"
    alert["attack"]["technique"]["id"] = "T0000"
    alert["art"]["technique_id"] = "T0000"
    return alert


def test_playbook_loader_validates_metadata() -> None:
    playbook = load_playbook()

    assert playbook["id"] == "soar.playbook.powershell_execution"
    assert playbook["name"] == "PowerShell Execution Response"
    assert playbook["status"] == "dry-run"


def test_loader_rejects_missing_playbook_id(tmp_path) -> None:
    path = tmp_path / "bad.yml"
    path.write_text(
        "\n".join(
            [
                "name: Bad",
                "status: dry-run",
                "description: Missing id.",
                "match:",
                "  rule_ids:",
                "    - det.t1059_001.powershell_process_start",
                "actions:",
                "  - id: notify_analyst",
                "    type: notification",
                "    status: planned",
                "    description: Notify.",
            ]
        ),
        encoding="utf-8",
    )

    with pytest.raises(SoarPlaybookValidationError, match="id"):
        load_playbook(path)


def test_loader_rejects_non_dry_run_status(tmp_path) -> None:
    path = tmp_path / "bad.yml"
    path.write_text(_playbook_text(status="active"), encoding="utf-8")

    with pytest.raises(SoarPlaybookValidationError, match="dry-run"):
        load_playbook(path)


def test_loader_rejects_non_planned_action(tmp_path) -> None:
    path = tmp_path / "bad.yml"
    path.write_text(_playbook_text(action_status="executed"), encoding="utf-8")

    with pytest.raises(SoarPlaybookValidationError, match="planned"):
        load_playbook(path)


def test_playbook_matches_native_powershell_alert_by_rule_id() -> None:
    assert find_matching_playbook(native_alert(), [load_playbook()]) is not None


def test_playbook_matches_sigma_like_alert_by_rule_id() -> None:
    assert find_matching_playbook(sigma_like_alert(), [load_playbook()]) is not None


def test_playbook_matches_equivalent_alert_by_attack_technique_id() -> None:
    assert find_matching_playbook(equivalent_attack_alert(), [load_playbook()]) is not None


def test_fixture_alert_input_produces_one_response_record() -> None:
    result = run_soar_response.run_soar_response()

    assert result["mode"] == "fixture-alert"
    assert result["response_count"] == 1


def test_alert_json_input_produces_one_response_record(tmp_path) -> None:
    path = tmp_path / "alert.json"
    path.write_text(json.dumps(native_alert()), encoding="utf-8")

    result = run_soar_response.run_soar_response(input_mode="alert-json", alert_path=path)

    assert result["response_count"] == 1


def test_non_matching_alert_produces_zero_response_records(tmp_path) -> None:
    path = tmp_path / "alert.json"
    path.write_text(json.dumps(non_matching_alert()), encoding="utf-8")

    result = run_soar_response.run_soar_response(input_mode="alert-json", alert_path=path)

    assert result["response_count"] == 0
    assert result["message"] == "No SOAR playbook matched the provided alerts."


def test_response_id_is_deterministic_for_same_alert_playbook_actions() -> None:
    playbook = load_playbook()
    first = build_response_record(native_alert(), playbook, created_at="2026-06-17T10:00:00Z")
    second = build_response_record(native_alert(), playbook, created_at="2026-06-17T11:00:00Z")

    assert first["response"]["id"] == second["response"]["id"]


def test_response_id_changes_when_action_ids_change() -> None:
    playbook = load_playbook()
    changed = copy.deepcopy(playbook)
    changed["actions"][0]["id"] = "notify_soc"

    first = build_response_record(native_alert(), playbook, created_at=FIXED_CREATED_AT)
    second = build_response_record(native_alert(), changed, created_at=FIXED_CREATED_AT)

    assert first["response"]["id"] != second["response"]["id"]


def test_response_status_mode_and_alert_metadata_are_copied() -> None:
    alert = native_alert()
    record = build_response_record(alert, load_playbook(), created_at=FIXED_CREATED_AT)

    assert record["response"]["status"] == "planned"
    assert record["response"]["mode"] == "dry-run"
    assert record["response"]["severity"] == alert["alert"]["severity"]
    assert record["alert"] == {
        "id": alert["alert"]["id"],
        "rule_id": "det.t1059_001.powershell_process_start",
        "technique_id": "T1059.001",
    }


def test_response_includes_exactly_three_planned_actions() -> None:
    record = build_response_record(native_alert(), load_playbook(), created_at=FIXED_CREATED_AT)

    assert [action["id"] for action in record["actions"]] == [
        "notify_analyst",
        "collect_process_context",
        "recommend_host_review",
    ]
    assert {action["status"] for action in record["actions"]} == {"planned"}


def test_response_index_name_from_string_and_date() -> None:
    assert build_response_index_name("2026-06-17") == "edr-response-actions-2026.06.17"
    assert build_response_index_name(date(2026, 6, 17)) == "edr-response-actions-2026.06.17"


def test_response_indexing_uses_response_id_as_document_id(monkeypatch: pytest.MonkeyPatch) -> None:
    captured = {}
    record = build_response_record(native_alert(), load_playbook(), created_at=FIXED_CREATED_AT)

    def fake_urlopen(request: object, timeout: int) -> FakeResponse:
        captured["request"] = request
        captured["timeout"] = timeout
        return FakeResponse(status=201, payload={"result": "created"})

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    result = index_response(
        record,
        ResponseIndexingConfig(base_url="http://localhost:9200", timeout_seconds=7),
        index_date="2026-06-17",
    )

    assert captured["timeout"] == 7
    assert captured["request"].get_method() == "PUT"
    assert captured["request"].full_url.endswith(f"/_doc/{record['response']['id']}")
    assert json.loads(captured["request"].data.decode("utf-8")) == record
    assert result.document_id == record["response"]["id"]


def test_write_response_calls_response_indexer(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = []

    def fake_index_responses(records: list[dict], config: object, *, index_date: str | None = None) -> list[ResponseIndexResult]:
        calls.append({"records": records, "index_date": index_date, "config": config})
        return [
            ResponseIndexResult(
                index="edr-response-actions-2026.06.17",
                document_id=records[0]["response"]["id"],
                result="created",
                status=201,
            )
        ]

    monkeypatch.setattr(run_soar_response, "index_responses", fake_index_responses)

    result = run_soar_response.run_soar_response(write_response=True, response_index_date="2026-06-17")

    assert len(calls) == 1
    assert calls[0]["index_date"] == "2026-06-17"
    assert result["indexed_count"] == 1


def test_without_write_response_indexer_is_not_called(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_index_responses(*_: object, **__: object) -> list[ResponseIndexResult]:
        raise AssertionError("response indexer should not be called")

    monkeypatch.setattr(run_soar_response, "index_responses", fail_index_responses)

    result = run_soar_response.run_soar_response(write_response=False)

    assert result["indexed_count"] == 0
    assert result["indexed_responses"] == []


def test_elasticsearch_input_can_be_monkeypatched(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_query_alert_documents(**_: object) -> list[dict]:
        return [native_alert()]

    monkeypatch.setattr(run_soar_response, "query_alert_documents", fake_query_alert_documents)

    result = run_soar_response.run_soar_response(input_mode="elasticsearch")

    assert result["mode"] == "elasticsearch"
    assert result["response_count"] == 1


def test_tests_do_not_call_containment_modules() -> None:
    before = set(sys.modules)

    plan_responses([native_alert()], [load_playbook()], created_at=FIXED_CREATED_AT)

    imported = set(sys.modules) - before
    assert not any(name.startswith("response.containment") for name in imported)


def test_indexing_errors_map_to_exit_code_2(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    def fake_index_responses(*_: object, **__: object) -> list[ResponseIndexResult]:
        raise ResponseIndexingError("indexing failed")

    monkeypatch.setattr(run_soar_response, "index_responses", fake_index_responses)

    exit_code = run_soar_response.main(["--write-response"])

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "Operational failure" in captured.err


class FakeResponse:
    def __init__(self, *, status: int, payload: dict) -> None:
        self.status = status
        self.payload = payload

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def getcode(self) -> int:
        return self.status

    def read(self) -> bytes:
        return json.dumps(self.payload).encode("utf-8")


def _playbook_text(*, status: str = "dry-run", action_status: str = "planned") -> str:
    return "\n".join(
        [
            "id: soar.playbook.test",
            "name: Test",
            f"status: {status}",
            "description: Test playbook.",
            "match:",
            "  rule_ids:",
            "    - det.t1059_001.powershell_process_start",
            "actions:",
            "  - id: notify_analyst",
            "    type: notification",
            f"    status: {action_status}",
            "    description: Notify.",
        ]
    )
