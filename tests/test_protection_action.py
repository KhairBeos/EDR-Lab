import copy
import json
from datetime import date

import pytest

from response.protection.actions import ProtectionActionError, kill_process
from response.protection.policy import ProtectionPolicyError, evaluate_kill_process_policy
from response.protection.protection_indexer import (
    ProtectionIndexResult,
    ProtectionIndexingConfig,
    ProtectionIndexingError,
    build_protection_index_name,
    index_protection_record,
)
from response.protection.records import build_protection_record
from scripts.detection import run_native_detection
from scripts.response import run_protection_action


FIXED_CREATED_AT = "2026-06-17T10:00:00Z"


def native_alert() -> dict:
    return run_native_detection.run_native_detection()["alerts"][0]


def unsupported_alert() -> dict:
    alert = copy.deepcopy(native_alert())
    alert["alert"]["id"] = "unsupported-rule-alert"
    alert["rule"]["id"] = "det.unsupported.rule"
    alert["attack"]["technique"]["id"] = "T0000"
    return alert


def protected_process_alert() -> dict:
    alert = copy.deepcopy(native_alert())
    alert["process"]["name"] = "lsass.exe"
    alert["process"]["pid"] = 500
    return alert


def test_default_dry_run_allowed_for_matching_powershell_alert() -> None:
    decision = evaluate_kill_process_policy(native_alert())

    assert decision["allowed"] is True
    assert decision["mode"] == "dry-run"
    assert decision["rule_id"] == "det.t1059_001.powershell_process_start"
    assert "dry_run_default" in decision["safety_checks"]


def test_execute_blocked_without_lab_allow_execute() -> None:
    decision = evaluate_kill_process_policy(native_alert(), execute=True)

    assert decision["allowed"] is False
    assert decision["mode"] == "execute"
    assert "lab_allow_execute_missing" in decision["safety_checks"]


def test_execute_blocked_for_protected_system_process() -> None:
    decision = evaluate_kill_process_policy(
        protected_process_alert(),
        execute=True,
        lab_allow_execute=True,
    )

    assert decision["allowed"] is False
    assert "protected_process_blocked" in decision["safety_checks"]


def test_execute_allowed_only_with_execute_and_lab_allow_execute() -> None:
    decision = evaluate_kill_process_policy(native_alert(), execute=True, lab_allow_execute=True)

    assert decision["allowed"] is True
    assert decision["mode"] == "execute"
    assert "execute_requested" in decision["safety_checks"]
    assert "lab_allow_execute" in decision["safety_checks"]


def test_unsupported_rule_blocked() -> None:
    decision = evaluate_kill_process_policy(unsupported_alert())

    assert decision["allowed"] is False
    assert "unsupported_rule_blocked" in decision["safety_checks"]


def test_force_lab_demo_can_bypass_unsupported_rule() -> None:
    decision = evaluate_kill_process_policy(unsupported_alert(), force_lab_demo=True)

    assert decision["allowed"] is True
    assert "force_lab_demo" in decision["safety_checks"]


def test_force_lab_demo_cannot_bypass_protected_process() -> None:
    alert = protected_process_alert()
    alert["rule"]["id"] = "det.unsupported.rule"

    decision = evaluate_kill_process_policy(alert, force_lab_demo=True)

    assert decision["allowed"] is False
    assert "protected_process_blocked" in decision["safety_checks"]


def test_kill_process_dry_run_does_not_call_os_kill(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_os_kill(*_: object, **__: object) -> None:
        raise AssertionError("os.kill should not be called")

    monkeypatch.setattr("os.kill", fail_os_kill)

    result = kill_process(1234, dry_run=True)

    assert result["status"] == "planned"


def test_kill_process_execute_uses_monkeypatched_os_call(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = []

    monkeypatch.setattr("platform.system", lambda: "Linux")

    def fake_os_kill(pid: int, sig: object) -> None:
        calls.append((pid, sig))

    monkeypatch.setattr("os.kill", fake_os_kill)

    result = kill_process(1234, dry_run=False)

    assert calls
    assert calls[0][0] == 1234
    assert result["status"] == "executed"


def test_windows_taskkill_path_can_be_monkeypatched(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = []

    monkeypatch.setattr("platform.system", lambda: "Windows")

    class Completed:
        returncode = 0
        stdout = "ok"
        stderr = ""

    def fake_run(args: list[str], **kwargs: object) -> Completed:
        calls.append({"args": args, "kwargs": kwargs})
        return Completed()

    monkeypatch.setattr("subprocess.run", fake_run)

    result = kill_process(4321, dry_run=False)

    assert calls[0]["args"] == ["taskkill", "/PID", "4321", "/T", "/F"]
    assert calls[0]["kwargs"]["check"] is False
    assert "shell" not in calls[0]["kwargs"]
    assert result["status"] == "executed"


def test_invalid_pid_raises_clear_action_or_policy_error() -> None:
    with pytest.raises(ProtectionActionError, match="PID"):
        kill_process(0, dry_run=True)

    with pytest.raises(ProtectionPolicyError, match="PID"):
        evaluate_kill_process_policy(native_alert(), explicit_pid=-1)


def test_protection_record_deterministic_id() -> None:
    decision = evaluate_kill_process_policy(native_alert())
    action_result = kill_process(decision["pid"], dry_run=True)

    first = build_protection_record(native_alert(), decision, action_result, created_at=FIXED_CREATED_AT)
    second = build_protection_record(native_alert(), decision, action_result, created_at="2026-06-17T11:00:00Z")

    assert first["protection"]["id"] == second["protection"]["id"]


def test_blocked_decision_creates_blocked_protection_record() -> None:
    decision = evaluate_kill_process_policy(unsupported_alert())
    action_result = {
        "action": "kill_process",
        "pid": decision["pid"],
        "dry_run": True,
        "status": "blocked",
        "message": decision["reason"],
    }

    record = build_protection_record(unsupported_alert(), decision, action_result, created_at=FIXED_CREATED_AT)

    assert record["protection"]["status"] == "blocked"


def test_failed_action_creates_failed_protection_record() -> None:
    decision = evaluate_kill_process_policy(native_alert(), execute=True, lab_allow_execute=True)
    action_result = {
        "action": "kill_process",
        "pid": decision["pid"],
        "dry_run": False,
        "status": "failed",
        "message": "failed",
    }

    record = build_protection_record(native_alert(), decision, action_result, created_at=FIXED_CREATED_AT)

    assert record["protection"]["status"] == "failed"


def test_cli_fixture_alert_dry_run_works() -> None:
    result = run_protection_action.run_protection_action(input_mode="fixture-alert")

    assert result["decision"]["allowed"] is True
    assert result["protection_record"]["protection"]["status"] == "planned"


def test_cli_alert_json_dry_run_works(tmp_path) -> None:
    path = tmp_path / "alert.json"
    path.write_text(json.dumps(native_alert()), encoding="utf-8")

    result = run_protection_action.run_protection_action(input_mode="alert-json", alert_path=path)

    assert result["decision"]["allowed"] is True
    assert result["action_result"]["status"] == "planned"


def test_cli_returns_1_for_policy_blocked(tmp_path, capsys: pytest.CaptureFixture[str]) -> None:
    path = tmp_path / "alert.json"
    path.write_text(json.dumps(unsupported_alert()), encoding="utf-8")

    exit_code = run_protection_action.main(["--input", "alert-json", "--alert-path", str(path)])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "blocked" in captured.out


def test_write_protection_calls_monkeypatched_indexer(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = []

    def fake_index(records: list[dict], config: object, *, index_date: str | None = None) -> list[ProtectionIndexResult]:
        calls.append({"records": records, "config": config, "index_date": index_date})
        return [
            ProtectionIndexResult(
                index="edr-protection-actions-2026.06.17",
                document_id=records[0]["protection"]["id"],
                result="created",
                status=201,
            )
        ]

    monkeypatch.setattr(run_protection_action, "index_protection_records", fake_index)

    result = run_protection_action.run_protection_action(input_mode="fixture-alert", write_protection=True)

    assert len(calls) == 1
    assert result["index_result"][0]["index"] == "edr-protection-actions-2026.06.17"


def test_protection_index_name_is_daily() -> None:
    assert build_protection_index_name("2026-06-17") == "edr-protection-actions-2026.06.17"
    assert build_protection_index_name(date(2026, 6, 17)) == "edr-protection-actions-2026.06.17"


def test_protection_indexer_uses_protection_id_as_document_id(monkeypatch: pytest.MonkeyPatch) -> None:
    captured = {}
    decision = evaluate_kill_process_policy(native_alert())
    record = build_protection_record(native_alert(), decision, kill_process(decision["pid"], dry_run=True))

    def fake_urlopen(request: object, timeout: int) -> FakeResponse:
        captured["request"] = request
        captured["timeout"] = timeout
        return FakeResponse(status=201, payload={"result": "created"})

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    result = index_protection_record(
        record,
        ProtectionIndexingConfig(base_url="http://localhost:9200", timeout_seconds=7),
        index_date="2026-06-17",
    )

    assert captured["timeout"] == 7
    assert captured["request"].get_method() == "PUT"
    assert captured["request"].full_url.endswith(f"/_doc/{record['protection']['id']}")
    assert json.loads(captured["request"].data.decode("utf-8")) == record
    assert result.document_id == record["protection"]["id"]


def test_indexer_rejects_missing_protection_id() -> None:
    with pytest.raises(ProtectionIndexingError, match="protection.id"):
        index_protection_record({"protection": {}}, ProtectionIndexingConfig(), index_date="2026-06-17")


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
