"""Run guarded lab-only protection actions."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from response.protection.actions import ProtectionActionError, kill_process
from response.protection.policy import ProtectionPolicyError, evaluate_kill_process_policy
from response.protection.protection_indexer import (
    ProtectionIndexingConfig,
    ProtectionIndexingError,
    index_protection_records,
)
from response.protection.records import build_protection_record
from scripts.detection.run_native_detection import run_native_detection
from scripts.lab_config import default_elasticsearch_url


class ProtectionCommandError(RuntimeError):
    """Raised for predictable protection command input failures."""


def run_protection_action(
    *,
    input_mode: str,
    alert_path: Path | None = None,
    action: str = "kill-process",
    pid: int | None = None,
    execute_protection: bool = False,
    lab_allow_execute: bool = False,
    force_lab_demo: bool = False,
    write_protection: bool = False,
    elasticsearch_url: str = "http://localhost:9200",
    protection_index_prefix: str = "edr-protection-actions",
) -> dict[str, Any]:
    """Load one alert, evaluate protection policy, run action if allowed, and optionally index the record."""

    if action != "kill-process":
        raise ProtectionCommandError(f"Unsupported protection action: {action!r}.")

    alert = _load_alert(input_mode=input_mode, alert_path=alert_path)
    decision = evaluate_kill_process_policy(
        alert,
        execute=execute_protection,
        lab_allow_execute=lab_allow_execute,
        force_lab_demo=force_lab_demo,
        explicit_pid=pid,
    )

    if not decision["allowed"]:
        action_result = {
            "action": "kill_process",
            "pid": decision.get("pid"),
            "dry_run": not execute_protection,
            "status": "blocked",
            "message": decision["reason"],
        }
        protection_record = build_protection_record(alert, decision, action_result)
        index_results = _maybe_index(
            protection_record,
            write_protection=write_protection,
            elasticsearch_url=elasticsearch_url,
            protection_index_prefix=protection_index_prefix,
        )
        return _result(decision, action_result, protection_record, index_results)

    try:
        action_result = kill_process(int(decision["pid"]), dry_run=decision["mode"] == "dry-run")
    except ProtectionActionError as exc:
        action_result = {
            "action": "kill_process",
            "pid": decision.get("pid"),
            "dry_run": decision["mode"] == "dry-run",
            "status": "failed",
            "message": str(exc),
        }
        protection_record = build_protection_record(alert, decision, action_result)
        raise ProtectionCommandErrorWithRecord(str(exc), protection_record) from exc

    protection_record = build_protection_record(alert, decision, action_result)
    index_results = _maybe_index(
        protection_record,
        write_protection=write_protection,
        elasticsearch_url=elasticsearch_url,
        protection_index_prefix=protection_index_prefix,
    )
    return _result(decision, action_result, protection_record, index_results)


def render_result(result: dict[str, Any], output: str) -> str:
    """Render protection result as JSON or summary."""

    if output == "json":
        return json.dumps(result, indent=2, sort_keys=True)
    if output != "summary":
        raise ValueError(f"Unsupported output format: {output!r}.")

    decision = result["decision"]
    record = result["protection_record"]
    protection = record["protection"]
    target = record["target"]
    lines = [
        "Protection action",
        f"Allowed: {decision['allowed']}",
        f"Mode: {decision['mode']}",
        f"Reason: {decision['reason']}",
        f"Action: {protection['action']}",
        f"Status: {protection['status']}",
        f"PID: {target.get('pid')}",
        f"Process: {target.get('process_name')}",
        f"Indexed: {len(result['index_result'])}",
    ]
    return "\n".join(lines)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run guarded lab-only protection action.")
    parser.add_argument("--input", choices=("fixture-alert", "alert-json"), default="fixture-alert")
    parser.add_argument("--alert-path", type=Path)
    parser.add_argument("--action", choices=("kill-process",), default="kill-process")
    parser.add_argument("--pid", type=int)
    parser.add_argument("--execute-protection", action="store_true")
    parser.add_argument("--lab-allow-execute", action="store_true")
    parser.add_argument("--force-lab-demo", action="store_true")
    parser.add_argument("--write-protection", action="store_true")
    parser.add_argument("--elasticsearch-url", default=default_elasticsearch_url())
    parser.add_argument("--protection-index-prefix", default="edr-protection-actions")
    parser.add_argument("--output", choices=("json", "summary"), default="json")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])
    try:
        result = run_protection_action(
            input_mode=args.input,
            alert_path=args.alert_path,
            action=args.action,
            pid=args.pid,
            execute_protection=args.execute_protection,
            lab_allow_execute=args.lab_allow_execute,
            force_lab_demo=args.force_lab_demo,
            write_protection=args.write_protection,
            elasticsearch_url=args.elasticsearch_url,
            protection_index_prefix=args.protection_index_prefix,
        )
    except ProtectionCommandErrorWithRecord as exc:
        print(f"Operational failure: {exc}", file=sys.stderr)
        print(json.dumps({"protection_record": exc.protection_record}, indent=2, sort_keys=True))
        return 2
    except (ProtectionCommandError, ProtectionPolicyError, ProtectionIndexingError, OSError) as exc:
        print(f"Operational failure: {exc}", file=sys.stderr)
        return 2
    except (ValueError, KeyError, TypeError) as exc:
        print(f"Protection action failed: {exc}", file=sys.stderr)
        return 3

    print(render_result(result, args.output))
    return 0 if result["decision"]["allowed"] else 1


class ProtectionCommandErrorWithRecord(ProtectionCommandError):
    """Operational failure that still has a protection record."""

    def __init__(self, message: str, protection_record: dict[str, Any]) -> None:
        super().__init__(message)
        self.protection_record = protection_record


def _load_alert(*, input_mode: str, alert_path: Path | None) -> dict[str, Any]:
    if input_mode == "fixture-alert":
        result = run_native_detection()
        alerts = result.get("alerts", [])
        if not alerts:
            raise ProtectionCommandError("Fixture alert input did not produce an alert.")
        return alerts[0]
    if input_mode == "alert-json":
        if alert_path is None:
            raise ProtectionCommandError("--alert-path is required when --input alert-json.")
        try:
            parsed = json.loads(alert_path.read_text(encoding="utf-8"))
        except OSError as exc:
            raise ProtectionCommandError(f"Could not read alert JSON path {alert_path}: {exc}") from exc
        except json.JSONDecodeError as exc:
            raise ProtectionCommandError(f"Alert JSON is malformed: {exc}") from exc
        if not isinstance(parsed, dict):
            raise ProtectionCommandError("Alert JSON input must be one alert object.")
        return parsed
    raise ProtectionCommandError(f"Unsupported input mode: {input_mode!r}.")


def _maybe_index(
    protection_record: dict[str, Any],
    *,
    write_protection: bool,
    elasticsearch_url: str,
    protection_index_prefix: str,
) -> list[dict[str, Any]]:
    if not write_protection:
        return []
    indexed = index_protection_records(
        [protection_record],
        ProtectionIndexingConfig(base_url=elasticsearch_url, index_prefix=protection_index_prefix),
    )
    return [asdict(item) for item in indexed]


def _result(
    decision: dict[str, Any],
    action_result: dict[str, Any],
    protection_record: dict[str, Any],
    index_results: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "decision": decision,
        "action_result": action_result,
        "protection_record": protection_record,
        "index_result": index_results,
    }


if __name__ == "__main__":
    raise SystemExit(main())
