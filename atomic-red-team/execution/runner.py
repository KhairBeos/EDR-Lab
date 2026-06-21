"""Minimal Phase 1 Atomic Red Team runner.

This runner intentionally supports one safe allowlisted test:
T1059.001 PowerShell / "PowerShell Command Execution".
"""

from __future__ import annotations

import argparse
import json
import platform
import subprocess
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SELECTED_TECHNIQUES_PATH = REPO_ROOT / "atomic-red-team" / "techniques" / "selected_techniques.yml"

ALLOWED_TECHNIQUE_ID = "T1059.001"
ALLOWED_PLATFORM = "windows"
ALLOWED_EXECUTOR = "powershell"
ALLOWED_TEST_GUID = "a538de64-1c74-46ed-aa60-b995ed302598"
ALLOWED_TEST_NAME = "PowerShell Command Execution"


@dataclass(frozen=True)
class SelectedTechnique:
    technique_id: str
    display_name: str
    platform: str
    executor: str
    test_name: str
    test_guid: str
    invoke_atomic_command: str


@dataclass
class ExecutionRecord:
    technique_id: str
    test_guid: str
    test_name: str
    platform: str
    executor: str
    run_timestamp: str
    mode: str
    status: str
    command: str
    return_code: int | None = None
    stdout: str = ""
    stderr: str = ""


def _read_scalar(value: str) -> str:
    value = value.strip()
    if value.startswith('"') and value.endswith('"'):
        return value[1:-1]
    if value.startswith("'") and value.endswith("'"):
        return value[1:-1]
    return value


def load_selected_technique(path: Path = SELECTED_TECHNIQUES_PATH) -> SelectedTechnique:
    """Load the single Phase 1 selected technique without adding a YAML dependency."""

    current: dict[str, str] = {}

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line == "techniques:":
            continue

        if line.startswith("- "):
            key, _, value = line[2:].partition(":")
        else:
            key, _, value = line.partition(":")

        if key and value:
            current[key.strip()] = _read_scalar(value)

    technique = SelectedTechnique(
        technique_id=current.get("technique_id", ""),
        display_name=current.get("display_name", ""),
        platform=current.get("platform", ""),
        executor=current.get("executor", ""),
        test_name=current.get("test_name", ""),
        test_guid=current.get("test_guid", ""),
        invoke_atomic_command=current.get("invoke_atomic_command", ""),
    )

    validate_allowlist(technique)
    return technique


def validate_allowlist(technique: SelectedTechnique) -> None:
    expected = {
        "technique_id": ALLOWED_TECHNIQUE_ID,
        "platform": ALLOWED_PLATFORM,
        "executor": ALLOWED_EXECUTOR,
        "test_guid": ALLOWED_TEST_GUID,
        "test_name": ALLOWED_TEST_NAME,
    }
    actual = asdict(technique)

    for key, expected_value in expected.items():
        if actual[key] != expected_value:
            raise ValueError(f"Selected technique is outside the Phase 1 allowlist: {key}={actual[key]!r}")


def build_invoke_atomic_process_command(technique: SelectedTechnique) -> list[str]:
    script = (
        "$ErrorActionPreference = 'Stop'; "
        "if (-not (Get-Command Invoke-AtomicTest -ErrorAction SilentlyContinue)) { "
        "throw 'Invoke-AtomicTest is not available. Install/import Invoke-AtomicRedTeam inside the Windows VM first.' "
        "} "
        f"Invoke-AtomicTest {technique.technique_id} -TestGuids {technique.test_guid}"
    )
    return ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script]


def build_record(technique: SelectedTechnique, mode: str, status: str) -> ExecutionRecord:
    return ExecutionRecord(
        technique_id=technique.technique_id,
        test_guid=technique.test_guid,
        test_name=technique.test_name,
        platform=technique.platform,
        executor=technique.executor,
        run_timestamp=datetime.now(timezone.utc).isoformat(),
        mode=mode,
        status=status,
        command=technique.invoke_atomic_command,
    )


def print_record(record: ExecutionRecord) -> None:
    print(json.dumps(asdict(record), indent=2))


def print_verification_commands() -> None:
    print(
        """
Sysmon Event ID 1 verification:

Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 100 |
  Where-Object { $_.Id -eq 1 -and $_.Message -match "powershell.exe" } |
  Select-Object -First 5 TimeCreated, Id, Message

PowerShell Operational log verification:

Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -MaxEvents 100 |
  Select-Object -First 10 TimeCreated, Id, Message
""".strip()
    )


def run_dry_run(technique: SelectedTechnique) -> int:
    record = build_record(technique, mode="dry-run", status="planned")
    print("Dry-run only. No Atomic Red Team command was executed.")
    print_record(record)
    print_verification_commands()
    return 0


def run_execute(technique: SelectedTechnique, confirm_vm: bool) -> int:
    if not confirm_vm:
        record = build_record(technique, mode="execute", status="failed")
        record.stderr = "Execute mode requires --confirm-vm to acknowledge this is the Phase 1 Windows VM endpoint."
        print_record(record)
        print_verification_commands()
        return 2

    if platform.system().lower() != "windows":
        record = build_record(technique, mode="execute", status="failed")
        record.stderr = "Execute mode must run inside the Windows VM endpoint."
        print_record(record)
        print_verification_commands()
        return 2

    process_command = build_invoke_atomic_process_command(technique)
    record = build_record(technique, mode="execute", status="running")

    try:
        completed = subprocess.run(process_command, capture_output=True, text=True, check=False)
    except FileNotFoundError as exc:
        record.status = "failed"
        record.stderr = str(exc)
        print_record(record)
        print_verification_commands()
        return 2

    record.return_code = completed.returncode
    record.stdout = completed.stdout
    record.stderr = completed.stderr
    record.status = "success" if completed.returncode == 0 else "failed"

    print_record(record)
    print_verification_commands()
    return completed.returncode


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the Phase 1 allowlisted Atomic Red Team PowerShell test.")
    parser.add_argument("--technique", default=ALLOWED_TECHNIQUE_ID)
    parser.add_argument("--platform", default=ALLOWED_PLATFORM)
    parser.add_argument("--executor", default=ALLOWED_EXECUTOR)
    parser.add_argument("--mode", choices=("dry-run", "execute"), default="dry-run")
    parser.add_argument(
        "--confirm-vm",
        action="store_true",
        help="Required for execute mode. Confirms this command is running inside the Phase 1 Windows VM endpoint.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    technique = load_selected_technique()

    if args.technique != technique.technique_id:
        raise SystemExit(f"Refusing technique {args.technique!r}; Phase 1 only allows {technique.technique_id}.")
    if args.platform != technique.platform:
        raise SystemExit(f"Refusing platform {args.platform!r}; Phase 1 only allows {technique.platform}.")
    if args.executor != technique.executor:
        raise SystemExit(f"Refusing executor {args.executor!r}; Phase 1 only allows {technique.executor}.")

    if args.mode == "dry-run":
        return run_dry_run(technique)

    return run_execute(technique, confirm_vm=args.confirm_vm)


if __name__ == "__main__":
    raise SystemExit(main())
