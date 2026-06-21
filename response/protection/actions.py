"""Lab-only protection action implementations."""

from __future__ import annotations

import os
import platform
import signal
import subprocess
from typing import Any


class ProtectionActionError(RuntimeError):
    """Raised when a protection action cannot be completed."""


def kill_process(pid: int, *, dry_run: bool = True) -> dict[str, Any]:
    """Kill one process by PID, or return a dry-run planned result."""

    pid = _validate_pid(pid)
    if dry_run:
        return {
            "action": "kill_process",
            "pid": pid,
            "dry_run": True,
            "status": "planned",
            "message": "dry-run only; process was not killed",
        }

    if platform.system().lower() == "windows":
        _kill_windows(pid)
    else:
        _kill_posix(pid)

    return {
        "action": "kill_process",
        "pid": pid,
        "dry_run": False,
        "status": "executed",
        "message": "process termination requested",
    }


def _kill_windows(pid: int) -> None:
    try:
        completed = subprocess.run(
            ["taskkill", "/PID", str(pid), "/T", "/F"],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as exc:
        raise ProtectionActionError(f"taskkill failed to start for PID {pid}: {exc}") from exc
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "").strip()
        raise ProtectionActionError(f"taskkill failed for PID {pid}: {detail or 'unknown error'}")


def _kill_posix(pid: int) -> None:
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError as exc:
        raise ProtectionActionError(f"process PID {pid} was not found") from exc
    except PermissionError as exc:
        raise ProtectionActionError(f"permission denied killing PID {pid}") from exc
    except OSError as exc:
        raise ProtectionActionError(f"failed to kill PID {pid}: {exc}") from exc


def _validate_pid(value: Any) -> int:
    if isinstance(value, bool):
        raise ProtectionActionError("PID must be a positive integer.")
    try:
        pid = int(value)
    except (TypeError, ValueError) as exc:
        raise ProtectionActionError(f"PID must be a positive integer, got {value!r}.") from exc
    if pid <= 0:
        raise ProtectionActionError(f"PID must be a positive integer, got {pid}.")
    return pid
