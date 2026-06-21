"""Shared detection engine runner for normalized ECS events."""

from __future__ import annotations

from typing import Any

from detection.rules.native.registry import build_native_alerts
from detection.rules.sigma_like.registry import build_sigma_like_alerts


def run_detection_engines(
    *,
    engine: str,
    event: dict[str, Any],
    source: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    """Run selected deterministic detection engines for one normalized event."""

    if engine not in {"native", "sigma-like", "all"}:
        raise ValueError(f"Unsupported detection engine: {engine!r}.")

    alerts: list[dict[str, Any]] = []
    if engine in {"native", "all"}:
        alerts.extend(build_native_alerts(event=event, source=source or {}))
    if engine in {"sigma-like", "all"}:
        alerts.extend(build_sigma_like_alerts(event=event, source=source or {}))
    return alerts
