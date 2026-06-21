"""Compatibility wrapper for behavioral sequence detection."""

from __future__ import annotations

from typing import Any

from detection.behavioral.correlation import detect_behavioral_sequences


def detect_sequences(events: list[dict[str, Any]], window_seconds: int = 60) -> list[dict[str, Any]]:
    return detect_behavioral_sequences(events, window_seconds=window_seconds)
