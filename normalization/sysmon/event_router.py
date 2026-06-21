"""Route Sysmon XML events to the supported event-specific normalizer."""

from __future__ import annotations

from typing import Any

from normalization.sysmon.common import parse_sysmon_event, system_text
from normalization.sysmon.file_create_normalizer import normalize_sysmon_event_11
from normalization.sysmon.network_connection_normalizer import normalize_sysmon_event_3
from normalization.sysmon.process_create_normalizer import (
    UnsupportedSysmonEventError,
    normalize_sysmon_event_1,
)
from normalization.sysmon.registry_value_set_normalizer import normalize_sysmon_event_13


def normalize_sysmon_event(xml: str) -> dict[str, Any]:
    """Normalize supported Sysmon XML events by dispatching on System.EventID."""

    parsed = parse_sysmon_event(xml)
    event_id = system_text(parsed.system, "EventID")

    if event_id == "1":
        return normalize_sysmon_event_1(xml)
    if event_id == "3":
        return normalize_sysmon_event_3(xml)
    if event_id == "11":
        return normalize_sysmon_event_11(xml)
    if event_id == "13":
        return normalize_sysmon_event_13(xml)

    raise UnsupportedSysmonEventError(
        f"Unsupported Sysmon Event ID {event_id!r}. Supported Event IDs: 1, 3, 11, 13."
    )
