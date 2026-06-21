"""Native deterministic T1547.001 registry Run key demo rule."""

from __future__ import annotations

from typing import Any

from detection.rules.demo_semantics import match_t1547_registry_run_key


RULE = {
    "id": "det.t1547_001.registry_run_key_persistence",
    "version": 1,
    "name": "T1547.001 Registry Run Key Persistence Marker",
    "description": "Detects safe registry Run/RunOnce persistence markers from normalized Sysmon Event ID 13 telemetry.",
    "severity": "high",
    "confidence": "high",
    "attack": {
        "technique_id": "T1547.001",
        "technique_name": "Registry Run Keys / Startup Folder",
        "tactic": ["Persistence"],
    },
    "data_sources": [
        {"event_dataset": "windows.sysmon_operational", "event_code": 13, "event_type": "registry_value_set"},
    ],
}


def match(event: dict[str, Any]) -> tuple[bool, tuple[str, ...]]:
    """Return whether this normalized event matches the T1547.001 demo rule."""

    return match_t1547_registry_run_key(event)
