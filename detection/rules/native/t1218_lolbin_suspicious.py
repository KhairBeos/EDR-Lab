"""Native deterministic T1218-lite LOLBin proxy execution demo rule."""

from __future__ import annotations

from typing import Any

from detection.rules.demo_semantics import match_t1218_lolbin_suspicious


RULE = {
    "id": "det.t1218.lolbin_suspicious_execution",
    "version": 1,
    "name": "T1218 LOLBin Suspicious Execution Marker",
    "description": "Detects safe rundll32/regsvr32/mshta proxy execution markers for deterministic T1218-lite demos.",
    "severity": "medium",
    "confidence": "medium",
    "attack": {
        "technique_id": "T1218",
        "technique_name": "System Binary Proxy Execution",
        "tactic": ["Defense Evasion"],
    },
    "data_sources": [
        {"event_dataset": "windows.sysmon_operational", "event_code": 1, "event_type": "process_creation"},
    ],
}


def match(event: dict[str, Any]) -> tuple[bool, tuple[str, ...]]:
    """Return whether this normalized event matches the T1218-lite demo rule."""

    return match_t1218_lolbin_suspicious(event)
