"""Native deterministic T1105 LOLBin download demo rule."""

from __future__ import annotations

from typing import Any

from detection.rules.demo_semantics import match_t1105_lolbin_download


RULE = {
    "id": "det.t1105.lolbin_download",
    "version": 1,
    "name": "T1105 LOLBin Download Marker",
    "description": "Detects safe LOLBin download markers across process, network, and file-create demo telemetry.",
    "severity": "medium",
    "confidence": "medium",
    "attack": {
        "technique_id": "T1105",
        "technique_name": "Ingress Tool Transfer",
        "tactic": ["Command and Control"],
    },
    "data_sources": [
        {"event_dataset": "windows.sysmon_operational", "event_code": 1, "event_type": "process_creation"},
        {"event_dataset": "windows.sysmon_operational", "event_code": 3, "event_type": "network_connection"},
        {"event_dataset": "windows.sysmon_operational", "event_code": 11, "event_type": "file_creation"},
    ],
}


def match(event: dict[str, Any]) -> tuple[bool, tuple[str, ...]]:
    """Return whether this normalized event matches the T1105 demo rule."""

    return match_t1105_lolbin_download(event)
