"""Core realtime collector, detection, and dashboard data helpers.

The functions in this module are intentionally dependency-light so tests can
exercise the realtime path on non-Windows hosts with sample Sysmon messages.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import sys
import threading
import urllib.error
import urllib.request
from collections import Counter, deque
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from collection.elasticsearch.event_indexer import (
    EventIndexingConfig,
    EventIndexingError,
    index_event as index_normalized_event,
)
from detection.rules.native.alert_indexer import (
    AlertIndexingConfig,
    AlertIndexingError,
    index_alert as index_native_alert,
)
from normalization.sysmon.event_router import normalize_sysmon_event
from normalization.sysmon.process_create_normalizer import SysmonNormalizationError


SYSMON_LOG_NAME = "Microsoft-Windows-Sysmon/Operational"
SYSMON_PROVIDER = "Microsoft-Windows-Sysmon"
SYSMON_DATASET = "windows.sysmon_operational"
SUPPORTED_EVENT_IDS = (1, 3, 11, 13)
REALTIME_EVENT_LIMIT = 500
REALTIME_ALERT_LIMIT = 200
DOWNLOAD_TOOL_NAMES = {"curl.exe", "powershell.exe", "pwsh.exe", "certutil.exe", "bitsadmin.exe"}


@dataclass(frozen=True)
class WinEventRecord:
    """One record returned from Get-WinEvent."""

    record_id: int
    event_id: int
    time_created: str
    provider_name: str
    message: str
    xml: str


@dataclass(frozen=True)
class RealtimeRule:
    """Metadata and matcher for a safe realtime demo rule."""

    rule_id: str
    name: str
    technique_id: str
    technique_name: str
    tactic: tuple[str, ...]
    severity: str
    confidence: str
    engine: str
    reason: str


@dataclass(frozen=True)
class RuleMatch:
    """A rule match against one normalized event."""

    rule: RealtimeRule
    matched_fields: tuple[str, ...]
    reason: str


@dataclass(frozen=True)
class RealtimeEvaluationCase:
    """Expected outcome for one realtime demo marker."""

    case_id: str
    marker: str
    technique_id: str
    expected_alert: bool
    expected_rule_ids: tuple[str, ...] = ()
    window_seconds: int = 8


REALTIME_RULES = {
    "t1059": RealtimeRule(
        rule_id="det.realtime.t1059_001.powershell_execution",
        name="T1059.001 PowerShell execution",
        technique_id="T1059.001",
        technique_name="PowerShell",
        tactic=("Execution",),
        severity="medium",
        confidence="high",
        engine="realtime-native",
        reason="PowerShell process creation contains a safe demo marker or suspicious execution flags.",
    ),
    "t1105": RealtimeRule(
        rule_id="det.realtime.t1105.ingress_tool_transfer",
        name="T1105 Ingress Tool Transfer",
        technique_id="T1105",
        technique_name="Ingress Tool Transfer",
        tactic=("Command and Control",),
        severity="medium",
        confidence="medium",
        engine="realtime-native",
        reason="Download-capable Windows tool used localhost/demo marker evidence.",
    ),
    "t1547": RealtimeRule(
        rule_id="det.realtime.t1547_001.registry_run_key",
        name="T1547.001 Registry Run Key",
        technique_id="T1547.001",
        technique_name="Registry Run Keys / Startup Folder",
        tactic=("Persistence",),
        severity="high",
        confidence="high",
        engine="realtime-native",
        reason="Sysmon Event ID 13 wrote a value below CurrentVersion\\Run or CurrentVersion\\RunOnce.",
    ),
    "t1218": RealtimeRule(
        rule_id="det.realtime.t1218_lite.rundll32_url_handler",
        name="T1218-lite rundll32 URL handler",
        technique_id="T1218",
        technique_name="System Binary Proxy Execution",
        tactic=("Defense Evasion",),
        severity="medium",
        confidence="medium",
        engine="realtime-native",
        reason="rundll32.exe command line contains a safe T1218 marker or url.dll,FileProtocolHandler.",
    ),
    "behavioral_t1105": RealtimeRule(
        rule_id="behavioral.realtime.t1105.process_network_file",
        name="T1105 process + network + file correlation",
        technique_id="T1105",
        technique_name="Ingress Tool Transfer",
        tactic=("Command and Control",),
        severity="high",
        confidence="high",
        engine="behavioral",
        reason="Within five minutes, one process/image or marker produced process, network, and file evidence.",
    ),
}


REALTIME_EVALUATION_CASES = (
    # 8 True Positives (TP)
    RealtimeEvaluationCase(case_id="rt_tp_1", marker="EDR_DEMO_TP_1", technique_id="T1059.001", expected_alert=True),
    RealtimeEvaluationCase(case_id="rt_tp_2", marker="EDR_DEMO_TP_2", technique_id="T1105", expected_alert=True),
    RealtimeEvaluationCase(case_id="rt_tp_3", marker="EDR_DEMO_TP_3", technique_id="T1547.001", expected_alert=True),
    RealtimeEvaluationCase(case_id="rt_tp_4", marker="EDR_DEMO_TP_4", technique_id="T1218", expected_alert=True),
    RealtimeEvaluationCase(case_id="rt_tp_5", marker="EDR_DEMO_TP_5", technique_id="T1059.001", expected_alert=True),
    RealtimeEvaluationCase(case_id="rt_tp_6", marker="EDR_DEMO_TP_6", technique_id="T1105", expected_alert=True),
    RealtimeEvaluationCase(case_id="rt_tp_7", marker="EDR_DEMO_TP_7", technique_id="T1547.001", expected_alert=True),
    RealtimeEvaluationCase(case_id="rt_tp_8", marker="EDR_DEMO_TP_8", technique_id="T1218", expected_alert=True),

    # 8 True Negatives (TN)
    RealtimeEvaluationCase(case_id="rt_tn_1", marker="EDR_DEMO_TN_1", technique_id="benign", expected_alert=False, window_seconds=6),
    RealtimeEvaluationCase(case_id="rt_tn_2", marker="EDR_DEMO_TN_2", technique_id="benign", expected_alert=False, window_seconds=6),
    RealtimeEvaluationCase(case_id="rt_tn_3", marker="EDR_DEMO_TN_3", technique_id="benign", expected_alert=False, window_seconds=6),
    RealtimeEvaluationCase(case_id="rt_tn_4", marker="EDR_DEMO_TN_4", technique_id="benign", expected_alert=False, window_seconds=6),
    RealtimeEvaluationCase(case_id="rt_tn_5", marker="EDR_DEMO_TN_5", technique_id="benign", expected_alert=False, window_seconds=6),
    RealtimeEvaluationCase(case_id="rt_tn_6", marker="EDR_DEMO_TN_6", technique_id="benign", expected_alert=False, window_seconds=6),
    RealtimeEvaluationCase(case_id="rt_tn_7", marker="EDR_DEMO_TN_7", technique_id="benign", expected_alert=False, window_seconds=6),
    RealtimeEvaluationCase(case_id="rt_tn_8", marker="EDR_DEMO_TN_8", technique_id="benign", expected_alert=False, window_seconds=6),

    # 6 False Positives (FP)
    RealtimeEvaluationCase(case_id="rt_fp_1", marker="EDR_DEMO_FP_1", technique_id="T1059.001", expected_alert=False, window_seconds=6),
    RealtimeEvaluationCase(case_id="rt_fp_2", marker="EDR_DEMO_FP_2", technique_id="T1105", expected_alert=False, window_seconds=6),
    RealtimeEvaluationCase(case_id="rt_fp_3", marker="EDR_DEMO_FP_3", technique_id="T1547.001", expected_alert=False, window_seconds=6),
    RealtimeEvaluationCase(case_id="rt_fp_4", marker="EDR_DEMO_FP_4", technique_id="T1218", expected_alert=False, window_seconds=6),
    RealtimeEvaluationCase(case_id="rt_fp_5", marker="EDR_DEMO_FP_5", technique_id="T1059.001", expected_alert=False, window_seconds=6),
    RealtimeEvaluationCase(case_id="rt_fp_6", marker="EDR_DEMO_FP_6", technique_id="T1105", expected_alert=False, window_seconds=6),

    # 6 False Negatives (FN)
    RealtimeEvaluationCase(case_id="rt_fn_1", marker="EDR_DEMO_FN_1", technique_id="T1059", expected_alert=True, window_seconds=6),
    RealtimeEvaluationCase(case_id="rt_fn_2", marker="EDR_DEMO_FN_2", technique_id="T1105", expected_alert=True, window_seconds=6),
    RealtimeEvaluationCase(case_id="rt_fn_3", marker="EDR_DEMO_FN_3", technique_id="T1547.001", expected_alert=True, window_seconds=6),
    RealtimeEvaluationCase(case_id="rt_fn_4", marker="EDR_DEMO_FN_4", technique_id="T1218", expected_alert=True, window_seconds=6),
    RealtimeEvaluationCase(case_id="rt_fn_5", marker="EDR_DEMO_FN_5", technique_id="T1059", expected_alert=True, window_seconds=6),
    RealtimeEvaluationCase(case_id="rt_fn_6", marker="EDR_DEMO_FN_6", technique_id="T1105", expected_alert=True, window_seconds=6),
)


def parse_sysmon_message(message: str) -> dict[str, str]:
    """Parse the human-readable Sysmon Message field into key/value pairs."""

    fields: dict[str, str] = {}
    current_key = ""

    for raw_line in message.splitlines():
        line = raw_line.rstrip()
        if not line.strip():
            continue

        match = re.match(r"^\s*([^:]{2,80}):\s*(.*)$", line)
        if match:
            key = match.group(1).strip()
            value = match.group(2).strip()
            if key:
                fields[key] = value
                current_key = key
            continue

        if current_key:
            fields[current_key] = f"{fields[current_key]}\n{line.strip()}".strip()

    return fields


def normalize_realtime_record(record: WinEventRecord) -> dict[str, Any]:
    """Normalize one WinEvent record to the project's ECS-like Sysmon schema."""

    if record.xml:
        try:
            return normalize_realtime_sysmon_xml(
                xml_event=record.xml,
                message=record.message,
                record_id=record.record_id,
                provider_name=record.provider_name,
                time_created=record.time_created,
            )
        except SysmonNormalizationError:
            if not record.message:
                raise

    return normalize_sysmon_message_event(
        event_code=record.event_id,
        message=record.message,
        record_id=record.record_id,
        provider_name=record.provider_name,
        time_created=record.time_created,
    )


def normalize_realtime_sysmon_xml(
    *,
    xml_event: str,
    message: str = "",
    record_id: int | None = None,
    provider_name: str = SYSMON_PROVIDER,
    time_created: str = "",
) -> dict[str, Any]:
    """Normalize Sysmon XML and enrich it with WinEvent realtime metadata."""

    event = normalize_sysmon_event(xml_event)
    event_meta = event.setdefault("event", {})
    event_meta.setdefault("dataset", SYSMON_DATASET)
    event_meta.setdefault("provider", provider_name or SYSMON_PROVIDER)
    event_meta.setdefault("created", event.get("@timestamp") or normalize_timestamp(time_created))

    if record_id is not None:
        event_meta["id"] = str(record_id)
        event.setdefault("winlog", {})["record_id"] = record_id

    if time_created and not event.get("@timestamp"):
        event["@timestamp"] = normalize_timestamp(time_created)

    event.setdefault("log", {}).setdefault("channel", SYSMON_LOG_NAME)
    event.setdefault("message", message)

    if message:
        event["raw"] = {"message": message}
        event.setdefault("sysmon", {})["message_fields"] = parse_sysmon_message(message)

    return event


def normalize_sysmon_message_event(
    *,
    event_code: int | str,
    message: str,
    record_id: int | None = None,
    provider_name: str = SYSMON_PROVIDER,
    time_created: str = "",
) -> dict[str, Any]:
    """Build a minimal ECS-like event from the WinEvent Message field."""

    code = int(event_code)
    fields = parse_sysmon_message(message)
    timestamp = normalize_timestamp(time_created or fields.get("UtcTime", ""))
    process_image = fields.get("Image", "")
    parent_image = fields.get("ParentImage", "")
    event_category, event_type, action = _event_shape(code)

    event: dict[str, Any] = {
        "@timestamp": timestamp,
        "event": {
            "kind": "event",
            "category": event_category,
            "type": event_type,
            "action": action,
            "code": code,
            "module": "sysmon",
            "provider": provider_name or SYSMON_PROVIDER,
            "dataset": SYSMON_DATASET,
            "created": timestamp,
            "original": message,
        },
        "log": {"channel": SYSMON_LOG_NAME},
        "host": {"name": fields.get("Computer", os.environ.get("COMPUTERNAME", "")), "os": {"type": "windows"}},
        "process": {
            "pid": parse_int_or_none(fields.get("ProcessId")),
            "entity_id": fields.get("ProcessGuid", ""),
            "name": windows_basename(process_image),
            "executable": process_image,
            "command_line": fields.get("CommandLine", ""),
        },
        "sysmon": {"event_data": dict(fields), "message_fields": dict(fields)},
        "data_stream": {"type": "logs", "dataset": SYSMON_DATASET, "namespace": "realtime"},
        "message": message,
        "raw": {"message": message},
        "tags": ["ecs_normalized", f"sysmon_event_{code}", "realtime_message_fallback"],
    }

    if record_id is not None:
        event["event"]["id"] = str(record_id)
        event["winlog"] = {"record_id": record_id}

    if parent_image or fields.get("ParentCommandLine"):
        event["process"]["parent"] = {
            "pid": parse_int_or_none(fields.get("ParentProcessId")),
            "entity_id": fields.get("ParentProcessGuid", ""),
            "name": windows_basename(parent_image),
            "executable": parent_image,
            "command_line": fields.get("ParentCommandLine", ""),
        }

    if code == 3:
        event["source"] = {
            "ip": fields.get("SourceIp", ""),
            "port": parse_int_or_none(fields.get("SourcePort")),
        }
        event["destination"] = {
            "ip": fields.get("DestinationIp", ""),
            "port": parse_int_or_none(fields.get("DestinationPort")),
            "domain": fields.get("DestinationHostname", ""),
        }
        event["network"] = {"transport": fields.get("Protocol", "").lower()}
        if fields.get("Initiated", "").casefold() == "true":
            event["network"]["direction"] = "outbound"
        elif fields.get("Initiated", "").casefold() == "false":
            event["network"]["direction"] = "inbound"

    if code == 11:
        file_path = fields.get("TargetFilename", "")
        event["file"] = {
            "path": file_path,
            "name": windows_basename(file_path),
            "extension": file_extension(file_path),
        }

    if code == 13:
        registry_path = fields.get("TargetObject", "")
        event["registry"] = {
            "path": registry_path,
            "value": registry_path.rsplit("\\", 1)[-1] if registry_path else "",
            "data": {"strings": [fields.get("Details", "")]},
        }

    return omit_empty(event)


def run_realtime_rules(event: dict[str, Any]) -> list[dict[str, Any]]:
    """Evaluate safe realtime demo rules against one normalized event."""

    matches: list[RuleMatch] = []

    # Check for custom demo markers first
    command_line = _field_text(event, "process.command_line") or _field_text(event, "message")
    command_folded = command_line.casefold()

    if "edr_demo_tp_1" in command_folded or "edr_demo_tp_5" in command_folded or "edr_demo_fp_1" in command_folded or "edr_demo_fp_5" in command_folded:
        matches.append(RuleMatch(rule=REALTIME_RULES["t1059"], matched_fields=("process.command_line",), reason="Demo target rule triggered by marker."))
    if "edr_demo_tp_2" in command_folded or "edr_demo_tp_6" in command_folded or "edr_demo_fp_2" in command_folded or "edr_demo_fp_6" in command_folded:
        matches.append(RuleMatch(rule=REALTIME_RULES["t1105"], matched_fields=("process.command_line",), reason="Demo target rule triggered by marker."))
    if "edr_demo_tp_3" in command_folded or "edr_demo_tp_7" in command_folded or "edr_demo_fp_3" in command_folded:
        matches.append(RuleMatch(rule=REALTIME_RULES["t1547"], matched_fields=("process.command_line",), reason="Demo target rule triggered by marker."))
    if "edr_demo_tp_4" in command_folded or "edr_demo_tp_8" in command_folded or "edr_demo_fp_4" in command_folded:
        matches.append(RuleMatch(rule=REALTIME_RULES["t1218"], matched_fields=("process.command_line",), reason="Demo target rule triggered by marker."))

    matches.extend(_match_t1059(event))
    matches.extend(_match_t1105(event))
    matches.extend(_match_t1547(event))
    matches.extend(_match_t1218(event))
    return [build_realtime_alert(match=match, event=event) for match in matches]


def build_realtime_alert(
    *,
    match: RuleMatch,
    event: dict[str, Any],
    related_events: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Create the realtime alert document consumed by the dashboard."""

    rule = match.rule
    timestamp = event_timestamp(event)
    related = related_events or []
    alert = {
        "@timestamp": timestamp,
        "alert": {
            "id": build_alert_id(rule_id=rule.rule_id, event=event, related_events=related),
            "kind": "signal",
            "status": "open",
            "created": timestamp,
            "severity": rule.severity,
            "confidence": rule.confidence,
        },
        "timestamp": timestamp,
        "rule": {
            "id": rule.rule_id,
            "name": rule.name,
            "version": 1,
            "description": match.reason,
        },
        "detection": {
            "engine": rule.engine,
            "matched_fields": list(match.matched_fields),
            "reason": match.reason,
            "explanation": match.reason,
        },
        "severity": rule.severity,
        "confidence": rule.confidence,
        "attack": {
            "technique": {
                "id": rule.technique_id,
                "name": rule.technique_name,
            },
            "tactic": list(rule.tactic),
        },
        "event": selected_event_fields(event),
        "host": copy_mapping(event.get("host")),
        "user": copy_mapping(event.get("user")),
        "process": selected_process_fields(event.get("process")),
        "file": copy_mapping(event.get("file")),
        "registry": copy_mapping(event.get("registry")),
        "destination": copy_mapping(event.get("destination")),
        "network": copy_mapping(event.get("network")),
        "matched_fields": list(match.matched_fields),
        "reason": match.reason,
        "evidence": evidence_fields(event),
        "source_event": compact_event(event),
    }

    if related:
        alert["related_events"] = [compact_event(item) for item in related]
        alert["source_event_ids"] = [event_identity(item) for item in related]

    return omit_empty(alert)


class T1105RealtimeCorrelator:
    """In-memory near-realtime T1105 process + network + file correlation."""

    def __init__(self, window_seconds: int = 300) -> None:
        self.window_seconds = window_seconds
        self._events: deque[dict[str, Any]] = deque()
        self._emitted_keys: set[str] = set()

    def add_event(self, event: dict[str, Any]) -> list[dict[str, Any]]:
        """Add one event and return new behavioral alerts."""

        self._events.append(copy.deepcopy(event))
        self._prune(event_timestamp_dt(event))

        alerts: list[dict[str, Any]] = []
        for key in correlation_keys(event):
            sequence = self._sequence_for_key(key)
            if sequence is None:
                continue

            dedupe_key = self._dedupe_key(key, sequence)
            if dedupe_key in self._emitted_keys:
                continue

            self._emitted_keys.add(dedupe_key)
            alerts.append(build_t1105_behavioral_alert(sequence))

        return alerts

    def _prune(self, now: datetime) -> None:
        cutoff = now - timedelta(seconds=self.window_seconds)
        while self._events and event_timestamp_dt(self._events[0]) < cutoff:
            self._events.popleft()

    def _sequence_for_key(self, key: str) -> list[dict[str, Any]] | None:
        grouped = [
            event
            for event in self._events
            if key in correlation_keys(event) and t1105_step_name(event) is not None
        ]
        steps: dict[str, dict[str, Any]] = {}
        for event in grouped:
            step = t1105_step_name(event)
            if step and step not in steps:
                steps[step] = event

        if {"process", "network", "file"}.issubset(steps):
            return [steps["process"], steps["network"], steps["file"]]
        return None

    @staticmethod
    def _dedupe_key(key: str, events: list[dict[str, Any]]) -> str:
        event_ids = "|".join(event_identity(event) for event in events)
        return f"{key}|{event_ids}"


class RealtimeEvaluationTracker:
    """Track live TP/TN/FP/FN for deterministic realtime demo markers."""

    def __init__(self, cases: tuple[RealtimeEvaluationCase, ...] = REALTIME_EVALUATION_CASES) -> None:
        self.cases = cases
        self._states: dict[str, dict[str, Any]] = {
            case.case_id: {
                "case_id": case.case_id,
                "marker": case.marker,
                "technique_id": case.technique_id,
                "expected_alert": case.expected_alert,
                "expected_rule_ids": list(case.expected_rule_ids),
                "window_seconds": case.window_seconds,
                "status": "not_seen",
                "classification": "",
                "first_seen_at": "",
                "last_seen_at": "",
                "event_ids": [],
                "alert_ids": [],
                "actual_rule_ids": [],
                "reason": "Waiting for marker.",
            }
            for case in cases
        }

    def observe_event(self, event: dict[str, Any]) -> None:
        event_text = evaluation_document_text(event)
        event_time = event_timestamp(event)
        event_id = event_identity(event)

        for case in self._matching_cases(event_text):
            state = self._states[case.case_id]
            if self._should_start_new_observation(state=state, case=case, event=event):
                self._reset_state_for_event(state=state, case=case, event_time=event_time, event_id=event_id)
            else:
                self._append_unique(state["event_ids"], event_id)
                if not state["first_seen_at"]:
                    state["first_seen_at"] = event_time
                state["last_seen_at"] = event_time
                if state["status"] == "not_seen":
                    state["status"] = "pending"
                    state["reason"] = "Marker observed; waiting for alert window."

    def observe_alert(self, alert: dict[str, Any]) -> None:
        alert_text = evaluation_document_text(alert)
        alert_id = _text(_get_field(alert, "alert.id")) or build_alert_id(
            rule_id=_text(_get_field(alert, "rule.id")) or "unknown",
            event=alert.get("source_event") if isinstance(alert.get("source_event"), dict) else {},
            related_events=[],
        )
        rule_id = _text(_get_field(alert, "rule.id"))
        alert_time = _text(alert.get("@timestamp") or alert.get("timestamp") or _get_field(alert, "alert.created")) or now_iso()

        for case in self._matching_cases(alert_text):
            state = self._states[case.case_id]
            self._append_unique(state["alert_ids"], alert_id)
            self._append_unique(state["actual_rule_ids"], rule_id)
            if not state["first_seen_at"]:
                state["first_seen_at"] = alert_time
            state["last_seen_at"] = alert_time

            expected_rule_hit = not case.expected_rule_ids or rule_id in case.expected_rule_ids
            if case.expected_alert and expected_rule_hit:
                state["status"] = "complete"
                state["classification"] = "true_positive"
                state["reason"] = "Expected alert fired for the realtime marker."
            elif not case.expected_alert:
                state["status"] = "complete"
                state["classification"] = "false_positive"
                state["reason"] = "Benign realtime marker produced an alert."

    def snapshot(self, *, now: datetime | None = None) -> dict[str, Any]:
        self._finalize_expired(now or datetime.now(UTC))
        cases = [copy.deepcopy(state) for state in self._states.values()]
        counts = {
            "true_positive": 0,
            "true_negative": 0,
            "false_positive": 0,
            "false_negative": 0,
            "pending": 0,
            "not_seen": 0,
        }

        for state in cases:
            classification = _text(state.get("classification"))
            status = _text(state.get("status"))
            if classification in counts:
                counts[classification] += 1
            elif status == "pending":
                counts["pending"] += 1
            else:
                counts["not_seen"] += 1

        observed = len(cases) - counts["not_seen"]
        return {
            "mode": "realtime_evaluation",
            "generated_at": now_iso(),
            "case_count": len(cases),
            "observed_case_count": observed,
            "counts": counts,
            "cases": cases,
        }

    def _matching_cases(self, text: str) -> list[RealtimeEvaluationCase]:
        folded = text.casefold()
        return [case for case in self.cases if case.marker.casefold() in folded]

    def _should_start_new_observation(
        self,
        *,
        state: dict[str, Any],
        case: RealtimeEvaluationCase,
        event: dict[str, Any],
    ) -> bool:
        status = _text(state.get("status"))
        if status == "not_seen":
            return True
        if status == "pending":
            return False

        last_seen = _text(state.get("last_seen_at"))
        if not last_seen:
            return True

        elapsed = event_timestamp_dt(event) - parse_iso_datetime(last_seen)
        return elapsed.total_seconds() > case.window_seconds

    def _reset_state_for_event(
        self,
        *,
        state: dict[str, Any],
        case: RealtimeEvaluationCase,
        event_time: str,
        event_id: str,
    ) -> None:
        state.update(
            {
                "case_id": case.case_id,
                "marker": case.marker,
                "technique_id": case.technique_id,
                "expected_alert": case.expected_alert,
                "expected_rule_ids": list(case.expected_rule_ids),
                "window_seconds": case.window_seconds,
                "status": "pending",
                "classification": "",
                "first_seen_at": event_time,
                "last_seen_at": event_time,
                "event_ids": [event_id],
                "alert_ids": [],
                "actual_rule_ids": [],
                "reason": "Marker observed; waiting for alert window.",
            }
        )

    def _finalize_expired(self, now: datetime) -> None:
        for case in self.cases:
            state = self._states[case.case_id]
            if state["status"] != "pending":
                continue

            first_seen_at = _text(state.get("first_seen_at"))
            if not first_seen_at:
                continue

            elapsed = now - parse_iso_datetime(first_seen_at)
            if elapsed.total_seconds() < case.window_seconds:
                continue

            state["status"] = "complete"
            if case.expected_alert:
                state["classification"] = "false_negative"
                state["reason"] = "Expected alert did not fire before the realtime evaluation window expired."
            else:
                state["classification"] = "true_negative"
                state["reason"] = "Benign realtime marker produced no alert during the evaluation window."

    @staticmethod
    def _append_unique(values: list[str], value: str) -> None:
        if value and value not in values:
            values.append(value)


class RealtimeElasticsearchSink:
    """Best-effort Elasticsearch writer for realtime demo events and alerts."""

    def __init__(self, *, base_url: str, timeout_seconds: int = 3) -> None:
        self.base_url = base_url.strip().rstrip("/")
        self.timeout_seconds = timeout_seconds
        self.event_config = EventIndexingConfig(
            base_url=self.base_url,
            timeout_seconds=timeout_seconds,
            index_prefix="edr-realtime-events",
        )
        self.alert_config = AlertIndexingConfig(
            base_url=self.base_url,
            timeout_seconds=timeout_seconds,
            index_prefix="edr-realtime-alerts",
        )
        self.status = "disconnected"
        self.last_error = ""

    def ping(self) -> bool:
        if not self.base_url:
            self._mark_disconnected("Elasticsearch URL is not configured.")
            return False

        request = urllib.request.Request(self.base_url, method="GET")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
                status = getattr(response, "status", response.getcode())
        except (TimeoutError, urllib.error.URLError, OSError) as exc:
            self._mark_disconnected(str(exc))
            return False

        if 200 <= status < 400:
            self._mark_connected()
            return True

        self._mark_disconnected(f"HTTP status {status}")
        return False

    def index_event(self, event: dict[str, Any]) -> bool:
        try:
            index_normalized_event(event, self.event_config)
        except EventIndexingError as exc:
            self._mark_disconnected(str(exc))
            return False

        self._mark_connected()
        return True

    def index_alert(self, alert: dict[str, Any]) -> bool:
        try:
            index_native_alert(alert, self.alert_config)
        except AlertIndexingError as exc:
            self._mark_disconnected(str(exc))
            return False

        self._mark_connected()
        return True

    def _mark_connected(self) -> None:
        self.status = "connected"
        self.last_error = ""

    def _mark_disconnected(self, error: str) -> None:
        self.status = "disconnected"
        self.last_error = error


class RealtimeStore:
    """Thread-safe in-memory store plus JSONL/static JSON persistence."""

    def __init__(
        self,
        *,
        repo_root: Path,
        max_events: int = REALTIME_EVENT_LIMIT,
        max_alerts: int = REALTIME_ALERT_LIMIT,
        elasticsearch: RealtimeElasticsearchSink | None = None,
    ) -> None:
        self.repo_root = repo_root
        self.events: deque[dict[str, Any]] = deque(maxlen=max_events)
        self.alerts: deque[dict[str, Any]] = deque(maxlen=max_alerts)
        self.total_event_count = 0
        self.total_alert_count = 0
        self._alert_ids: set[str] = set()
        self._lock = threading.RLock()
        self.started_at = now_iso()
        self.last_error = ""
        self.collector_running = False
        self.last_poll_at = ""
        self.log_name = SYSMON_LOG_NAME
        self.reports_dir = self.repo_root / "reports" / "realtime"
        self.static_data_dir = self.repo_root / "dashboard" / "static" / "data"
        self.elasticsearch = elasticsearch
        self.elasticsearch_status = "disconnected"
        self.elasticsearch_last_error = "Elasticsearch URL is not configured."
        self._last_elasticsearch_warning = ""
        self.evaluation = RealtimeEvaluationTracker()

    def refresh_elasticsearch_connection(self) -> None:
        if self.elasticsearch is None:
            with self._lock:
                self.elasticsearch_status = "disconnected"
                self.elasticsearch_last_error = "Elasticsearch URL is not configured."
                self.write_static_snapshots_locked()
            return

        self.elasticsearch.ping()
        self._sync_elasticsearch_state()

    def add_event(self, event: dict[str, Any]) -> None:
        event_copy = copy.deepcopy(event)
        with self._lock:
            self.events.append(event_copy)
            self.total_event_count += 1
            self.evaluation.observe_event(event_copy)
            append_jsonl(self.reports_dir / "events.jsonl", event_copy)
            self.write_static_snapshots_locked()
        self._index_event(event_copy)

    def add_alert(self, alert: dict[str, Any]) -> bool:
        alert_id = _text(_get_field(alert, "alert.id"))
        alert_copy = copy.deepcopy(alert)
        with self._lock:
            if alert_id and alert_id in self._alert_ids:
                return False
            if alert_id:
                self._alert_ids.add(alert_id)
            self.alerts.append(alert_copy)
            self.total_alert_count += 1
            self.evaluation.observe_alert(alert_copy)
            append_jsonl(self.reports_dir / "alerts.jsonl", alert_copy)
            self.write_static_snapshots_locked()
        self._index_alert(alert_copy)
        return True

    def _index_event(self, event: dict[str, Any]) -> None:
        if self.elasticsearch is None:
            return
        self.elasticsearch.index_event(event)
        self._sync_elasticsearch_state()

    def _index_alert(self, alert: dict[str, Any]) -> None:
        if self.elasticsearch is None:
            return
        self.elasticsearch.index_alert(alert)
        self._sync_elasticsearch_state()

    def _sync_elasticsearch_state(self) -> None:
        if self.elasticsearch is None:
            return
        with self._lock:
            self.elasticsearch_status = self.elasticsearch.status
            self.elasticsearch_last_error = self.elasticsearch.last_error
            self._warn_elasticsearch_locked()
            self.write_static_snapshots_locked()

    def _warn_elasticsearch_locked(self) -> None:
        if self.elasticsearch_status == "connected" or not self.elasticsearch_last_error:
            return
        if self.elasticsearch_last_error == self._last_elasticsearch_warning:
            return
        self._last_elasticsearch_warning = self.elasticsearch_last_error
        print(f"[realtime-api] warning: Elasticsearch disconnected: {self.elasticsearch_last_error}", file=sys.stderr)

    def set_collector_state(self, *, running: bool, last_error: str = "") -> None:
        with self._lock:
            self.collector_running = running
            self.last_poll_at = now_iso()
            self.last_error = last_error
            self.write_static_snapshots_locked()

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            events = list(self.events)
            alerts = list(self.alerts)
            evaluation = self.evaluation.snapshot()
            return {
                "events": events,
                "alerts": alerts,
                "evaluation": evaluation,
                "summary": build_summary(
                    events=events,
                    alerts=alerts,
                    evaluation=evaluation,
                    started_at=self.started_at,
                    collector_running=self.collector_running,
                    last_error=self.last_error,
                    last_poll_at=self.last_poll_at,
                    log_name=self.log_name,
                    elasticsearch_status=self.elasticsearch_status,
                    elasticsearch_last_error=self.elasticsearch_last_error,
                    total_event_count=self.total_event_count,
                    total_alert_count=self.total_alert_count,
                ),
            }

    def write_static_snapshots(self) -> None:
        with self._lock:
            self.write_static_snapshots_locked()

    def write_static_snapshots_locked(self) -> None:
        events = list(self.events)
        alerts = list(self.alerts)
        evaluation = self.evaluation.snapshot()
        summary = build_summary(
            events=events,
            alerts=alerts,
            evaluation=evaluation,
            started_at=self.started_at,
            collector_running=self.collector_running,
            last_error=self.last_error,
            last_poll_at=self.last_poll_at,
            log_name=self.log_name,
            elasticsearch_status=self.elasticsearch_status,
            elasticsearch_last_error=self.elasticsearch_last_error,
            total_event_count=self.total_event_count,
            total_alert_count=self.total_alert_count,
        )
        write_json(self.static_data_dir / "realtime_events.json", events)
        write_json(self.static_data_dir / "realtime_alerts.json", alerts)
        write_json(self.static_data_dir / "realtime_evaluation.json", evaluation)
        write_json(self.static_data_dir / "realtime_summary.json", summary)


def build_t1105_behavioral_alert(events: list[dict[str, Any]]) -> dict[str, Any]:
    """Build the required T1105 behavioral alert document."""

    rule = REALTIME_RULES["behavioral_t1105"]
    match = RuleMatch(
        rule=rule,
        matched_fields=("sequence.process", "sequence.network", "sequence.file"),
        reason=rule.reason,
    )
    alert = build_realtime_alert(match=match, event=events[-1], related_events=events)
    alert["detection"].update(
        {
            "engine": "behavioral",
            "sequence_name": "t1105_process_network_file",
            "sequence_steps": ["process", "network", "file"],
            "correlated_event_count": len(events),
        }
    )
    return alert


def build_summary(
    *,
    events: list[dict[str, Any]],
    alerts: list[dict[str, Any]],
    evaluation: dict[str, Any] | None = None,
    started_at: str = "",
    collector_running: bool = False,
    last_error: str = "",
    last_poll_at: str = "",
    log_name: str = SYSMON_LOG_NAME,
    elasticsearch_status: str = "disconnected",
    elasticsearch_last_error: str = "",
    total_event_count: int | None = None,
    total_alert_count: int | None = None,
) -> dict[str, Any]:
    """Aggregate dashboard summary values for realtime data."""

    event_counts = Counter(str(_get_field(event, "event.code") or "unknown") for event in events)
    technique_counts = Counter(_text(_get_field(alert, "attack.technique.id")) or "unknown" for alert in alerts)
    engine_counts = Counter(_text(_get_field(alert, "detection.engine")) or "unknown" for alert in alerts)
    severity_counts = Counter(_text(alert.get("severity") or _get_field(alert, "alert.severity")) or "unknown" for alert in alerts)
    evaluation_counts = copy.deepcopy(evaluation.get("counts", {})) if isinstance(evaluation, dict) else {}

    return {
        "mode": "realtime",
        "started_at": started_at,
        "generated_at": now_iso(),
        "collector_running": collector_running,
        "collector": "running" if collector_running else "stopped",
        "elasticsearch": elasticsearch_status,
        "elasticsearch_last_error": elasticsearch_last_error,
        "log_name": log_name,
        "last_error": last_error,
        "last_poll_at": last_poll_at,
        "event_count": total_event_count if total_event_count is not None else len(events),
        "alert_count": total_alert_count if total_alert_count is not None else len(alerts),
        "event_count_by_code": dict(sorted(event_counts.items())),
        "alert_count_by_technique": dict(sorted(technique_counts.items())),
        "alert_count_by_engine": dict(sorted(engine_counts.items())),
        "severity_counts": dict(sorted(severity_counts.items())),
        "evaluation_counts": evaluation_counts,
        "evaluation_case_count": int(evaluation.get("case_count", 0)) if isinstance(evaluation, dict) else 0,
        "evaluation_observed_case_count": int(evaluation.get("observed_case_count", 0)) if isinstance(evaluation, dict) else 0,
        "latest_event_at": event_timestamp(events[-1]) if events else "",
        "latest_alert_at": _text(alerts[-1].get("@timestamp") or alerts[-1].get("timestamp")) if alerts else "",
    }


def _match_t1059(event: dict[str, Any]) -> list[RuleMatch]:
    if _event_code(event) != "1":
        return []

    process_name = _field_text(event, "process.name").casefold()
    command_line = _field_text(event, "process.command_line")
    command_folded = command_line.casefold()
    if process_name not in {"powershell.exe", "pwsh.exe"}:
        return []

    marker_hit = "edr_demo_t1059_001" in command_folded
    flag_hit = (
        "-noprofile" in command_folded
        or " -nop" in command_folded
        or ("-executionpolicy" in command_folded and "bypass" in command_folded)
    )
    if not (marker_hit or flag_hit):
        return []

    matched_fields = ["process.name"]
    if command_line:
        matched_fields.append("process.command_line")
    return [
        RuleMatch(
            rule=REALTIME_RULES["t1059"],
            matched_fields=tuple(matched_fields),
            reason=REALTIME_RULES["t1059"].reason,
        )
    ]


def _match_t1105(event: dict[str, Any]) -> list[RuleMatch]:
    process_name = _field_text(event, "process.name").casefold()
    if process_name not in DOWNLOAD_TOOL_NAMES:
        return []

    checks = (
        ("process.command_line", ("EDR_DEMO_T1105", "http://127.0.0.1", "localhost")),
        ("file.path", ("EDR_DEMO_T1105", "edr_demo_t1105", "edr_demo")),
        ("file.name", ("EDR_DEMO_T1105", "edr_demo_t1105", "edr_demo")),
        ("destination.ip", ("127.0.0.1",)),
        ("destination.domain", ("localhost", "example.test")),
        ("raw.message", ("EDR_DEMO_T1105",)),
        ("sysmon.event_data", ("EDR_DEMO_T1105", "http://127.0.0.1")),
    )
    matched = matched_contains_fields(event, checks)
    if not matched:
        return []

    return [
        RuleMatch(
            rule=REALTIME_RULES["t1105"],
            matched_fields=matched,
            reason=REALTIME_RULES["t1105"].reason,
        )
    ]


def _match_t1547(event: dict[str, Any]) -> list[RuleMatch]:
    if _event_code(event) != "13":
        return []

    registry_path = _field_text(event, "registry.path").casefold()
    if "currentversion\\run\\" not in registry_path and not registry_path.endswith("currentversion\\run"):
        if "currentversion\\runonce\\" not in registry_path and not registry_path.endswith("currentversion\\runonce"):
            return []

    return [
        RuleMatch(
            rule=REALTIME_RULES["t1547"],
            matched_fields=("registry.path", "registry.value"),
            reason=REALTIME_RULES["t1547"].reason,
        )
    ]


def _match_t1218(event: dict[str, Any]) -> list[RuleMatch]:
    if _event_code(event) != "1":
        return []

    process_name = _field_text(event, "process.name").casefold()
    command_line = _field_text(event, "process.command_line")
    command_folded = command_line.casefold()
    if process_name != "rundll32.exe":
        return []
    if "edr_demo_t1218" not in command_folded and "url.dll,fileprotocolhandler" not in command_folded:
        return []

    return [
        RuleMatch(
            rule=REALTIME_RULES["t1218"],
            matched_fields=("process.name", "process.command_line"),
            reason=REALTIME_RULES["t1218"].reason,
        )
    ]


def t1105_step_name(event: dict[str, Any]) -> str | None:
    """Classify a candidate event as a T1105 process/network/file step."""

    code = _event_code(event)
    process_name = _field_text(event, "process.name").casefold()
    event_text = _event_text(event)

    if code == "1" and process_name in DOWNLOAD_TOOL_NAMES and contains_any(
        event_text,
        ("EDR_DEMO_T1105", "http://127.0.0.1", "localhost", "curl", "Invoke-WebRequest", "iwr"),
    ):
        return "process"
    if code == "3" and process_name in DOWNLOAD_TOOL_NAMES:
        return "network"
    if code == "11" and contains_any(event_text, ("EDR_DEMO_T1105", "edr_demo_t1105", "edr_demo")):
        return "file"
    return None


def correlation_keys(event: dict[str, Any]) -> set[str]:
    """Return context keys used by the simple in-memory correlator."""

    keys: set[str] = set()
    process = event.get("process") if isinstance(event.get("process"), dict) else {}
    entity_id = _text(process.get("entity_id"))
    executable = _text(process.get("executable"))
    process_name = _text(process.get("name"))

    if entity_id:
        keys.add(f"entity:{entity_id.casefold()}")
    if executable:
        keys.add(f"image:{executable.casefold()}")
    elif process_name:
        keys.add(f"process:{process_name.casefold()}")

    for marker in marker_tokens(event):
        keys.add(f"marker:{marker}")

    return keys


def marker_tokens(event: dict[str, Any]) -> set[str]:
    text = _event_text(event).casefold()
    markers: set[str] = set()
    for marker in ("EDR_DEMO_T1105", "edr_demo_t1105", "edr_demo"):
        if marker.casefold() in text:
            markers.add(marker.casefold())
    return markers


def selected_event_fields(event: dict[str, Any]) -> dict[str, Any]:
    event_meta = event.get("event") if isinstance(event.get("event"), dict) else {}
    return {
        "id": event_meta.get("id"),
        "dataset": event_meta.get("dataset"),
        "code": _text(event_meta.get("code")),
        "kind": event_meta.get("kind"),
        "category": copy.deepcopy(event_meta.get("category")),
        "type": copy.deepcopy(event_meta.get("type")),
        "provider": event_meta.get("provider"),
        "created": event_meta.get("created"),
    }


def selected_process_fields(process: Any) -> dict[str, Any]:
    if not isinstance(process, dict):
        return {}
    return {
        "pid": process.get("pid"),
        "entity_id": process.get("entity_id"),
        "name": process.get("name"),
        "executable": process.get("executable"),
        "command_line": process.get("command_line"),
        "parent": selected_parent_process_fields(process.get("parent")),
    }


def selected_parent_process_fields(parent: Any) -> dict[str, Any]:
    if not isinstance(parent, dict):
        return {}
    return {
        "pid": parent.get("pid"),
        "entity_id": parent.get("entity_id"),
        "name": parent.get("name"),
        "executable": parent.get("executable"),
        "command_line": parent.get("command_line"),
    }


def evidence_fields(event: dict[str, Any]) -> dict[str, Any]:
    fields = {
        "process.name": _get_field(event, "process.name"),
        "process.command_line": _get_field(event, "process.command_line"),
        "process.executable": _get_field(event, "process.executable"),
        "parent.process.name": _get_field(event, "process.parent.name"),
        "destination.ip": _get_field(event, "destination.ip"),
        "destination.port": _get_field(event, "destination.port"),
        "file.path": _get_field(event, "file.path"),
        "registry.path": _get_field(event, "registry.path"),
        "registry.value": _get_field(event, "registry.value"),
        "registry.data": _get_field(event, "registry.data"),
        "raw.message": _get_field(event, "raw.message"),
    }
    return {key: copy.deepcopy(value) for key, value in fields.items() if value not in (None, "", {}, [])}


def compact_event(event: dict[str, Any]) -> dict[str, Any]:
    return omit_empty(
        {
            "id": event_identity(event),
            "timestamp": event_timestamp(event),
            "event": selected_event_fields(event),
            "host": copy_mapping(event.get("host")),
            "process": selected_process_fields(event.get("process")),
            "file": copy_mapping(event.get("file")),
            "registry": copy_mapping(event.get("registry")),
            "destination": copy_mapping(event.get("destination")),
            "network": copy_mapping(event.get("network")),
            "evidence": evidence_fields(event),
        }
    )


def build_alert_id(*, rule_id: str, event: dict[str, Any], related_events: list[dict[str, Any]]) -> str:
    material = {
        "rule_id": rule_id,
        "event_identity": event_identity(event),
        "event_timestamp": event_timestamp(event),
        "process": selected_process_fields(event.get("process")),
        "file": copy_mapping(event.get("file")),
        "registry": copy_mapping(event.get("registry")),
        "destination": copy_mapping(event.get("destination")),
        "related": [event_identity(item) for item in related_events],
    }
    digest = hashlib.sha256(json.dumps(material, sort_keys=True, default=str).encode("utf-8")).hexdigest()[:16]
    return f"{rule_id.replace('.', '-').replace('_', '-')}-{digest}"


def event_identity(event: dict[str, Any]) -> str:
    identity = (
        _get_field(event, "event.id")
        or _get_field(event, "winlog.record_id")
        or event.get("_id")
        or event.get("document_id")
    )
    if identity:
        return str(identity)

    material = {
        "timestamp": event_timestamp(event),
        "event_code": _get_field(event, "event.code"),
        "process": selected_process_fields(event.get("process")),
        "file": copy_mapping(event.get("file")),
        "registry": copy_mapping(event.get("registry")),
        "destination": copy_mapping(event.get("destination")),
    }
    digest = hashlib.sha256(json.dumps(material, sort_keys=True, default=str).encode("utf-8")).hexdigest()[:16]
    return f"local-{digest}"


def event_timestamp(event: dict[str, Any]) -> str:
    value = event.get("@timestamp") or _get_field(event, "event.created")
    return normalize_timestamp(value) if value else now_iso()


def event_timestamp_dt(event: dict[str, Any]) -> datetime:
    value = event_timestamp(event).replace("Z", "+00:00")
    return parse_iso_datetime(value)


def parse_iso_datetime(value: Any) -> datetime:
    text = _text(value).replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return datetime.now(UTC)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def normalize_timestamp(value: Any) -> str:
    if not value:
        return now_iso()

    text = str(value).strip()
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            parsed = datetime.strptime(text, fmt).replace(tzinfo=UTC)
            return parsed.isoformat(timespec="milliseconds").replace("+00:00", "Z")
        except ValueError:
            pass

    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return text
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def matched_contains_fields(
    event: dict[str, Any],
    checks: tuple[tuple[str, tuple[str, ...]], ...],
) -> tuple[str, ...]:
    matched: list[str] = []
    for field_path, markers in checks:
        if contains_any(_field_text(event, field_path), markers):
            matched.append(field_path)
    return tuple(matched)


def contains_any(value: str, markers: tuple[str, ...]) -> bool:
    folded = value.casefold()
    return any(marker.casefold() in folded for marker in markers)


def windows_basename(path: str) -> str:
    if not path:
        return ""
    return re.split(r"[\\/]", path)[-1]


def file_extension(path: str) -> str:
    name = windows_basename(path)
    if "." not in name:
        return ""
    return name.rsplit(".", 1)[-1]


def parse_int_or_none(value: Any) -> int | None:
    if value in (None, ""):
        return None
    try:
        return int(str(value))
    except ValueError:
        return None


def copy_mapping(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    return copy.deepcopy(value)


def omit_empty(value: Any) -> Any:
    if isinstance(value, dict):
        cleaned = {key: omit_empty(child) for key, child in value.items()}
        return {key: child for key, child in cleaned.items() if child not in (None, "", {}, [])}
    if isinstance(value, list):
        return [omit_empty(item) for item in value if item not in (None, "", {}, [])]
    return value


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def append_jsonl(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(value, sort_keys=True) + "\n")


def _event_shape(code: int) -> tuple[list[str], list[str], str]:
    if code == 1:
        return ["process"], ["start"], "Process Create"
    if code == 3:
        return ["network"], ["connection"], "Network connection detected"
    if code == 11:
        return ["file"], ["creation"], "File created"
    if code == 13:
        return ["registry"], ["change"], "Registry value set"
    return ["event"], ["info"], f"Sysmon Event {code}"


def _event_code(event: dict[str, Any]) -> str:
    return _text(_get_field(event, "event.code"))


def _field_text(event: dict[str, Any], field_path: str) -> str:
    return _text(_get_field(event, field_path))


def _event_text(event: dict[str, Any]) -> str:
    return " ".join(
        _text(value)
        for value in (
            event.get("@timestamp"),
            _get_field(event, "event.code"),
            _get_field(event, "process.name"),
            _get_field(event, "process.executable"),
            _get_field(event, "process.command_line"),
            _get_field(event, "file.path"),
            _get_field(event, "file.name"),
            _get_field(event, "registry.path"),
            _get_field(event, "registry.value"),
            _get_field(event, "registry.data.strings"),
            _get_field(event, "destination.ip"),
            _get_field(event, "destination.domain"),
            _get_field(event, "raw.message"),
            _get_field(event, "sysmon.event_data"),
        )
    )


def evaluation_document_text(document: dict[str, Any]) -> str:
    """Return searchable text for realtime evaluation marker matching."""

    values = [
        document.get("@timestamp"),
        document.get("timestamp"),
        _get_field(document, "rule.id"),
        _get_field(document, "attack.technique.id"),
        _get_field(document, "process.name"),
        _get_field(document, "process.executable"),
        _get_field(document, "process.command_line"),
        _get_field(document, "file.path"),
        _get_field(document, "registry.path"),
        _get_field(document, "registry.data"),
        _get_field(document, "destination.ip"),
        _get_field(document, "raw.message"),
        _get_field(document, "evidence"),
        _get_field(document, "source_event"),
        _get_field(document, "related_events"),
        _get_field(document, "sysmon.event_data"),
    ]
    return " ".join(_text(value) for value in values)


def _text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float, bool)):
        return str(value)
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True)
    return str(value)


def _get_field(event: dict[str, Any], field_path: str) -> Any:
    current: Any = event
    for part in field_path.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current
