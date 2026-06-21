"""Pure local behavioral correlation for normalized ECS-like events."""

from __future__ import annotations

import copy
from datetime import UTC, datetime
from typing import Any

from detection.behavioral.alerts import build_behavioral_alert
from detection.behavioral.sequences import BEHAVIORAL_SEQUENCES, SequenceDefinition, event_marker_tokens, match_step


def detect_behavioral_sequences(
    events: list[dict[str, Any]],
    *,
    window_seconds: int | None = None,
) -> list[dict[str, Any]]:
    """Return zero or more behavioral alert documents from normalized ECS events."""

    safe_events = [copy.deepcopy(event) for event in events]
    sorted_events = _sort_events(safe_events)
    grouped_events = _group_by_host(sorted_events)

    alerts: list[dict[str, Any]] = []
    sequence_index = 0
    for host_events in grouped_events.values():
        for definition in BEHAVIORAL_SEQUENCES:
            effective_window = window_seconds if window_seconds is not None else definition.window_seconds
            matches = _match_sequence(host_events, definition=definition, window_seconds=effective_window)
            for matched_events, matched_steps in matches:
                alerts.append(
                    build_behavioral_alert(
                        definition=definition,
                        events=matched_events,
                        sequence_steps=matched_steps,
                        sequence_index=sequence_index,
                    )
                )
                sequence_index += 1
    return alerts


def _sort_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    indexed = list(enumerate(events))
    indexed.sort(key=lambda item: (_timestamp_sort_key(item[1]), item[0]))
    return [event for _, event in indexed]


def _group_by_host(events: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    groups: dict[str, list[dict[str, Any]]] = {}
    for event in events:
        host_name = _text(_get_field(event, "host.name")) or "unknown-host"
        groups.setdefault(host_name, []).append(event)
    return groups


def _match_sequence(
    events: list[dict[str, Any]],
    *,
    definition: SequenceDefinition,
    window_seconds: int,
) -> list[tuple[list[dict[str, Any]], list[str]]]:
    if not definition.required_steps:
        return []

    matches: list[tuple[list[dict[str, Any]], list[str]]] = []
    first_step = definition.required_steps[0]

    for start_index, anchor in enumerate(events):
        if not match_step(definition, first_step, anchor):
            continue

        matched_events = [anchor]
        matched_steps = [first_step]
        matched_indexes = {start_index}
        current_index = start_index

        for step_name in definition.required_steps[1:]:
            found_index = _find_next_step(
                events,
                definition=definition,
                step_name=step_name,
                anchor=anchor,
                start_index=current_index + 1,
                window_seconds=window_seconds,
                excluded_indexes=matched_indexes,
            )
            if found_index is None:
                break
            matched_events.append(events[found_index])
            matched_steps.append(step_name)
            matched_indexes.add(found_index)
            current_index = found_index
        else:
            for optional_step in definition.optional_steps:
                optional_index = _find_next_step(
                    events,
                    definition=definition,
                    step_name=optional_step,
                    anchor=anchor,
                    start_index=start_index + 1,
                    window_seconds=window_seconds,
                    excluded_indexes=matched_indexes,
                )
                if optional_index is None:
                    continue
                matched_events.append(events[optional_index])
                matched_steps.append(optional_step)
                matched_indexes.add(optional_index)

            matches.append((matched_events, matched_steps))

    return matches


def _find_next_step(
    events: list[dict[str, Any]],
    *,
    definition: SequenceDefinition,
    step_name: str,
    anchor: dict[str, Any],
    start_index: int,
    window_seconds: int,
    excluded_indexes: set[int],
) -> int | None:
    for index in range(start_index, len(events)):
        if index in excluded_indexes:
            continue

        candidate = events[index]
        if not _within_window(anchor, candidate, window_seconds):
            continue
        if not match_step(definition, step_name, candidate):
            continue
        if not _same_or_close_process_context(anchor, candidate):
            continue
        return index
    return None


def _same_or_close_process_context(anchor: dict[str, Any], candidate: dict[str, Any]) -> bool:
    anchor_entity = _field_text(anchor, "process.entity_id")
    candidate_entity = _field_text(candidate, "process.entity_id")
    candidate_parent_entity = _field_text(candidate, "process.parent.entity_id")

    if anchor_entity and candidate_parent_entity == anchor_entity:
        return True
    if anchor_entity and candidate_entity:
        return anchor_entity == candidate_entity

    anchor_pid_name = _pid_name_context(anchor)
    candidate_pid_name = _pid_name_context(candidate)
    if anchor_pid_name and candidate_pid_name and anchor_pid_name == candidate_pid_name:
        return True

    return _close_marker_context(anchor, candidate)


def _close_marker_context(anchor: dict[str, Any], candidate: dict[str, Any]) -> bool:
    anchor_name = _field_text(anchor, "process.name").casefold()
    candidate_name = _field_text(candidate, "process.name").casefold()
    if anchor_name and candidate_name and anchor_name != candidate_name:
        return False

    shared_markers = event_marker_tokens(anchor) & event_marker_tokens(candidate)
    return bool(shared_markers)


def _pid_name_context(event: dict[str, Any]) -> tuple[str, str] | None:
    pid = _field_text(event, "process.pid")
    name = _field_text(event, "process.name").casefold()
    if not pid or not name:
        return None
    return (pid, name)


def _within_window(anchor: dict[str, Any], candidate: dict[str, Any], window_seconds: int) -> bool:
    anchor_time = _parse_timestamp(anchor)
    candidate_time = _parse_timestamp(candidate)
    if anchor_time is None or candidate_time is None:
        return True

    delta_seconds = (candidate_time - anchor_time).total_seconds()
    return 0 <= delta_seconds <= window_seconds


def _timestamp_sort_key(event: dict[str, Any]) -> datetime:
    return _parse_timestamp(event) or datetime(1970, 1, 1, tzinfo=UTC)


def _parse_timestamp(event: dict[str, Any]) -> datetime | None:
    value = event.get("@timestamp") or _get_field(event, "event.created")
    if not isinstance(value, str) or not value:
        return None

    normalized = value.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _field_text(event: dict[str, Any], field_path: str) -> str:
    return _text(_get_field(event, field_path))


def _text(value: Any) -> str:
    if value is None:
        return ""
    return str(value)


def _get_field(event: dict[str, Any], field_path: str) -> Any:
    current: Any = event
    for part in field_path.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current
