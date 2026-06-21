"""MITRE ATT&CK Navigator layer generation for local EDR coverage."""

from __future__ import annotations

from typing import Any


LAYER_NAME = "EDR Advanced MVP Coverage"
LAYER_DOMAIN = "enterprise-attack"
LAYER_VERSIONS = {
    "attack": "14",
    "layer": "4.5",
    "navigator": "4.9.1",
}

REQUIRED_TECHNIQUE_ORDER = ("T1059.001", "T1105", "T1547.001", "T1218")
ENGINE_ORDER = ("native", "sigma-like", "behavioral", "ml-anomaly")
METADATA_ORDER = (
    "engines",
    "rule_ids",
    "demo_case_count",
    "true_positive_count",
    "false_positive_count",
    "false_negative_count",
    "telemetry_event_ids",
    "notes",
)
SCORE_COLORS = {
    1: "#d8e2ef",
    2: "#9ecae1",
    3: "#6baed6",
    4: "#3182bd",
    5: "#08519c",
}
TACTIC_SLUGS = {
    "Command and Control": "command-and-control",
    "Defense Evasion": "defense-evasion",
    "Execution": "execution",
    "Persistence": "persistence",
}
SEQUENCE_TECHNIQUE_IDS = {
    "t1105_download_sequence": "T1105",
    "t1547_001_registry_persistence_sequence": "T1547.001",
    "t1218_lolbin_sequence": "T1218",
}


class AttackNavigatorLayerError(RuntimeError):
    """Raised for predictable ATT&CK Navigator layer failures."""


def build_attack_navigator_layer(coverage_report: dict[str, Any]) -> dict[str, Any]:
    """Build a MITRE ATT&CK Navigator-compatible layer from coverage report data."""

    case_matrix = _optional_mapping(coverage_report.get("case_matrix"))
    dashboard_data = _optional_mapping(coverage_report.get("dashboard_data"))
    aggregates = _aggregate_techniques(
        coverage_report,
        case_matrix=case_matrix,
        dashboard_data=dashboard_data,
    )
    engines = _all_engines(aggregates)
    phase = str(coverage_report.get("project_phase") or "Current EDR coverage")

    return {
        "name": LAYER_NAME,
        "versions": dict(LAYER_VERSIONS),
        "domain": LAYER_DOMAIN,
        "description": (
            f"{phase} visualized for the EDR demo across "
            f"{_join_human([_display_engine(engine) for engine in engines])} engines. "
            "This reporting layer does not add detection semantics."
        ),
        "filters": {"platforms": ["Windows"]},
        "sorting": 0,
        "layout": {
            "layout": "side",
            "aggregateFunction": "average",
            "showID": False,
            "showName": True,
            "showAggregateScores": False,
            "countUnscored": False,
        },
        "hideDisabled": False,
        "techniques": [_build_layer_technique(aggregate) for aggregate in aggregates],
    }


def build_coverage_summary_markdown(
    coverage_report: dict[str, Any],
    layer: dict[str, Any],
    *,
    case_matrix: dict[str, Any] | None = None,
    dashboard_data: dict[str, Any] | None = None,
    project_status: str | None = None,
) -> str:
    """Render a deterministic operator summary for the generated Navigator layer."""

    aggregates = _aggregate_techniques(
        coverage_report,
        case_matrix=case_matrix,
        dashboard_data=dashboard_data,
    )
    layer_techniques = {
        technique["techniqueID"]: technique for technique in layer.get("techniques", [])
    }
    status = project_status or str(coverage_report.get("project_phase") or "Unknown")

    lines = [
        "# ATT&CK Navigator Coverage Summary",
        "",
        f"Project status: {status}",
        f"Layer name: {layer.get('name', LAYER_NAME)}",
        f"Domain: {layer.get('domain', LAYER_DOMAIN)}",
        "",
        "## Covered Techniques",
        "",
        "| Technique | Name | Tactic | Score | Color | Engines | Rule IDs | Event IDs | Demo Cases | TP | FP | FN |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]

    for aggregate in aggregates:
        technique = layer_techniques.get(aggregate["technique_id"], {})
        lines.append(
            "| "
            f"{aggregate['technique_id']} | "
            f"{aggregate['technique_name']} | "
            f"{', '.join(aggregate['tactic']) or 'unknown'} | "
            f"{technique.get('score', aggregate['score'])} | "
            f"{technique.get('color', SCORE_COLORS[aggregate['score']])} | "
            f"{', '.join(_display_engine(engine) for engine in aggregate['engines'])} | "
            f"{', '.join(aggregate['rule_ids']) or 'none'} | "
            f"{', '.join(aggregate['telemetry_event_ids']) or 'unknown'} | "
            f"{aggregate['demo_case_count']} | "
            f"{aggregate['true_positive_count']} | "
            f"{aggregate['false_positive_count']} | "
            f"{aggregate['false_negative_count']} |"
        )

    if case_matrix:
        totals = _case_matrix_totals(case_matrix)
        lines.extend(
            [
                "",
                "## Demo Matrix Totals",
                "",
                "| Total Cases | True Positives | True Negatives | False Positives | False Negatives |",
                "| --- | --- | --- | --- | --- |",
                "| "
                f"{totals['total_cases']} | "
                f"{totals['true_positive_count']} | "
                f"{totals['true_negative_count']} | "
                f"{totals['false_positive_count']} | "
                f"{totals['false_negative_count']} |",
            ]
        )

    lines.extend(
        [
            "",
            "## Score And Color Legend",
            "",
            "| Score | Color | Meaning |",
            "| --- | --- | --- |",
            f"| 1 | {SCORE_COLORS[1]} | Single engine coverage |",
            f"| 2 | {SCORE_COLORS[2]} | Native plus Sigma-like coverage |",
            f"| 3 | {SCORE_COLORS[3]} | Multi-engine coverage including behavioral or ML evidence |",
            f"| 4 | {SCORE_COLORS[4]} | Multi-engine coverage plus demo case evidence |",
            f"| 5 | {SCORE_COLORS[5]} | Multi-engine, behavioral, demo case, and response/protection evidence |",
            "",
            "## Technique Comments",
            "",
        ]
    )
    for technique in layer.get("techniques", []):
        lines.append(f"- {technique['techniqueID']}: {technique['comment']}")

    lines.extend(
        [
            "",
            "## Artifact Paths",
            "",
            "- Layer JSON: `reports/attack_navigator/edr_attack_layer.json`",
            "- Markdown summary: `reports/attack_navigator/coverage_summary.md`",
            "- Source coverage report: `reports/detection_coverage_report.json`",
            "- Optional case matrix: `reports/demo_cases/case_matrix.json`",
            "- Optional dashboard data: `reports/demo_cases/dashboard_data.json`",
            "",
            "## Limitations",
            "",
            "- This is not full ATT&CK coverage.",
            "- Detection rules are deterministic demo rules.",
            "- T1218-lite is constrained demo coverage.",
            "- There is no production containment.",
            "- Kill-process is lab-only and guarded by explicit flags.",
            "- The Navigator score is a communication score, not production detection maturity.",
        ]
    )

    return "\n".join(lines) + "\n"


def score_technique(
    *,
    engines: set[str],
    demo_case_count: int,
    has_response_or_protection: bool,
) -> int:
    """Return the deterministic communication score for a technique."""

    if len(engines) <= 1:
        return 1
    if engines == {"native", "sigma-like"}:
        return 2
    if demo_case_count <= 0:
        return 3
    if has_response_or_protection and "behavioral" in engines:
        return 5
    return 4


def render_json_layer(layer: dict[str, Any]) -> str:
    """Render a Navigator layer as stable JSON."""

    import json

    return json.dumps(layer, indent=2, sort_keys=True)


def _build_layer_technique(aggregate: dict[str, Any]) -> dict[str, Any]:
    technique: dict[str, Any] = {
        "techniqueID": aggregate["technique_id"],
        "score": aggregate["score"],
        "color": SCORE_COLORS[aggregate["score"]],
        "comment": _technique_comment(aggregate),
        "metadata": _metadata_entries(aggregate),
    }
    tactic = _navigator_tactic(aggregate["tactic"])
    if tactic:
        technique["tactic"] = tactic
    return technique


def _aggregate_techniques(
    coverage_report: dict[str, Any],
    *,
    case_matrix: dict[str, Any] | None = None,
    dashboard_data: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    techniques: dict[str, dict[str, Any]] = {}

    for covered in _list_of_mappings(coverage_report.get("covered_techniques")):
        technique_id = str(covered.get("technique_id") or "").strip()
        if not technique_id:
            continue
        aggregate = _ensure_aggregate(techniques, technique_id)
        aggregate["technique_name"] = str(covered.get("technique_name") or aggregate["technique_name"])
        aggregate["tactic"].update(str(tactic) for tactic in _as_list(covered.get("tactic")) if tactic)
        aggregate["engines"].update(str(engine) for engine in _as_list(covered.get("engines")) if engine)
        datasource = _optional_mapping(covered.get("datasource"))
        aggregate["telemetry_event_ids"].update(_split_event_codes(datasource.get("event_code")))

    for rule in _list_of_mappings(coverage_report.get("rule_inventory")):
        attack = _optional_mapping(rule.get("attack"))
        technique_id = str(attack.get("technique_id") or "").strip()
        if not technique_id:
            continue
        aggregate = _ensure_aggregate(techniques, technique_id)
        aggregate["technique_name"] = str(attack.get("technique_name") or aggregate["technique_name"])
        aggregate["tactic"].update(str(tactic) for tactic in _as_list(attack.get("tactic")) if tactic)
        engine = str(rule.get("engine") or "").strip()
        if engine:
            aggregate["engines"].add(engine)
        rule_id = str(rule.get("rule_id") or "").strip()
        if rule_id:
            aggregate["rule_ids"].add(rule_id)
        datasource = _optional_mapping(rule.get("supported_datasource"))
        aggregate["telemetry_event_ids"].update(_split_event_codes(datasource.get("event_code")))

    if case_matrix:
        for case in _list_of_mappings(case_matrix.get("cases")):
            technique_id = str(case.get("technique_id") or "").strip()
            if not technique_id or technique_id not in techniques:
                continue
            aggregate = techniques[technique_id]
            aggregate["demo_case_count"] += 1
            classification = str(case.get("classification") or "")
            if classification == "true_positive":
                aggregate["true_positive_count"] += 1
            elif classification == "false_positive":
                aggregate["false_positive_count"] += 1
            elif classification == "false_negative":
                aggregate["false_negative_count"] += 1

            aggregate["engines"].update(str(engine) for engine in _as_list(case.get("actual_engines")) if engine)
            aggregate["rule_ids"].update(str(rule_id) for rule_id in _as_list(case.get("actual_rule_ids")) if rule_id)
            aggregate["telemetry_event_ids"].update(_split_event_codes(case.get("event_code")))
            if _case_has_response_or_protection(case):
                aggregate["has_response_or_protection"] = True

    if dashboard_data:
        sequence_counts = _optional_mapping(dashboard_data.get("sequence_count_by_name"))
        for sequence_name, count in sequence_counts.items():
            technique_id = SEQUENCE_TECHNIQUE_IDS.get(str(sequence_name))
            if not technique_id or not count or technique_id not in techniques:
                continue
            aggregate = techniques[technique_id]
            aggregate["sequence_count"] += int(count)

    aggregates = []
    for technique_id in sorted(techniques, key=_technique_sort_key):
        aggregate = techniques[technique_id]
        aggregate["engines"] = _ordered_values(aggregate["engines"], preferred=ENGINE_ORDER)
        aggregate["rule_ids"] = sorted(aggregate["rule_ids"])
        aggregate["tactic"] = _ordered_tactics(aggregate["tactic"])
        aggregate["telemetry_event_ids"] = _ordered_event_ids(aggregate["telemetry_event_ids"])
        aggregate["notes"] = _build_notes(aggregate)
        aggregate["score"] = score_technique(
            engines=set(aggregate["engines"]),
            demo_case_count=int(aggregate["demo_case_count"]),
            has_response_or_protection=bool(aggregate["has_response_or_protection"]),
        )
        aggregates.append(aggregate)
    return aggregates


def _ensure_aggregate(techniques: dict[str, dict[str, Any]], technique_id: str) -> dict[str, Any]:
    if technique_id not in techniques:
        techniques[technique_id] = {
            "technique_id": technique_id,
            "technique_name": _default_technique_name(technique_id),
            "tactic": set(),
            "engines": set(),
            "rule_ids": set(),
            "telemetry_event_ids": set(),
            "demo_case_count": 0,
            "true_positive_count": 0,
            "false_positive_count": 0,
            "false_negative_count": 0,
            "sequence_count": 0,
            "has_response_or_protection": False,
            "notes": [],
            "score": 1,
        }
    return techniques[technique_id]


def _default_technique_name(technique_id: str) -> str:
    names = {
        "T1059.001": "PowerShell",
        "T1105": "Ingress Tool Transfer",
        "T1547.001": "Registry Run Keys / Startup Folder",
        "T1218": "System Binary Proxy Execution",
    }
    return names.get(technique_id, technique_id)


def _metadata_entries(aggregate: dict[str, Any]) -> list[dict[str, str]]:
    values = {
        "engines": ", ".join(_display_engine(engine) for engine in aggregate["engines"]),
        "rule_ids": ", ".join(aggregate["rule_ids"]),
        "demo_case_count": str(aggregate["demo_case_count"]),
        "true_positive_count": str(aggregate["true_positive_count"]),
        "false_positive_count": str(aggregate["false_positive_count"]),
        "false_negative_count": str(aggregate["false_negative_count"]),
        "telemetry_event_ids": ", ".join(aggregate["telemetry_event_ids"]),
        "notes": "; ".join(aggregate["notes"]),
    }
    return [
        {"name": name, "value": values[name]}
        for name in METADATA_ORDER
        if values.get(name)
    ]


def _technique_comment(aggregate: dict[str, Any]) -> str:
    technique_id = aggregate["technique_id"]
    event_ids = "/".join(aggregate["telemetry_event_ids"]) or "unknown"
    engines = [_display_engine(engine) for engine in aggregate["engines"]]
    engine_phrase = _join_human(engines)

    if technique_id == "T1218":
        return (
            "T1218 is constrained T1218-lite demo coverage for deterministic "
            "LOLBin execution and behavioral sequence evidence."
        )
    if technique_id == "T1059.001" and "ml-anomaly" in aggregate["engines"]:
        return (
            "T1059.001 covered by native, Sigma-like, and ML anomaly demo "
            f"evidence using Sysmon Event ID {event_ids} process telemetry."
        )
    return (
        f"{technique_id} covered by {engine_phrase} detections using "
        f"Sysmon Event ID {event_ids} evidence."
    )


def _build_notes(aggregate: dict[str, Any]) -> list[str]:
    notes: list[str] = []
    if "behavioral" in aggregate["engines"]:
        notes.append("Includes behavioral correlation coverage.")
    if "ml-anomaly" in aggregate["engines"]:
        notes.append("Includes ML anomaly demo evidence.")
    if aggregate["demo_case_count"]:
        notes.append("Includes demo case evidence.")
    if aggregate["has_response_or_protection"]:
        notes.append("Includes lab-only response/protection evidence.")
    if aggregate["sequence_count"]:
        notes.append(f"Dashboard sequence count: {aggregate['sequence_count']}.")
    if aggregate["technique_id"] == "T1218":
        notes.append("T1218-lite is constrained deterministic demo coverage.")
    return notes


def _case_has_response_or_protection(case: dict[str, Any]) -> bool:
    expected_protection = case.get("expected_protection")
    return (
        bool(case.get("expected_response"))
        or int(case.get("response_count") or 0) > 0
        or int(case.get("indexed_response_count") or 0) > 0
        or (expected_protection not in (None, "", "none"))
    )


def _case_matrix_totals(case_matrix: dict[str, Any]) -> dict[str, int]:
    cases = _list_of_mappings(case_matrix.get("cases"))
    return {
        "total_cases": int(case_matrix.get("case_count") or len(cases)),
        "true_positive_count": int(
            case_matrix.get("true_positive_count")
            or sum(1 for case in cases if case.get("classification") == "true_positive")
        ),
        "true_negative_count": int(
            case_matrix.get("true_negative_count")
            or sum(1 for case in cases if case.get("classification") == "true_negative")
        ),
        "false_positive_count": int(
            case_matrix.get("false_positive_count")
            or sum(1 for case in cases if case.get("classification") == "false_positive")
        ),
        "false_negative_count": int(
            case_matrix.get("false_negative_count")
            or sum(1 for case in cases if case.get("classification") == "false_negative")
        ),
    }


def _all_engines(aggregates: list[dict[str, Any]]) -> list[str]:
    engines: set[str] = set()
    for aggregate in aggregates:
        engines.update(aggregate["engines"])
    return _ordered_values(engines, preferred=ENGINE_ORDER)


def _optional_mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _list_of_mappings(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, set):
        return list(value)
    return [value]


def _split_event_codes(value: Any) -> set[str]:
    codes: set[str] = set()
    for item in _as_list(value):
        text = str(item)
        for part in text.replace(",", "/").split("/"):
            code = part.strip()
            if code and code.lower() != "unknown" and code.lower() != "none":
                codes.add(code)
    return codes


def _ordered_values(values: set[str], *, preferred: tuple[str, ...]) -> list[str]:
    ordered = [value for value in preferred if value in values]
    ordered.extend(sorted(value for value in values if value not in preferred))
    return ordered


def _ordered_tactics(values: set[str]) -> list[str]:
    preferred = ("Execution", "Command and Control", "Persistence", "Defense Evasion")
    return _ordered_values(values, preferred=preferred)


def _ordered_event_ids(values: set[str]) -> list[str]:
    def sort_key(value: str) -> tuple[int, str]:
        return (int(value), value) if value.isdigit() else (999, value)

    return sorted(values, key=sort_key)


def _technique_sort_key(technique_id: str) -> tuple[int, str]:
    if technique_id in REQUIRED_TECHNIQUE_ORDER:
        return (REQUIRED_TECHNIQUE_ORDER.index(technique_id), technique_id)
    return (len(REQUIRED_TECHNIQUE_ORDER), technique_id)


def _navigator_tactic(tactics: list[str]) -> str | None:
    if not tactics:
        return None
    return TACTIC_SLUGS.get(tactics[0], tactics[0].lower().replace(" ", "-"))


def _display_engine(engine: str) -> str:
    labels = {
        "native": "native",
        "sigma-like": "Sigma-like",
        "behavioral": "behavioral",
        "ml-anomaly": "ML anomaly",
    }
    return labels.get(engine, engine)


def _join_human(values: list[str]) -> str:
    if not values:
        return "no"
    if len(values) == 1:
        return values[0]
    if len(values) == 2:
        return f"{values[0]} and {values[1]}"
    return f"{', '.join(values[:-1])}, and {values[-1]}"
