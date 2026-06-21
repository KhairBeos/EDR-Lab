import copy

import pytest

from detection.rules.native import (
    ElasticsearchConfig,
    ElasticsearchQueryError,
    build_alert_document,
    build_powershell_candidate_query,
    evaluate_rule,
    load_rule,
    parse_search_hits,
)
from scripts.smoke.end_to_end_art_telemetry_smoke import build_smoke_payloads, load_fixture


FIXED_CREATED_AT = "2026-06-16T15:30:00Z"


def powershell_process_event() -> dict:
    _, normalized_payload = build_smoke_payloads(load_fixture())
    payload = copy.deepcopy(normalized_payload)
    payload["process"]["name"] = "powershell.exe"
    payload["process"]["executable"] = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    payload["process"]["command_line"] = "powershell.exe -NoLogo"
    payload["process"]["args"] = ["powershell.exe", "-NoLogo"]
    return payload


def test_default_elasticsearch_config_matches_local_lab() -> None:
    config = ElasticsearchConfig()

    assert config.base_url == "http://localhost:9200"
    assert config.index_pattern == "edr-raw-events-*"
    assert config.timeout_seconds == 10
    assert config.size == 100


def test_query_filters_normalized_sysmon_event_id_1() -> None:
    query = build_powershell_candidate_query()
    filters = query["query"]["bool"]["filter"]

    assert {"term": {"event.dataset": "windows.sysmon_operational"}} in filters
    assert {"term": {"event.code": 1}} in filters


def test_query_should_match_current_process_powershell_fields_only() -> None:
    query = build_powershell_candidate_query(size=25)
    bool_query = query["query"]["bool"]

    assert query["size"] == 25
    assert bool_query["minimum_should_match"] == 1
    assert bool_query["should"] == [
        {"term": {"process.name": "powershell.exe"}},
        {
            "wildcard": {
                "process.executable": {
                    "value": "*\\powershell.exe",
                    "case_insensitive": True,
                }
            }
        },
        {
            "wildcard": {
                "process.command_line": {
                    "value": "*powershell.exe*",
                    "case_insensitive": True,
                }
            }
        },
    ]
    assert "parent" not in str(bool_query["should"])


def test_parse_search_hits_converts_source_and_source_metadata() -> None:
    event = powershell_process_event()
    response = {
        "hits": {
            "hits": [
                {
                    "_index": "edr-raw-events-2026.06.16",
                    "_id": "powershell-doc-1",
                    "_source": event,
                }
            ]
        }
    }

    candidates = parse_search_hits(response)

    assert len(candidates) == 1
    assert candidates[0].event is event
    assert candidates[0].source == {
        "index": "edr-raw-events-2026.06.16",
        "document_id": "powershell-doc-1",
    }


def test_missing_source_raises_predictable_error() -> None:
    response = {
        "hits": {
            "hits": [
                {
                    "_index": "edr-raw-events-2026.06.16",
                    "_id": "missing-source",
                }
            ]
        }
    }

    with pytest.raises(ElasticsearchQueryError, match="missing _source"):
        parse_search_hits(response)


def test_malformed_response_raises_predictable_error() -> None:
    with pytest.raises(ElasticsearchQueryError, match="missing hits.hits"):
        parse_search_hits({"unexpected": {}})

    with pytest.raises(ElasticsearchQueryError, match="must be a list"):
        parse_search_hits({"hits": {"hits": {}}})


def test_candidate_can_pass_native_evaluator() -> None:
    rule = load_rule()
    response = {
        "hits": {
            "hits": [
                {
                    "_index": "edr-raw-events-2026.06.16",
                    "_id": "powershell-doc-1",
                    "_source": powershell_process_event(),
                }
            ]
        }
    }

    candidate = parse_search_hits(response)[0]
    result = evaluate_rule(rule, candidate.event)

    assert result.matched is True
    assert result.matched_fields == ("process.name", "process.executable", "process.command_line")


def test_parent_only_powershell_candidate_does_not_match_evaluator() -> None:
    rule = load_rule()
    _, normalized_payload = build_smoke_payloads(load_fixture())
    assert normalized_payload["process"]["name"] == "cmd.exe"
    assert normalized_payload["process"]["parent"]["name"] == "powershell.exe"
    response = {
        "hits": {
            "hits": [
                {
                    "_index": "edr-raw-events-2026.06.16",
                    "_id": "parent-only-powershell-doc",
                    "_source": normalized_payload,
                }
            ]
        }
    }

    candidate = parse_search_hits(response)[0]
    result = evaluate_rule(rule, candidate.event)

    assert result.matched is False
    assert result.matched_fields == ()


def test_candidate_source_metadata_appears_in_alert_document() -> None:
    rule = load_rule()
    response = {
        "hits": {
            "hits": [
                {
                    "_index": "edr-raw-events-2026.06.16",
                    "_id": "powershell-doc-1",
                    "_source": powershell_process_event(),
                }
            ]
        }
    }
    candidate = parse_search_hits(response)[0]
    match = evaluate_rule(rule, candidate.event)

    alert = build_alert_document(
        match=match,
        rule=rule,
        event=candidate.event,
        created_at=FIXED_CREATED_AT,
        source=candidate.source,
    )

    assert alert["source"] == {
        "index": "edr-raw-events-2026.06.16",
        "document_id": "powershell-doc-1",
    }
