Status: done

# Technical Design: Elasticsearch Query For Normalized PowerShell Events

## Scope

Design này chỉ bao phủ issue:

`.scratch/phase-2-detection-engine-mvp/issues/03-elasticsearch-query-for-normalized-powershell-events.md`

Mục tiêu là query Elasticsearch read-only để lấy candidate normalized Sysmon Event ID 1 ECS documents cho native PowerShell rule, rồi pass search hits vào evaluator đã có từ Issue 01. Alert builder của Issue 02 chỉ được dùng như integration boundary nếu cần chứng minh `_index` / `_id` được preserve làm source metadata.

In scope:

- Read/search Elasticsearch only.
- Query normalized Sysmon Event ID 1 ECS documents.
- Narrow candidates by PowerShell-like process evidence.
- Pass `_source` into native evaluator.
- Preserve `_index` and `_id` as optional `source` metadata for alert builder.

Out of scope:

- Writing alerts to Elasticsearch.
- Detection smoke command.
- TheHive.
- SOAR.
- ML.
- Kafka.
- Production index templates, ILM, auth, TLS, multi-node Elastic.

## Elasticsearch Index Pattern

Use existing Phase 1 local lab index pattern:

```text
edr-raw-events-*
```

Reason:

- Current Logstash smoke path writes both raw and normalized payloads to the same raw-events index family.
- Normalized documents are distinguished by ECS fields, not by a separate index yet.

Default config:

```python
ELASTICSEARCH_URL = "http://localhost:9200"
INDEX_PATTERN = "edr-raw-events-*"
REQUEST_TIMEOUT_SECONDS = 10
RESULT_SIZE = 100
```

Trade-off:

- `edr-raw-events-*` is imperfect naming for normalized docs, but it matches current Phase 1 infrastructure.
- A future phase can move normalized docs to a dedicated index/data stream without changing evaluator logic.

## Query DSL

The Elasticsearch query should narrow candidates but not replace native rule evaluation.

Important: Issue 01 rule currently matches **current process fields only**:

- `process.name`
- `process.executable`
- `process.command_line`

Therefore query should primarily search current process fields. Parent process fields may be excluded to avoid returning many candidates that evaluator will reject. If parent fields are included later for recall, evaluator remains source of truth and will reject parent-only PowerShell events.

Recommended MVP query:

```json
{
  "size": 100,
  "sort": [
    {
      "@timestamp": {
        "order": "desc",
        "unmapped_type": "date"
      }
    }
  ],
  "query": {
    "bool": {
      "filter": [
        {
          "term": {
            "event.dataset": "windows.sysmon_operational"
          }
        },
        {
          "term": {
            "event.code": 1
          }
        }
      ],
      "should": [
        {
          "term": {
            "process.name": "powershell.exe"
          }
        },
        {
          "wildcard": {
            "process.executable": {
              "value": "*\\powershell.exe",
              "case_insensitive": true
            }
          }
        },
        {
          "wildcard": {
            "process.command_line": {
              "value": "*powershell.exe*",
              "case_insensitive": true
            }
          }
        }
      ],
      "minimum_should_match": 1
    }
  }
}
```

Implementation note:

- If local Elasticsearch mapping does not support `case_insensitive` wildcard, fallback to query normalized lowercase candidates where possible, or loosen query and let evaluator enforce case-insensitive matching.
- If exact `term` on `process.name` fails because the field is mapped as text, use `process.name.keyword` where available or fallback to `match_phrase`.

Safer compatibility option:

```json
{
  "query": {
    "bool": {
      "filter": [
        { "term": { "event.dataset": "windows.sysmon_operational" } },
        { "term": { "event.code": 1 } }
      ],
      "should": [
        { "match_phrase": { "process.name": "powershell.exe" } },
        { "query_string": { "query": "process.executable:*powershell.exe OR process.command_line:*powershell.exe" } }
      ],
      "minimum_should_match": 1
    }
  }
}
```

Prefer the first bool/wildcard DSL for testability and clarity. Keep fallback as implementation note, not default.

## Required Fields

Query request config:

- Elasticsearch base URL.
- Index pattern.
- Timeout seconds.
- Result size.

Required fields in candidate documents:

- `event.dataset`
- `event.code`
- `process.name` OR `process.executable` OR `process.command_line`

Useful fields to preserve for evaluator/alert:

- `@timestamp`
- `event.kind`
- `event.category`
- `event.type`
- `event.created`
- `host`
- `user`
- `process`
- `process.parent`
- `art`
- `tags`

Required fields in Elasticsearch hit:

- `_source`: normalized ECS event document.

Optional but important fields in Elasticsearch hit:

- `_index`
- `_id`

## Distinguishing Normalized Events From Raw Events

Raw smoke payload marker:

```json
{
  "event": {
    "dataset": "edr.raw"
  }
}
```

Normalized smoke payload markers:

```json
{
  "event": {
    "dataset": "windows.sysmon_operational",
    "code": 1
  },
  "tags": ["ecs_normalized", "sysmon_event_1"]
}
```

Decision:

- Primary normalized gate is `event.dataset = windows.sysmon_operational` and `event.code = 1`.
- `tags` are optional hints, not required filters.

Reason:

- Issue 01 evaluator already uses `event.dataset` and `event.code` as the hard gate.
- Tags are useful but less fundamental than the ECS event contract.
- Raw payloads with `event.dataset = edr.raw` cannot pass the query filter or evaluator.

## Passing Search Hits Into Native Evaluator

Recommended internal shape:

```python
@dataclass(frozen=True)
class SearchCandidate:
    event: dict[str, Any]
    source: dict[str, str]
```

Conversion:

```python
def hit_to_candidate(hit: dict[str, Any]) -> SearchCandidate:
    event = hit["_source"]
    source = {
        "index": hit.get("_index", ""),
        "document_id": hit.get("_id", ""),
    }
    return SearchCandidate(event=event, source=source)
```

Evaluation flow:

```python
rule = load_rule()
candidates = search_normalized_powershell_candidates(client_config)

for candidate in candidates:
    match = evaluate_rule(rule, candidate.event)
    if match.matched:
        alert = build_alert_document(
            match=match,
            rule=rule,
            event=candidate.event,
            source=candidate.source,
        )
```

Boundary:

- Query client returns candidates.
- Evaluator decides match/no-match.
- Alert builder receives only matched event + source metadata.
- Query client does not build alerts and does not write anything.

## Preserving `_index` And `_id`

Elasticsearch hit:

```json
{
  "_index": "edr-raw-events-2026.06.16",
  "_id": "abc123",
  "_source": {
    "event": {
      "dataset": "windows.sysmon_operational",
      "code": 1
    }
  }
}
```

Internal source metadata:

```json
{
  "index": "edr-raw-events-2026.06.16",
  "document_id": "abc123"
}
```

Pass to Issue 02 alert builder:

```python
build_alert_document(
    match=match,
    rule=rule,
    event=candidate.event,
    source=candidate.source,
)
```

Expected alert output:

```json
{
  "source": {
    "index": "edr-raw-events-2026.06.16",
    "document_id": "abc123"
  }
}
```

This also participates in stable `alert.id`, so alerts built from indexed events can be stable across repeated searches.

## Error Handling

Define predictable errors:

```python
class ElasticsearchQueryError(RuntimeError):
    pass
```

Expected failure cases:

- Connection refused / timeout.
- Non-2xx HTTP response.
- Invalid JSON response.
- Missing `hits.hits` list.
- Hit missing `_source`.

Behavior:

- Raise `ElasticsearchQueryError` with a short message.
- Do not return partial malformed hits silently.
- Do not crash with raw urllib/JSON exception types at public API boundary.

## Test Strategy

Core tests must not require Docker or Elasticsearch.

Test seams:

1. Query DSL construction.
2. Hit-to-candidate conversion.
3. Candidate -> evaluator integration.
4. Candidate source metadata -> alert builder integration.
5. Error normalization for malformed responses.

Primary tests:

1. Default config uses `http://localhost:9200`, `edr-raw-events-*`, timeout `10`, size `100`.
2. Query DSL filters `event.dataset = windows.sysmon_operational`.
3. Query DSL filters `event.code = 1`.
4. Query DSL searches current process PowerShell fields.
5. Query DSL does not rely on raw payload markers.
6. `hit_to_candidate()` returns `_source` as event.
7. `hit_to_candidate()` maps `_index` to `source.index`.
8. `hit_to_candidate()` maps `_id` to `source.document_id`.
9. Candidate event can be passed to `evaluate_rule()` and matches PowerShell process creation.
10. Parent-only PowerShell candidate does not match evaluator, preserving Issue 01 boundary.
11. Candidate source metadata can be passed to `build_alert_document()` and appears in alert `source`.
12. Malformed Elasticsearch response raises `ElasticsearchQueryError`.

Optional live validation:

```powershell
docker compose up -d
python scripts\smoke\end_to_end_art_telemetry_smoke.py --post-logstash
curl.exe -s "http://localhost:9200/edr-raw-events-*/_search?q=art.technique_id:T1059.001&size=5&pretty"
```

Focused test command:

```powershell
python -m pytest tests\test_detection_elasticsearch_query.py
python -m pytest tests
```

## Example Query

Request:

```http
POST http://localhost:9200/edr-raw-events-*/_search
Content-Type: application/json
```

Body:

```json
{
  "size": 100,
  "sort": [
    {
      "@timestamp": {
        "order": "desc",
        "unmapped_type": "date"
      }
    }
  ],
  "query": {
    "bool": {
      "filter": [
        {
          "term": {
            "event.dataset": "windows.sysmon_operational"
          }
        },
        {
          "term": {
            "event.code": 1
          }
        }
      ],
      "should": [
        {
          "term": {
            "process.name": "powershell.exe"
          }
        },
        {
          "wildcard": {
            "process.executable": {
              "value": "*\\powershell.exe",
              "case_insensitive": true
            }
          }
        },
        {
          "wildcard": {
            "process.command_line": {
              "value": "*powershell.exe*",
              "case_insensitive": true
            }
          }
        }
      ],
      "minimum_should_match": 1
    }
  }
}
```

## Example Matching Hit

```json
{
  "_index": "edr-raw-events-2026.06.16",
  "_id": "powershell-doc-1",
  "_source": {
    "@timestamp": "2026-06-08T02:30:00.0000000Z",
    "event": {
      "kind": "event",
      "category": ["process"],
      "type": ["start"],
      "action": "Process Create",
      "code": 1,
      "module": "sysmon",
      "dataset": "windows.sysmon_operational",
      "created": "2026-06-08T02:30:00.000Z"
    },
    "host": {
      "name": "WIN11-EDR-LAB",
      "os": {
        "type": "windows"
      }
    },
    "user": {
      "domain": "WIN11-EDR-LAB",
      "name": "edr-lab"
    },
    "process": {
      "pid": 5824,
      "entity_id": "{9f7f5c20-1c5d-6666-0100-000000000400}",
      "name": "powershell.exe",
      "executable": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
      "command_line": "powershell.exe -NoLogo",
      "parent": {
        "pid": 4460,
        "name": "explorer.exe",
        "executable": "C:\\Windows\\explorer.exe",
        "command_line": "C:\\Windows\\explorer.exe"
      }
    },
    "art": {
      "technique_id": "T1059.001",
      "test_guid": "a538de64-1c74-46ed-aa60-b995ed302598",
      "test_name": "PowerShell Command Execution",
      "platform": "windows",
      "executor": "powershell"
    },
    "tags": ["ecs_normalized", "sysmon_event_1"]
  }
}
```

Candidate conversion:

```json
{
  "event": {
    "event": {
      "dataset": "windows.sysmon_operational",
      "code": 1
    },
    "process": {
      "name": "powershell.exe"
    }
  },
  "source": {
    "index": "edr-raw-events-2026.06.16",
    "document_id": "powershell-doc-1"
  }
}
```

Evaluator result:

```json
{
  "matched": true,
  "rule_id": "det.t1059_001.powershell_process_start",
  "matched_fields": [
    "process.name",
    "process.executable",
    "process.command_line"
  ]
}
```

## Files To Create Or Edit

Recommended implementation files:

- `detection/rules/native/elasticsearch.py`
- `detection/rules/native/__init__.py`
- `tests/test_detection_elasticsearch_query.py`

Possible additions if implementation needs clearer separation:

- `detection/rules/native/search.py`

But prefer one `elasticsearch.py` file for the MVP.

Do not edit:

- Smoke path scripts.
- Response/SOAR modules.
- ML modules.
- Kafka config.
- Rule evaluator semantics from Issue 01 unless a bug is found.
- Alert builder semantics from Issue 02 unless source metadata contract needs a bug fix.

## Suggested Public API

```python
@dataclass(frozen=True)
class ElasticsearchConfig:
    base_url: str = "http://localhost:9200"
    index_pattern: str = "edr-raw-events-*"
    timeout_seconds: int = 10
    size: int = 100


@dataclass(frozen=True)
class SearchCandidate:
    event: dict[str, Any]
    source: dict[str, str]


def build_powershell_candidate_query(size: int = 100) -> dict[str, Any]:
    ...


def parse_search_hits(response: dict[str, Any]) -> list[SearchCandidate]:
    ...


def search_powershell_candidates(config: ElasticsearchConfig) -> list[SearchCandidate]:
    ...
```

Implementation note:

- Use Python standard library `urllib.request` to avoid dependency churn.
- Keep network function small and separately test query construction/parsing.
- Core unit tests should call `build_powershell_candidate_query()` and `parse_search_hits()` only.
