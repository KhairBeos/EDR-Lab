Status: done

# Technical Design: Alert Document For PowerShell Rule

## Scope

Design này chỉ bao phủ issue:

`.scratch/phase-2-detection-engine-mvp/issues/02-alert-document-for-powershell-rule.md`

Mục tiêu là tạo một alert Python dictionary / JSON document từ native rule match result của Issue 01.

In scope:

- Input là `MatchResult` từ native evaluator, matched ECS event, và rule metadata.
- Output là một JSON-compatible Python dictionary.
- Preserve ATT&CK metadata, rule metadata, ECS evidence, và `art.*` metadata nếu có.
- Deterministic alert ID để fixture tests ổn định.

Out of scope:

- Elasticsearch writing/querying.
- Detection smoke command.
- TheHive.
- SOAR.
- ML.
- Kafka.
- Correlation/deduplication across rules.
- Alert UI/dashboard.

## Design Goals

- Alert document nhỏ, stable, dễ assert trong tests.
- Không mutate matched ECS event.
- Không phụ thuộc system clock trong core tests nếu caller truyền `created_at`.
- Không yêu cầu Elasticsearch `_index` / `_id`, nhưng dùng được nếu có.
- Missing optional evidence fields không crash.

## Proposed Module Shape

Đề xuất file implementation sau:

- `detection/rules/native/alerts.py`
- `tests/test_detection_alert_document.py`

Public API:

```python
def build_alert_document(
    *,
    match: MatchResult,
    rule: dict[str, Any],
    event: dict[str, Any],
    created_at: datetime | str | None = None,
    source: dict[str, str] | None = None,
) -> dict[str, Any]:
    ...
```

Behavior:

- Nếu `match.matched is False`, raise `AlertDocumentError`.
- Validate required rule metadata.
- Extract evidence from ECS event.
- Generate stable alert ID.
- Return JSON-compatible dict.

## Alert Document Schema

Recommended shape:

```json
{
  "alert": {
    "id": "det-t1059-001-powershell-process-start-<stable-hash>",
    "kind": "signal",
    "status": "open",
    "created": "2026-06-16T15:30:00Z",
    "severity": "medium",
    "confidence": "high"
  },
  "rule": {
    "id": "det.t1059_001.powershell_process_start",
    "name": "PowerShell Process Execution",
    "version": 1,
    "description": "Detects Windows PowerShell process creation from normalized Sysmon Event ID 1 ECS documents."
  },
  "attack": {
    "technique": {
      "id": "T1059.001",
      "name": "PowerShell"
    },
    "tactic": ["Execution"]
  },
  "event": {
    "dataset": "windows.sysmon_operational",
    "code": 1,
    "kind": "event",
    "category": ["process"],
    "type": ["start"],
    "created": "2026-06-08T02:30:00.000Z"
  },
  "host": {
    "name": "WIN11-EDR-LAB"
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
      "entity_id": "{9f7f5c20-1c58-6666-ff00-000000000400}",
      "name": "explorer.exe",
      "executable": "C:\\Windows\\explorer.exe",
      "command_line": "C:\\Windows\\explorer.exe"
    }
  },
  "detection": {
    "matched_fields": [
      "process.name",
      "process.executable",
      "process.command_line"
    ]
  },
  "source": {
    "index": "edr-raw-events-2026.06.16",
    "document_id": "elastic-doc-id"
  },
  "art": {
    "technique_id": "T1059.001",
    "test_guid": "a538de64-1c74-46ed-aa60-b995ed302598",
    "test_name": "PowerShell Command Execution",
    "platform": "windows",
    "executor": "powershell"
  }
}
```

Notes:

- `source` is optional because Issue 02 has no Elasticsearch yet.
- `art` is optional but should be copied when present.
- Empty optional sections should be omitted or kept minimal; avoid fields with `None`.

## Required Fields

Required input fields from `MatchResult`:

- `matched == True`
- `rule_id`
- `matched_fields`

Required input fields from rule metadata:

- `id`
- `version`
- `name`
- `description`
- `severity`
- `confidence`
- `attack.technique_id`
- `attack.technique_name`
- `attack.tactic`

Required input fields from matched ECS event:

- `event.dataset`
- `event.code`

Required output fields:

- `alert.id`
- `alert.kind`
- `alert.status`
- `alert.created`
- `alert.severity`
- `alert.confidence`
- `rule.id`
- `rule.name`
- `rule.version`
- `attack.technique.id`
- `attack.technique.name`
- `attack.tactic`
- `event.dataset`
- `event.code`
- `detection.matched_fields`

Optional output evidence, copied if present:

- `event.kind`
- `event.category`
- `event.type`
- `event.created`
- `host.name`
- `user.domain`
- `user.name`
- `process.pid`
- `process.entity_id`
- `process.name`
- `process.executable`
- `process.command_line`
- `process.parent.pid`
- `process.parent.entity_id`
- `process.parent.name`
- `process.parent.executable`
- `process.parent.command_line`
- `art.*`
- `source.index`
- `source.document_id`

## Relationship To The Matched ECS Event

The alert is a derived document, not a replacement for the ECS event.

Rules:

- Copy only investigation-useful evidence into alert.
- Do not copy `event.original`; it can be large and belongs to source event storage.
- Do not mutate the matched event.
- Preserve `art.*` metadata exactly when present.
- Preserve process and parent process context because PowerShell investigation often needs parent/child chain.
- Preserve `event.created` as source activity time.
- Use `alert.created` as detection-time metadata.

Trade-off:

- Copying selected fields makes alert readable and stable.
- Not embedding the full event avoids huge alert docs and keeps later alert indexing simpler.

## Relationship To Rule Metadata

Alert document should snapshot rule metadata at detection time.

Copy:

- Rule ID.
- Rule name.
- Rule version.
- Rule description.
- Rule severity.
- Rule confidence.
- ATT&CK technique ID/name/tactic.

Reason:

- If rule metadata changes later, existing alerts still explain why they fired.
- Tests can assert stable alert contract without loading external docs.

Do not copy:

- Full rule `match` condition into alert.
- Full rule file path.
- Loader-specific internal fields.

## Severity / Confidence Mapping

For Issue 02, severity and confidence are direct copies from rule metadata:

```python
alert["alert"]["severity"] = rule["severity"]
alert["alert"]["confidence"] = rule["confidence"]
```

No scoring formula yet.

Allowed values:

- Severity: `low`, `medium`, `high`, `critical`
- Confidence: `low`, `medium`, `high`

For current PowerShell rule:

- `severity = medium`
- `confidence = high`

Rationale:

- Medium severity: PowerShell process creation is useful execution telemetry but not automatically malicious.
- High confidence: the detector is confident that PowerShell execution occurred if normalized process fields match.

Out of scope:

- Dynamic severity from command-line flags.
- Risk score.
- Host/user criticality.
- Correlation-based severity upgrade.
- ML confidence.

## Stable Alert ID Strategy

Goal: same rule + same source event -> same alert ID.

Recommended algorithm:

1. Build stable material from:
   - `rule.id`
   - `event.event.dataset`
   - `event.event.code`
   - `event.event.created` or `@timestamp`
   - `host.name`
   - `process.entity_id` if present
   - `process.pid` if present
   - `process.executable` or `process.name`
   - `process.command_line` if present
   - `source.document_id` if present
2. JSON serialize with sorted keys.
3. SHA-256 hash.
4. Use first 16 hex chars for readability.
5. Prefix with normalized rule name.

Example:

```text
det-t1059-001-powershell-process-start-7b7c9d2a4f8e91bc
```

Pseudo-code:

```python
def build_alert_id(rule: dict, event: dict, source: dict | None) -> str:
    material = {
        "rule_id": rule["id"],
        "dataset": get_field(event, "event.dataset"),
        "event_code": get_field(event, "event.code"),
        "event_created": get_field(event, "event.created") or event.get("@timestamp"),
        "host_name": get_field(event, "host.name"),
        "process_entity_id": get_field(event, "process.entity_id"),
        "process_pid": get_field(event, "process.pid"),
        "process_executable": get_field(event, "process.executable"),
        "process_command_line": get_field(event, "process.command_line"),
        "source_document_id": (source or {}).get("document_id"),
    }
    digest = sha256(json.dumps(material, sort_keys=True).encode("utf-8")).hexdigest()[:16]
    return f"det-t1059-001-powershell-process-start-{digest}"
```

Why not UUID:

- Random UUID breaks fixture tests.
- Stable ID helps future duplicate prevention without implementing full deduplication now.

## Test Strategy

Test seam:

`normalized ECS event + rule metadata + MatchResult -> alert document`

Primary tests:

1. Builds alert document from matched PowerShell rule result.
2. Raises clear error if `MatchResult.matched` is false.
3. Alert includes required `alert.*` fields.
4. Alert includes rule metadata.
5. Alert includes ATT&CK metadata.
6. Alert includes event dataset/code and selected event metadata.
7. Alert includes host/user/process/parent evidence when present.
8. Alert preserves `art.*` metadata when present.
9. Alert omits optional sections safely when source fields are missing.
10. Alert ID is deterministic for the same input.
11. Alert ID changes when source event identity changes.
12. Severity/confidence are copied from rule metadata.
13. Missing required rule metadata raises clear validation error.

Fixture approach:

- Reuse `build_smoke_payloads(load_fixture())`.
- Copy normalized payload and modify current process to `powershell.exe`, matching Issue 01 test strategy.
- Use `load_rule()` from native loader.
- Use `evaluate_rule()` to create real `MatchResult`.
- Pass fixed `created_at`, e.g. `"2026-06-16T15:30:00Z"`, so tests do not depend on current time.

Example test setup:

```python
rule = load_rule()
event = powershell_process_event()
match = evaluate_rule(rule, event)

alert = build_alert_document(
    match=match,
    rule=rule,
    event=event,
    created_at="2026-06-16T15:30:00Z",
)

assert alert["alert"]["severity"] == "medium"
assert alert["attack"]["technique"]["id"] == "T1059.001"
assert alert["process"]["name"] == "powershell.exe"
```

Commands:

```powershell
python -m pytest tests\test_detection_alert_document.py
python -m pytest tests\test_powershell_detection_rule.py
python -m pytest tests
```

## Example Alert Document

```json
{
  "alert": {
    "id": "det-t1059-001-powershell-process-start-7b7c9d2a4f8e91bc",
    "kind": "signal",
    "status": "open",
    "created": "2026-06-16T15:30:00Z",
    "severity": "medium",
    "confidence": "high"
  },
  "rule": {
    "id": "det.t1059_001.powershell_process_start",
    "name": "PowerShell Process Execution",
    "version": 1,
    "description": "Detects Windows PowerShell process creation from normalized Sysmon Event ID 1 ECS documents."
  },
  "attack": {
    "technique": {
      "id": "T1059.001",
      "name": "PowerShell"
    },
    "tactic": ["Execution"]
  },
  "event": {
    "dataset": "windows.sysmon_operational",
    "code": 1,
    "kind": "event",
    "category": ["process"],
    "type": ["start"],
    "created": "2026-06-08T02:30:00.000Z"
  },
  "host": {
    "name": "WIN11-EDR-LAB"
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
      "entity_id": "{9f7f5c20-1c58-6666-ff00-000000000400}",
      "name": "explorer.exe",
      "executable": "C:\\Windows\\explorer.exe",
      "command_line": "C:\\Windows\\explorer.exe"
    }
  },
  "detection": {
    "matched_fields": [
      "process.name",
      "process.executable",
      "process.command_line"
    ]
  },
  "art": {
    "technique_id": "T1059.001",
    "test_guid": "a538de64-1c74-46ed-aa60-b995ed302598",
    "test_name": "PowerShell Command Execution",
    "platform": "windows",
    "executor": "powershell"
  }
}
```

## Files To Create Or Edit

Implementation issue should create/edit:

- `detection/rules/native/alerts.py`
- `detection/rules/native/__init__.py`
- `tests/test_detection_alert_document.py`

Possible small edits:

- `detection/rules/native/evaluator.py` only if `MatchResult` needs an additional public field for matched event evidence. Prefer not to edit it unless necessary.
- `tests/test_powershell_detection_rule.py` only if a shared test helper is needed. Prefer keeping alert tests self-contained.

Do not edit:

- Smoke path scripts.
- Elasticsearch query code.
- Response/SOAR modules.
- ML modules.
- Kafka configuration.

## Implementation Notes For Later

- Use `datetime.now(timezone.utc)` only when `created_at` is not provided.
- Normalize datetime output to `YYYY-MM-DDTHH:MM:SSZ`.
- Use helper to recursively omit keys with `None` values.
- Use a dot-path helper for extracting ECS fields.
- Define `AlertDocumentError(ValueError)` for clear failures.
- Keep builder pure: no file writes, no network calls, no indexing.
