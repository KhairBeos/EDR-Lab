Status: done

# Technical Design: Native PowerShell Detection Rule

## Scope

Design này chỉ bao phủ issue:

`.scratch/phase-2-detection-engine-mvp/issues/01-native-powershell-detection-rule.md`

Mục tiêu là thiết kế rule native đầu tiên để detect `T1059.001` PowerShell execution từ existing normalized Sysmon Event ID 1 ECS documents.

In scope:

- Detect `powershell.exe` process creation từ Sysmon Event ID 1.
- Dùng existing normalized ECS fields.
- Rule chạy local trên Python dictionaries.
- Test bằng fixture-based smoke payload hiện có.

Out of scope:

- Elasticsearch querying.
- Alert writing.
- SigmaHQ import.
- Full Sigma compiler.
- ML.
- Kafka.
- TheHive.
- SOAR.
- New Sysmon Event IDs.

## Design Goals

- Đơn giản, deterministic, dễ test.
- Không phụ thuộc Docker, Elasticsearch, Logstash, Kibana, Windows VM.
- Rule format đủ rõ để sau này thêm rule mới mà không phải rewrite evaluator.
- Không parse raw Sysmon XML trong detection layer.
- Không match raw event; chỉ match normalized Sysmon Event ID 1 ECS document.

## Rule File Format

Use một native YAML rule format nhỏ, Sigma-like nhưng không cố implement Sigma spec.

Đề xuất file:

`detection/rules/native/t1059_001_powershell_process_start.yml`

Format:

```yaml
id: det.t1059_001.powershell_process_start
version: 1
name: PowerShell Process Execution
description: Detects Windows PowerShell process creation from normalized Sysmon Event ID 1 ECS documents.
severity: medium
confidence: high

attack:
  technique_id: T1059.001
  technique_name: PowerShell
  tactic:
    - Execution

data_source:
  event_dataset: windows.sysmon_operational
  event_code: 1
  event_category: process
  event_type: start

match:
  any:
    - field: process.name
      equals_any:
        - powershell.exe
    - field: process.executable
      endswith_any:
        - "\\powershell.exe"
    - field: process.command_line
      contains_any:
        - "powershell.exe"
```

Decision: issue gốc có nhắc parent process để fit fixture hiện tại, nhưng user scope lần này nói rõ `detect powershell.exe process creation`. Vì vậy design này chỉ match current process fields, không match `process.parent.*`. Nếu fixture hiện tại chỉ có PowerShell parent và process là `cmd.exe`, test cho rule này nên tạo normalized event variant trong test bằng cách copy payload rồi đổi `process.*` sang PowerShell. Không cần thêm Sysmon Event ID mới.

## Required Fields

Rule metadata required:

- `id`: stable rule ID, ví dụ `det.t1059_001.powershell_process_start`.
- `version`: integer, bắt đầu từ `1`.
- `name`: human-readable name.
- `description`: ngắn, mô tả điều kiện detect.
- `severity`: `low | medium | high | critical`.
- `confidence`: `low | medium | high`.
- `attack.technique_id`: `T1059.001`.
- `attack.technique_name`: `PowerShell`.
- `attack.tactic`: list, chứa `Execution`.
- `data_source.event_dataset`: `windows.sysmon_operational`.
- `data_source.event_code`: `1`.
- `match.any`: list condition OR.

Input ECS event required for evaluation:

- `event.dataset`
- `event.code`
- `process.name`

Input ECS event optional but useful:

- `event.category`
- `event.type`
- `process.executable`
- `process.command_line`
- `process.args`
- `host.name`
- `user.name`
- `art.technique_id`
- `tags`

Minimum normalized event gate:

```python
event["event"]["dataset"] == "windows.sysmon_operational"
event["event"]["code"] == 1
```

Best-effort normalized marker:

```python
"ecs_normalized" in event.get("tags", [])
"sysmon_event_1" in event.get("tags", [])
```

Tags should be helpful but not mandatory, because `event.dataset` + `event.code` is the actual contract.

## Matching Logic

Evaluation pipeline:

1. Validate rule config shape.
2. Gate by normalized Sysmon Event ID 1:
   - `event.dataset == windows.sysmon_operational`
   - `event.code == 1`
3. Evaluate process creation fields:
   - `process.name == powershell.exe`, case-insensitive.
   - OR `process.executable` path basename is `powershell.exe`, case-insensitive.
   - OR `process.command_line` contains executable token `powershell.exe`, case-insensitive.
4. Return match result containing:
   - `matched: true`
   - `rule_id`
   - `matched_fields`
   - original event reference/object for later alert issue.

Recommended evaluator behavior:

```python
def rule_matches(event: dict, rule: dict) -> bool:
    event_meta = event.get("event", {})
    process = event.get("process", {})

    if event_meta.get("dataset") != "windows.sysmon_operational":
        return False

    if event_meta.get("code") != 1:
        return False

    process_name = str(process.get("name", "")).lower()
    process_executable = str(process.get("executable", "")).lower()
    process_command_line = str(process.get("command_line", "")).lower()

    return (
        process_name == "powershell.exe"
        or process_executable.endswith("\\powershell.exe")
        or "powershell.exe" in process_command_line
    )
```

Best practice: implement actual evaluator generic enough for `equals_any`, `endswith_any`, `contains_any`, nhưng không implement full Sigma expression language. Rule logic vẫn data-driven, còn evaluator vẫn nhỏ.

## False Positive Boundaries

This MVP intentionally detects PowerShell process creation, not malicious PowerShell behavior.

Expected benign matches:

- Admin mở PowerShell manually.
- Developer chạy setup script.
- IT automation, login script, endpoint management agent.
- Security tooling chạy PowerShell commands.
- Atomic Red Team approved test.

Boundaries for this rule:

- The rule should not claim malicious activity by itself.
- Severity should stay `medium`, not `high/critical`, because process creation alone is weak signal.
- Confidence can be `high` for "PowerShell process execution happened", not "attack happened".
- Do not match `cmd.exe` just because parent process is PowerShell in this design.
- Do not inspect PowerShell script content, encoded commands, download cradle, AMSI bypass, or suspicious flags yet.
- Do not suppress known admin paths yet; allowlist/suppression belongs to later tuning issue.

Suggested wording:

```text
Detects PowerShell process creation. This is an execution telemetry signal, not a standalone maliciousness verdict.
```

## Test Strategy

Test at external behavior seam: normalized ECS event -> rule evaluator -> match/no-match result.

Primary tests:

1. Matches normalized Sysmon Event ID 1 where `process.name = powershell.exe`.
2. Matches normalized Sysmon Event ID 1 where `process.executable` ends with `\powershell.exe`.
3. Matches normalized Sysmon Event ID 1 where `process.command_line` contains `powershell.exe`.
4. Ignores raw payload where `event.dataset = edr.raw`.
5. Ignores normalized event where `event.code != 1`.
6. Ignores normalized Event ID 1 where process is unrelated, e.g. `cmd.exe`.
7. Matching is case-insensitive, e.g. `PowerShell.EXE`.
8. Missing optional fields do not crash evaluator.
9. Rule metadata validation fails clearly if required fields are missing.

Fixture approach:

- Reuse `build_smoke_payloads(load_fixture())`.
- Use existing normalized payload as base.
- For matching tests, clone normalized payload and set:

```python
payload["process"]["name"] = "powershell.exe"
payload["process"]["executable"] = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
payload["process"]["command_line"] = "powershell.exe -NoLogo"
```

- For non-matching test, keep existing fixture as-is if it has `process.name = cmd.exe`.

Commands:

```powershell
python -m pytest tests\test_powershell_detection_rule.py
python -m pytest tests\test_end_to_end_smoke_path.py
python -m pytest tests
```

Trade-off:

- Reusing fixture payload builder avoids drift from normalization contract.
- Mutating a copied payload in tests is acceptable here because the purpose is testing detection semantics, not XML normalization.
- Creating a new XML fixture for PowerShell process itself would be more realistic but adds fixture maintenance and is not required for this native rule design.

## Example Matching ECS Event

```json
{
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
    "name": "powershell.exe",
    "executable": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "command_line": "powershell.exe -NoLogo",
    "args": ["powershell.exe", "-NoLogo"],
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
```

Expected result:

```json
{
  "matched": true,
  "rule_id": "det.t1059_001.powershell_process_start",
  "matched_fields": ["process.name", "process.executable", "process.command_line"]
}
```

## Example Non-Matching Event

```json
{
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
    "name": "WIN11-EDR-LAB"
  },
  "user": {
    "name": "edr-lab"
  },
  "process": {
    "pid": 5824,
    "name": "cmd.exe",
    "executable": "C:\\Windows\\System32\\cmd.exe",
    "command_line": "cmd.exe /c whoami",
    "parent": {
      "pid": 4460,
      "name": "explorer.exe",
      "executable": "C:\\Windows\\explorer.exe",
      "command_line": "C:\\Windows\\explorer.exe"
    }
  },
  "tags": ["ecs_normalized", "sysmon_event_1"]
}
```

Expected result:

```json
{
  "matched": false,
  "rule_id": "det.t1059_001.powershell_process_start",
  "matched_fields": []
}
```

Raw payload non-match boundary:

```json
{
  "event": {
    "dataset": "edr.raw",
    "code": 1
  },
  "process": {
    "name": "powershell.exe"
  }
}
```

Expected result: no match, because raw payload is not normalized ECS input.

## Files To Create Or Edit

Implementation issue should create/edit:

- `detection/rules/native/t1059_001_powershell_process_start.yml`
- `detection/rules/native/__init__.py`
- `detection/rules/native/loader.py`
- `detection/rules/native/evaluator.py`
- `tests/test_powershell_detection_rule.py`

Optional if the codebase prefers a flatter first slice:

- `detection/native_rules.py`
- `tests/test_powershell_detection_rule.py`

Recommendation:

Start with the smaller module split:

- `loader.py` validates rule shape.
- `evaluator.py` evaluates rule conditions against normalized ECS dictionaries.
- YAML file stores rule metadata and conditions.

This keeps rule definition separate from Python logic without committing to full Sigma support.

## Implementation Notes For Later

- Use `yaml.safe_load` if PyYAML is already an accepted dependency. If not, JSON is acceptable to avoid dependency churn.
- Keep field access safe with a small dot-path helper, e.g. `get_field(event, "process.name")`.
- Normalize string comparisons with `.casefold()`.
- Treat missing fields as non-match, not as errors.
- Raise predictable config errors for invalid rule files.
- Do not add alert document fields in this issue. Return only match result and metadata needed by the next issue.
