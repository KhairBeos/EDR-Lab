Status: ready-for-agent

# Phase 2 Detection Engine MVP PRD

## Problem Statement

The project has a Phase 1 pipeline that can load a Sysmon Event ID 1 Process Create fixture, normalize it into ECS-compatible JSON, attach Atomic Red Team metadata for `T1059.001`, and optionally send the raw and normalized payloads through the local Logstash and Elasticsearch smoke path.

From the user's perspective, the next missing piece is the first real detection path. The platform can collect and normalize PowerShell-related telemetry, but it does not yet query normalized events, evaluate a detection rule, or produce an alert document that proves the detection layer can consume the Phase 1 pipeline.

Phase 2 MVP is successful when one focused detection rule finds `T1059.001` PowerShell execution from existing normalized Sysmon Event ID 1 ECS documents and emits a simple, testable alert document.

## Solution

Build the smallest detection engine slice that turns normalized process telemetry into a detection alert:

- Define one Sigma-like or native detection rule for `T1059.001` PowerShell execution.
- Use existing normalized Sysmon Event ID 1 ECS documents as the only input event shape.
- Query Elasticsearch for matching normalized events.
- Evaluate the rule against those events.
- Produce a simple alert document with rule metadata, event evidence, ATT&CK technique metadata, and detection timestamps.
- Validate the whole path with the existing fixture-based smoke flow.

This PRD intentionally keeps Phase 2 narrow. It proves the detection layer boundary without introducing ML, Kafka, TheHive, SOAR, or a full SigmaHQ rule import.

## User Stories

1. As a detection engineer, I want a first detection path for `T1059.001`, so that Phase 2 starts with a concrete ATT&CK technique instead of another placeholder.
2. As a detection engineer, I want the detector to consume normalized Sysmon Event ID 1 ECS documents, so that it builds directly on the Phase 1 normalization contract.
3. As a detection engineer, I want the first rule to detect PowerShell process execution, so that Atomic Red Team PowerShell telemetry can create a real alert.
4. As a detection engineer, I want the rule to match `powershell.exe`, so that common Windows PowerShell execution is detected.
5. As a detection engineer, I want the rule to optionally support `pwsh.exe`, so that PowerShell Core can be covered without needing a second rule.
6. As a detection engineer, I want the rule to check process creation fields, so that it aligns with Sysmon Event ID 1 semantics.
7. As a detection engineer, I want the rule to use ECS fields such as `event.dataset`, `event.code`, `process.name`, `process.executable`, `process.command_line`, `host.name`, and `user.name`, so that it does not depend on raw Sysmon XML parsing.
8. As a detection engineer, I want the rule to preserve MITRE ATT&CK metadata, so that alerts can be traced to `T1059.001`.
9. As a detection engineer, I want the rule to preserve Atomic Red Team metadata when it exists, so that fixture-based validation can link an alert back to the ART test.
10. As a platform engineer, I want Elasticsearch querying isolated behind a small interface, so that future detection rules do not each implement their own HTTP query logic.
11. As a platform engineer, I want Elasticsearch query failures to return predictable errors, so that smoke validation can distinguish "no matching event" from "Elastic is unavailable".
12. As a platform engineer, I want the detection engine to query only normalized events, so that raw payloads do not create duplicate or malformed alerts.
13. As a platform engineer, I want the search query to filter on `event.dataset = windows.sysmon_operational`, so that it targets the normalized Sysmon stream.
14. As a platform engineer, I want the search query to filter on `event.code = 1`, so that the MVP stays scoped to Sysmon Process Create telemetry.
15. As a platform engineer, I want the search query to limit result size, so that local smoke runs remain fast and predictable.
16. As a platform engineer, I want the detection engine to accept a configurable Elasticsearch URL and index pattern, so that local Docker Compose defaults can be used without hardcoding every environment detail.
17. As a platform engineer, I want sensible defaults for the local lab, so that running the smoke path remains simple.
18. As a security engineer, I want an alert document emitted for each matching event, so that detection output has a stable contract for later correlation and response layers.
19. As a security engineer, I want each alert to include the source event timestamp, so that I can reason about when the suspicious activity happened.
20. As a security engineer, I want each alert to include the alert creation timestamp, so that I can reason about detection latency later.
21. As a security engineer, I want each alert to include host, user, process, parent process, and command line evidence, so that I can inspect the reason the alert fired.
22. As a security engineer, I want each alert to include severity, confidence, and rule ID, so that later correlation can rank and group alerts.
23. As a security engineer, I want the alert to include `attack.technique.id = T1059.001`, so that the coverage matrix can eventually consume alert metadata.
24. As a security engineer, I want the alert to include `attack.technique.name = PowerShell`, so that the alert is understandable without external lookup.
25. As a security engineer, I want the alert to include `attack.tactic` values for Execution, so that the alert is aligned to ATT&CK language.
26. As a security engineer, I want the alert to reference the matched event ID or document ID when available, so that I can pivot from alert to event.
27. As a maintainer, I want deterministic fixture-based tests for the rule, so that rule behavior does not require a live Windows VM.
28. As a maintainer, I want deterministic fixture-based tests for alert generation, so that the alert contract remains stable across refactors.
29. As a maintainer, I want smoke validation that can run without posting to Logstash, so that the core detection logic is fast to verify locally.
30. As a maintainer, I want optional smoke validation against Elasticsearch, so that the full query-to-alert path can be proven when the local lab is running.
31. As a maintainer, I want the smoke path to reuse existing Phase 1 payload builders, so that test input does not drift away from the normalization contract.
32. As a maintainer, I want the detection rule stored locally in a simple format, so that future rules can follow the same pattern.
33. As a maintainer, I want rule loading errors to be explicit, so that malformed detection rules fail loudly.
34. As a maintainer, I want unsupported event shapes to be ignored rather than crashing the detector, so that future pipeline noise does not break the MVP path.
35. As a maintainer, I want no dependency on Kafka, so that Phase 2 MVP can run on the current local Elastic lab.
36. As a maintainer, I want no dependency on ML models, so that the first detection path remains explainable and deterministic.
37. As a maintainer, I want no dependency on TheHive, so that alert generation can be validated before case management exists.
38. As a maintainer, I want no dependency on SOAR playbooks, so that response automation remains a later layer.
39. As a maintainer, I want no bulk SigmaHQ import, so that the first rule can be reviewed and tested deeply.
40. As a project owner, I want Phase 2 MVP documented as a narrow vertical slice, so that future agents can implement it without expanding scope.

## Implementation Decisions

- Treat Phase 2 Detection Engine MVP as the first detection-layer vertical slice in the existing five-layer architecture: collection -> normalization -> detection -> correlation -> response.
- Use existing normalized Sysmon Event ID 1 ECS documents as the only supported detection input.
- Do not parse raw Sysmon XML in the detection engine.
- Do not require live Windows endpoint execution for the primary test seam.
- Keep the first rule focused on PowerShell process execution for `T1059.001`.
- Store the rule as either one Sigma-like local rule or one native detection rule. The rule format should be intentionally small and should not require a full Sigma compiler.
- Prefer a native rule shape if it makes the MVP easier to run and test. Prefer a Sigma-like rule only if it can be evaluated without implementing a general-purpose Sigma backend.
- Rule metadata must include stable rule ID, name, description, severity, confidence, ATT&CK technique ID, ATT&CK technique name, ATT&CK tactic, supported data source, and expected ECS fields.
- Rule matching should use normalized process fields, especially `process.name`, `process.executable`, and `process.command_line`.
- The MVP match condition should detect at least `powershell.exe` process creation. Supporting `pwsh.exe` is acceptable if it remains part of the same simple rule.
- The Elasticsearch query should narrow candidates before local rule evaluation. It should target normalized Sysmon Process Create events and PowerShell-like process names or executable paths.
- The detection engine should keep Elasticsearch access behind a small client interface with explicit configuration for base URL, index pattern, request timeout, and result size.
- Default local lab settings should align with the Phase 1 Elastic lab: Elasticsearch on `http://localhost:9200` and the existing raw events index pattern.
- Query results should be normalized into an internal event envelope before rule evaluation, so alert generation does not depend on Elasticsearch response internals.
- Alert generation should be a separate step from querying, so fixture tests can validate rule-to-alert behavior without Elasticsearch.
- Alert documents should be simple JSON-compatible dictionaries and should avoid response, case-management, or SOAR-only fields.
- Alert IDs should be deterministic when source event identity is available, so rerunning the same fixture does not produce unstable test output.
- Alert documents should include enough evidence for manual debugging: host, user, process, parent process, command line, event timestamp, source dataset, source event code, source index, and source document ID when available.
- Alert documents should include rule metadata and ATT&CK metadata directly, not only by reference.
- Alert documents should preserve ART metadata when the matched event contains `art.*`, especially `art.technique_id`, `art.test_guid`, `art.test_name`, `art.platform`, and `art.executor`.
- The first alert contract should be close to this shape:

```json
{
  "alert": {
    "id": "det-t1059-001-<stable-source-id>",
    "kind": "signal",
    "status": "open",
    "created": "2026-06-16T00:00:00Z",
    "severity": "medium",
    "confidence": "high"
  },
  "rule": {
    "id": "det.t1059_001.powershell_process_start",
    "name": "PowerShell Process Execution",
    "version": 1
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
    "created": "2026-06-08T02:30:00.000Z"
  },
  "host": {
    "name": "WIN11-EDR-LAB"
  },
  "user": {
    "name": "edr-lab"
  },
  "process": {
    "name": "powershell.exe",
    "executable": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "command_line": "powershell.exe -NoLogo"
  },
  "source": {
    "index": "edr-raw-events-2026.06.16",
    "document_id": "elastic-doc-id"
  },
  "art": {
    "technique_id": "T1059.001"
  }
}
```

- The exact alert contract can be trimmed during implementation, but it must remain stable enough for tests and later correlation.
- The existing fixture currently represents `cmd.exe` spawned by a PowerShell parent. The MVP should explicitly decide whether the first alert fires on a PowerShell process event itself or on evidence that PowerShell is the parent process. The preferred MVP behavior is to detect PowerShell when it appears in either the process or parent process fields, because the current fixture-based smoke path already contains PowerShell parent evidence.
- If the implementation chooses process-only detection, it must add or adapt a fixture that contains `process.name = powershell.exe` while preserving the normalized Sysmon Event ID 1 ECS contract.
- The detection engine should expose a small command-line smoke entry point that can run the detection path against fixture payloads and optionally against Elasticsearch.
- Documentation should update the Phase 2 operator flow with commands for generating fixture payloads, optionally posting them to Logstash, running detection, and inspecting produced alerts.

## Testing Decisions

- Test the highest useful seam first: given a normalized Sysmon Event ID 1 ECS document representing `T1059.001` PowerShell execution, the detection path should produce one simple alert document.
- Reuse the existing fixture-based smoke path as prior art. The current smoke tests already prove ART metadata preservation, raw versus normalized payload distinction, and ECS process field availability.
- Add unit tests for the rule evaluator that pass normalized ECS dictionaries directly.
- Add unit tests that prove non-normalized raw payloads are ignored.
- Add unit tests that prove unsupported `event.code` values are ignored.
- Add unit tests that prove non-PowerShell process events do not alert.
- Add unit tests that prove PowerShell evidence in `process.name` or `process.executable` alerts.
- Add unit tests that prove PowerShell evidence in parent process fields alerts if the MVP keeps compatibility with the current fixture.
- Add unit tests for alert document generation that assert stable rule metadata, ATT&CK metadata, evidence fields, ART metadata preservation, and deterministic alert ID behavior.
- Add tests for malformed rule configuration if the rule is loaded from a file.
- Add tests for Elasticsearch query construction without requiring a live Elasticsearch container.
- Add an optional integration or smoke test path that runs only when Elasticsearch is available locally.
- Do not test private helper internals. Tests should assert observable behavior: matched events, ignored events, generated alerts, and predictable errors.
- Do not require Docker, Logstash, Elasticsearch, or a Windows VM for the core detection tests.
- Manual acceptance testing should start the local Elastic lab, generate or post the existing smoke payloads, run the detection command, and confirm at least one alert for `T1059.001`.
- A good test for this feature is one that would still pass if the detection engine internals were refactored but the rule, query behavior, and alert contract stayed correct.

## Out of Scope

- ML anomaly detection, baseline training, UEBA, LSTM command-line models, and model scoring.
- Kafka topics, Kafka consumers, streaming detection, and queue-based alert transport.
- TheHive case creation, Cortex enrichment, MISP/OpenCTI enrichment, and external case-management integrations.
- SOAR playbooks, host isolation, process kill, network block, and automated containment.
- Bulk SigmaHQ import, full Sigma compiler implementation, and broad rulepack management.
- Detection coverage for techniques other than `T1059.001`.
- Sysmon event IDs other than Event ID 1.
- Production Elastic index templates, ILM, authentication, TLS, and multi-node Elastic deployment.
- Correlation, alert deduplication across multiple rules, alert scoring, and case grouping.
- UI dashboards beyond simple Elasticsearch/Kibana verification.

## Further Notes

- This PRD depends on the Phase 1 normalization contract documented for Sysmon Event ID 1.
- The current fixture contains PowerShell as the parent process of `cmd.exe`. That is useful for validating the first detection path, but implementation should be explicit about whether parent-process PowerShell evidence is part of the MVP rule semantics.
- The preferred test seam is fixture payload -> rule evaluation -> alert document, with Elasticsearch query validation as a secondary seam.
- Keep the implementation boring and deterministic. The purpose of this MVP is to prove the detection boundary, not to maximize detection coverage.
