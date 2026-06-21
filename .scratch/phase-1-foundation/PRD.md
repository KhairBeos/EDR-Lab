Status: ready-for-agent

# Phase 1 Foundation PRD

## Problem Statement

The project needs a working Phase 1 foundation for the EDR Advanced platform. Right now the repository has the intended folder structure and placeholder files, but there is no runnable lab environment, no configured Windows endpoint telemetry path, no usable Sysmon baseline, no Elastic Stack deployment, no Atomic Red Team execution flow, and no ECS normalization path from raw endpoint events to searchable Kibana data.

From the user's perspective, Phase 1 is successful when a Windows 10/11 endpoint can execute a selected Atomic Red Team test, produce tagged telemetry, ship that telemetry into the collection pipeline, normalize it into ECS-compatible fields, and make the raw ART-related events visible in Kibana by MITRE ATT&CK technique ID.

## Solution

Build the Phase 1 lab foundation described in the README:

- Provision a Windows endpoint profile for victim-machine telemetry generation.
- Install and configure Sysmon using a SwiftOnSecurity-style baseline adapted for the priority Event IDs.
- Deploy an Elastic Stack lab with Elasticsearch, Kibana, and Logstash using Docker Compose.
- Add the collection path needed to ingest Sysmon and Windows Event Log records.
- Configure Atomic Red Team for selected Windows techniques and provide a Python execution wrapper that injects `art.*` metadata.
- Normalize raw endpoint and ART execution events into ECS-compatible records before detection layers consume them.
- Provide validation commands and tests that prove the end-to-end path works.

This PRD focuses only on Phase 1 foundation work. Later detection, ML, correlation, SOAR, and CI/CD validation capabilities build on this pipeline.

## User Stories

1. As a security engineer, I want a documented Windows endpoint setup, so that I can prepare a repeatable victim machine for ART execution.
2. As a security engineer, I want endpoint prerequisites documented, so that Sysmon, PowerShell logging, and event collection are enabled consistently.
3. As a security engineer, I want a Sysmon baseline configuration, so that high-value process, network, file, registry, image-load, and DNS telemetry is collected.
4. As a detection engineer, I want Sysmon Event ID 1 collected, so that process creation and parent-child chains can be analyzed later.
5. As a detection engineer, I want Sysmon Event ID 3 collected, so that network connections are available for C2 and lateral movement analysis.
6. As a detection engineer, I want Sysmon Event IDs 7, 8, and 10 collected, so that DLL loading, CreateRemoteThread, and LSASS access can support future process injection and credential access detections.
7. As a detection engineer, I want Sysmon Event IDs 11, 12, 13, 15, and 22 collected, so that file, registry, alternate data stream, and DNS behavior is available to the detection engine.
8. As a security engineer, I want critical Windows Security channel events collected, so that authentication, process, scheduled task, and account management activity is observable.
9. As a security engineer, I want PowerShell 4103 and 4104 logging covered by the endpoint guidance, so that command and script behavior from ART tests is visible.
10. As a security engineer, I want WMI-Activity events documented for collection, so that WMI persistence and execution activity can be collected in later tests.
11. As a platform engineer, I want Docker Compose to start Elasticsearch, Kibana, and Logstash, so that the lab stack is reproducible locally.
12. As a platform engineer, I want health checks for Elastic Stack services, so that startup failures are obvious before running ART tests.
13. As a platform engineer, I want persistent local volumes for Elasticsearch and Kibana, so that test data and dashboards survive container restarts during development.
14. As a platform engineer, I want Logstash pipeline configuration committed, so that raw endpoint events have a defined ingestion entry point.
15. As a platform engineer, I want collection configuration separated from detection code, so that Phase 1 can stabilize the data path before detection rules are built.
16. As a security engineer, I want Atomic Red Team cloned or referenced through a documented setup step, so that test execution uses known upstream technique definitions.
17. As a detection engineer, I want selected ART techniques listed in configuration, so that Phase 1 can start with a narrow, repeatable test set.
18. As a detection engineer, I want the first selected technique to include T1059.001 on Windows, so that PowerShell execution validates the first end-to-end event path.
19. As a detection engineer, I want an ART execution wrapper, so that tests can be run with consistent arguments and metadata.
20. As a detection engineer, I want each ART execution tagged with `art.technique_id`, so that Kibana can filter raw events by ATT&CK technique.
21. As a detection engineer, I want each ART execution tagged with `art.test_guid`, so that a single test run can be correlated across events.
22. As a detection engineer, I want each ART execution tagged with `art.test_name`, `art.platform`, `art.executor`, and `art.run_timestamp`, so that raw telemetry has enough context for validation.
23. As a detection engineer, I want ART metadata injection to be deterministic, so that tests can assert exact fields.
24. As a platform engineer, I want raw Sysmon events separated from normalized events, so that ingestion and normalization failures can be diagnosed independently.
25. As a platform engineer, I want ECS mappings for Sysmon Event ID 1, so that process fields are normalized before detection work begins.
26. As a platform engineer, I want `process.name`, `process.executable`, `process.pid`, `process.parent.name`, `process.parent.pid`, `process.command_line`, `process.args`, `user.name`, `host.name`, and `event.created` populated from Sysmon process creation records, so that future Sigma and behavioral detectors have stable input.
27. As a platform engineer, I want ECS mapping definitions to be versioned, so that mapping changes are reviewed alongside tests.
28. As a platform engineer, I want malformed events handled predictably, so that one bad event does not break the entire pipeline.
29. As a security engineer, I want Kafka topic names documented and configured for the intended architecture, so that raw, normalized, enriched, and alert streams have stable names even if Kafka is not fully exercised in the first milestone.
30. As a security engineer, I want a Kibana view for raw ART events by technique ID, so that I can visually confirm that a technique generated telemetry.
31. As a security engineer, I want a setup script for dependencies, so that a fresh environment can be prepared without manually discovering every command.
32. As a security engineer, I want a stack deployment script, so that the Elastic lab can be started consistently.
33. As a security engineer, I want a clear quick-start path, so that I can start the stack, run one ART test, and inspect Kibana.
34. As a maintainer, I want smoke tests for the configuration files, so that invalid YAML, JSON, or XML does not land unnoticed.
35. As a maintainer, I want unit tests for ART metadata tagging, so that event enrichment remains stable.
36. As a maintainer, I want unit tests for ECS normalization, so that canonical fields remain stable across refactors.
37. As a maintainer, I want an integration test seam around the local ingestion path, so that Phase 1 can prove a sample Sysmon event becomes a normalized ECS event without requiring a live Windows endpoint.
38. As a maintainer, I want documentation that distinguishes host setup from Docker stack setup, so that Windows endpoint work and Ubuntu/Linux server work do not get mixed together.
39. As a maintainer, I want all Phase 1 commands documented in the README or project docs, so that future contributors can reproduce the foundation.
40. As a maintainer, I want Phase 1 explicitly marked complete only when raw ART events are visible in Kibana by technique ID, so that the milestone stays tied to the README deliverable.

## Implementation Decisions

- Treat Phase 1 as a data pipeline milestone, not a detection milestone.
- The Windows endpoint is the telemetry source. The Linux or Docker host runs Elastic Stack services and development tooling.
- Endpoint setup guidance must cover Windows 10/11, Sysmon installation, PowerShell logging, Windows Event Log channels, and connectivity to the collection endpoint.
- Sysmon configuration starts from the SwiftOnSecurity baseline concept but is stored locally and adapted to the README's priority event IDs.
- Elastic Stack runs through Docker Compose with Elasticsearch, Kibana, and Logstash as the required services.
- Kafka topic architecture is recorded in configuration, but Kafka may be introduced as a defined interface before it is required for the first end-to-end smoke test. The first milestone can route endpoint events through Logstash directly if that keeps the foundation testable.
- Atomic Red Team execution is controlled through a Python wrapper rather than direct ad hoc shell commands.
- The wrapper accepts technique ID, platform, executor options where needed, and a metadata-tagging flag.
- The wrapper produces a structured execution record even when the ART command fails, so failed runs can still be diagnosed.
- ART metadata uses the README field names: `art.technique_id`, `art.test_guid`, `art.test_name`, `art.platform`, `art.executor`, and `art.run_timestamp`.
- Selected techniques are maintained in configuration to keep the initial ART scope explicit.
- T1059.001 PowerShell on Windows is the first required happy-path technique.
- ECS normalization is a separate module from ART execution and stack deployment.
- ECS mappings are data-driven where practical, so new Sysmon Event IDs can be added without rewriting core parsing logic.
- Sysmon Event ID 1 normalization is the first required mapping because it proves process telemetry and parent-child context.
- Raw events and normalized events remain distinguishable in index names or event metadata.
- Kibana must expose a queryable view or saved object that can filter on `art.technique_id`.
- Setup scripts should orchestrate documented commands, not hide important prerequisites.
- Secrets, hostnames, credentials, and endpoint-specific values should come from environment files or documented local configuration rather than hardcoded values.
- The implementation should keep Phase 2 detection code untouched except where a future detection seam needs a stable normalized event contract.
- Documentation must describe what runs on the Windows endpoint versus what runs on the Elastic Stack host.

## Testing Decisions

- Test external behavior at the highest useful seam: given a representative Sysmon/Windows event and ART metadata, the pipeline should produce an ECS-compatible normalized event with expected fields.
- Add configuration validation tests for Docker Compose, Logstash pipelines, Sysmon XML, selected ART technique YAML, Kafka topic YAML, and JSON outputs.
- Add unit tests for ART metadata injection. These tests should verify required `art.*` keys, timestamp formatting, and preservation of original event fields.
- Add unit tests for ECS normalization. These tests should verify Sysmon Event ID 1 mappings into process, user, host, and event fields.
- Add tests for malformed or partial input events. These tests should assert predictable errors or skipped-event records rather than crashes.
- Add a smoke test for the ART runner interface that can run in dry-run mode without a Windows endpoint.
- Add a smoke test for Docker Compose configuration that validates service definitions without requiring the full stack to run in CI.
- Add an integration test using fixture events to simulate the ingestion-to-normalization path without depending on a live Windows endpoint.
- Avoid testing implementation details such as private helper function names or exact parser internals.
- Existing scaffold tests in validation are placeholders and should be replaced or extended as Phase 1 modules become real.
- Manual acceptance testing requires starting the Elastic Stack, running a Windows ART test, confirming events arrive, and filtering in Kibana by `art.technique_id`.

## Out of Scope

- Sigma rule import, compilation, deployment, and alert generation.
- ML anomaly detection, baseline training, MLflow tracking, and UEBA.
- Behavioral detection rules such as process tree and sequence detection.
- TheHive, Cortex, MISP, OpenCTI, ATT&CK Navigator automation, and alert scoring.
- SOAR playbooks and host containment actions.
- Full GitHub Actions detection validation against an isolated lab VM.
- Production hardening, TLS, authentication policy, multi-node Elastic clusters, and long-term log retention tuning.
- Achieving the full README target of 80% MITRE ATT&CK tactic coverage.

## Further Notes

- The README currently states that Phase 1 deliverable is an end-to-end log pipeline with raw ART events visible in Kibana. That is the acceptance bar for this PRD.
- The current repository has placeholders for the relevant Phase 1 files. Implementation should replace placeholders incrementally rather than creating a parallel structure.
- The project glossary defines Atomic Red Team as the primary source for adversary emulation events and detection validation. Phase 1 should preserve that language in docs, tests, and issue titles.
- The first useful demo should be small: start Elastic Stack, run one Windows PowerShell ART technique, ingest telemetry, normalize process fields, and show the event in Kibana by technique ID.
