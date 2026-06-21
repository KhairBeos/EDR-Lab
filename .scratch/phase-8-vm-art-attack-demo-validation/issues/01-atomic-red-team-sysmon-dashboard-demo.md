Status: done

# Atomic Red Team Sysmon dashboard demo validation

## Goal

Implement an Atomic Red Team backed Windows VM demo validation pack that proves the current EDR MVP works with real lab-generated Sysmon telemetry.

This is a demo and validation phase, not a new detection semantics phase. The implementation should connect a safe Windows VM Atomic Red Team run to the existing collection, normalization, detection, ML anomaly, Kafka dry-run, SOAR dry-run, reporting, and Kibana validation workflow.

## Context

Current capabilities already exist and should be reused:

- Sysmon Event ID 1 XML normalization into ECS-like documents.
- Native `T1059.001` PowerShell process-start detection.
- Sigma-like `T1059.001` PowerShell process-start detection.
- Normalized event indexing to `edr-normalized-events-*`.
- Alert indexing to `edr-alerts-native-*`.
- Kafka deterministic dry-run path for detectable PowerShell fixtures.
- SOAR dry-run response records.
- ML-style process anomaly detection from normalized ECS-like events.
- Final demo JSON/Markdown reporting.

This phase adds operator docs, safe samples, a demo orchestration script, evidence bundle generation, and tests that prove the demo pack can be run without requiring live infrastructure in CI.

## Demo flow

The intended operator flow is:

```text
Windows VM
  -> install Sysmon
  -> install Atomic Red Team
  -> run safe T1059.001 PowerShell atomic test
  -> Sysmon records Event ID 1
  -> export Sysmon XML
  -> normalize XML through existing pipeline
  -> run native and Sigma-like detection
  -> optionally run ML anomaly demo from crafted normalized JSON
  -> index normalized events and alerts when Elasticsearch is enabled
  -> run SOAR dry-run response
  -> validate in Kibana Discover/dashboard
  -> generate evidence bundle
```

The automated tests must use local fixtures and monkeypatches. They must not require Windows VM, Atomic Red Team, Docker, Kafka, Elasticsearch, or Kibana.

## Technical design

Create:

- `docs/windows_vm_atomic_red_team_demo.md`
- `docs/atomic_attack_case_catalog.md`
- `docs/sysmon_event_export.md`
- `docs/kibana_dashboard_validation.md`
- `docs/demo_evidence_checklist.md`
- `scripts/demo/run_art_sysmon_demo_validation.py`
- `scripts/demo/build_demo_evidence_bundle.py`
- `tests/test_art_sysmon_demo_docs.py`
- `samples/sysmon/art_t1059_001_powershell_event.xml`
- `samples/sysmon/ml_suspicious_process_event.json`

Optional if practical:

- `kibana/saved_objects/edr_demo_dashboard.ndjson`

Reuse existing code instead of duplicating behavior:

- `normalization/sysmon/process_create_normalizer.py` for Sysmon Event ID 1 XML.
- Native PowerShell rule loader/evaluator/alert builder for `det.t1059_001.powershell_process_start`.
- Sigma-like rule loader/evaluator/alert builder for `sigma_like.t1059_001.powershell_process_start`.
- Existing alert indexer for `edr-alerts-native-*`.
- Existing normalized event indexing helper, if present; otherwise add a tiny demo-local wrapper using standard library HTTP.
- Existing SOAR dry-run engine/CLI helpers for response planning.
- Existing ML anomaly modules for JSON sample scoring.
- Existing Kafka dry-run fixture-detectable PowerShell path for Kafka validation.

Do not change rule matching semantics, ML scoring semantics, SOAR playbook semantics, or Kafka message semantics to make this demo pass.

## Windows VM and Atomic Red Team docs

Create `docs/windows_vm_atomic_red_team_demo.md`.

Document:

- Windows VM must be isolated lab only.
- Sysmon install flow.
- How to confirm the Sysmon service is running.
- How to confirm `Microsoft-Windows-Sysmon/Operational` exists.
- How to confirm Sysmon Event ID 1 appears when running a process.
- Atomic Red Team / `Invoke-AtomicRedTeam` install notes.
- Run only safe lab tests.
- Do not run Atomic Red Team on production endpoints.

Clarify roles:

- Atomic Red Team creates attack simulation activity.
- Sysmon records telemetry.
- The EDR pipeline consumes exported Sysmon XML.

## Atomic attack case catalog

Create `docs/atomic_attack_case_catalog.md`.

Primary case:

- Technique: `T1059.001` PowerShell.
- Tool: Atomic Red Team.
- Goal: trigger native and Sigma-like PowerShell detection.

Expected telemetry:

- Sysmon Event ID 1.
- `process.name = powershell.exe`.
- `process.command_line` contains an Atomic Red Team or demo marker.

Expected detections:

- Native `rule.id = det.t1059_001.powershell_process_start`.
- Sigma-like `rule.id = sigma_like.t1059_001.powershell_process_start`.

Include this fallback safe manual command:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Write-Output EDR_DEMO_T1059_001"
```

Clarify:

- The fallback manual command is not the primary attack simulator.
- Primary validation should use Atomic Red Team when available.

ML demo case:

- Use a crafted normalized ECS JSON event with encoded-command and download-keyword indicators.
- Do not include malicious payloads.
- Do not download malware.
- The sample should produce an `ml-anomaly` alert through the existing ML scoring path.

Kafka demo case:

- Use the current Kafka fixture-detectable PowerShell path.
- Expected: `processed_message_count = 1`, `alert_count = 2`.

SOAR demo case:

- Use a fixture alert or produced alert.
- Expected: one dry-run response record with planned actions only.

## Sysmon XML export docs

Create `docs/sysmon_event_export.md`.

Document:

- How to find the Sysmon Event ID 1 generated by Atomic Red Team.
- How to export the selected event as XML from Event Viewer.
- How to export using PowerShell where appropriate.
- Save XML as `samples/sysmon/art_t1059_001_powershell_event.xml` or an operator-provided path.
- How to copy XML from VM to the host project folder.

Include troubleshooting:

- Sysmon service missing.
- Event ID 1 not generated.
- Wrong event selected.
- XML namespace issues.
- Timestamp confusion.
- PowerShell execution policy issues.

## Demo validation CLI

Create `scripts/demo/run_art_sysmon_demo_validation.py`.

Commands:

```powershell
python scripts\demo\run_art_sysmon_demo_validation.py --input fixture --engine all --output summary
```

```powershell
python scripts\demo\run_art_sysmon_demo_validation.py --input xml --xml-path .\samples\sysmon\art_t1059_001_powershell_event.xml --engine all --output summary
```

```powershell
python scripts\demo\run_art_sysmon_demo_validation.py --input xml --xml-path .\event.xml --engine all --write-events --write-alerts --write-response --elasticsearch-url http://localhost:9200
```

```powershell
python scripts\demo\run_art_sysmon_demo_validation.py --input json --event-path .\samples\sysmon\ml_suspicious_process_event.json --engine ml-anomaly --output summary
```

Options:

- `--input fixture|xml|json`
- `--xml-path`
- `--event-path`
- `--engine native|sigma-like|all|ml-anomaly`, default `all`
- `--write-events`
- `--write-alerts`
- `--write-response`
- `--elasticsearch-url`, default `http://localhost:9200`
- `--output json|summary`, default `json`

Behavior:

- `fixture` input performs deterministic local validation using the current detectable PowerShell fixture.
- `fixture` input requires no VM and no Elasticsearch.
- `xml` input normalizes one Sysmon Event ID 1 XML event, then runs native and Sigma-like detection.
- `xml` input optionally indexes the normalized event.
- `xml` input optionally indexes produced alerts.
- `xml` input optionally runs SOAR dry-run response from produced alerts.
- `json` input processes one normalized ECS event through the ML anomaly path.
- `json` input optionally indexes the produced ML alert.
- Without `--write-events`, `--write-alerts`, or `--write-response`, no Elasticsearch call should be made.

Suggested output fields:

- `normalized_event_count`
- `native_alert_count`
- `sigma_like_alert_count`
- `ml_alert_count`
- `response_count`
- `indexed_event_count`
- `indexed_alert_count`
- `indexed_response_count`

Suggested exit codes:

- `0` when validation completes successfully.
- `2` for predictable operational failures such as missing input file, malformed XML/JSON, unsupported event, or requested Elasticsearch write failure.
- `3` for unexpected implementation failures.

## Kibana dashboard validation

Create `docs/kibana_dashboard_validation.md`.

Document Level 1: Kibana Discover validation.

Indexes:

- `edr-normalized-events-*`
- `edr-alerts-native-*`
- `edr-response-actions-*`

Useful filters:

- `event.dataset: windows.sysmon_operational`
- `event.code: 1`
- `process.name: powershell.exe`
- `rule.id: det.t1059_001.powershell_process_start`
- `rule.id: sigma_like.t1059_001.powershell_process_start`
- `detection.engine: ml-anomaly`
- `playbook.id: soar.playbook.powershell_execution`

Document Level 2: optional dashboard panels.

Panels:

- Normalized events over time.
- Alert count by `rule.id`.
- Alert count by `detection.engine`.
- Response count by `playbook.id`.
- Recent alerts table.
- Recent response actions table.

If a saved object is added, place it at `kibana/saved_objects/edr_demo_dashboard.ndjson`. Tests must not require saved object import.

## Evidence checklist

Create `docs/demo_evidence_checklist.md`.

Checklist items:

- Windows VM booted.
- Sysmon service running.
- Sysmon Event ID 1 visible.
- Atomic Red Team `T1059.001` executed.
- XML exported.
- XML normalized by pipeline.
- Native alert produced.
- Sigma-like alert produced.
- Alert indexed to `edr-alerts-native-*` when Elasticsearch is enabled.
- SOAR response planned.
- Response indexed to `edr-response-actions-*` when Elasticsearch is enabled.
- Final report generated.
- Kibana Discover/dashboard screenshot captured manually.
- Evidence bundle generated.

## Evidence bundle CLI

Create `scripts/demo/build_demo_evidence_bundle.py`.

Command:

```powershell
python scripts\demo\build_demo_evidence_bundle.py --output-dir reports\demo_evidence
```

Behavior:

- Create output directory if missing.
- Copy or generate:
  - `final_demo_report.json`
  - `final_demo_report.md`
  - `detection_coverage_report.json` if it exists
  - `detection_coverage_report.md` if it exists
  - demo evidence checklist markdown
  - command log template
  - `manifest.json`
- Do not require live Elasticsearch.
- Manifest should include `generated_at`, `included_files`, and `missing_optional_files`.

The command log template should be a markdown file operators can fill during a live demo. It should not claim commands were executed automatically.

## Sample artifacts

Add safe samples:

- `samples/sysmon/art_t1059_001_powershell_event.xml`
- `samples/sysmon/ml_suspicious_process_event.json`

Requirements:

- No malicious payloads.
- PowerShell sample must use a benign marker command.
- XML sample must be compatible with the existing Sysmon Event ID 1 normalizer.
- JSON sample must be a normalized ECS-like event compatible with the existing ML anomaly path.
- ML sample should produce an anomaly alert.

## README cross-links

Update `README.md` with:

```markdown
## VM Attack Demo and Dashboard Validation
```

Link:

- `docs/windows_vm_atomic_red_team_demo.md`
- `docs/atomic_attack_case_catalog.md`
- `docs/sysmon_event_export.md`
- `docs/kibana_dashboard_validation.md`
- `docs/demo_evidence_checklist.md`

Add commands:

```powershell
python scripts\demo\run_art_sysmon_demo_validation.py --input fixture --engine all --output summary
python scripts\demo\build_demo_evidence_bundle.py --output-dir reports\demo_evidence
```

## Tests

Create `tests/test_art_sysmon_demo_docs.py`.

Tests must not require:

- Windows VM.
- Atomic Red Team.
- Docker.
- Kafka.
- Elasticsearch.
- Kibana.

Cover:

- `docs/windows_vm_atomic_red_team_demo.md` exists and mentions Windows VM, Sysmon, Atomic Red Team, Event ID 1, and lab-only safety.
- `docs/atomic_attack_case_catalog.md` exists and mentions `T1059.001`, PowerShell, native rule ID, and Sigma-like rule ID.
- `docs/sysmon_event_export.md` exists and mentions XML export.
- `docs/kibana_dashboard_validation.md` exists and mentions `edr-normalized-events-*`, `edr-alerts-native-*`, and `edr-response-actions-*`.
- `docs/demo_evidence_checklist.md` exists and mentions VM, Sysmon, Atomic Red Team, alert, SOAR response, final report, and Kibana.
- Demo validation script fixture mode runs without live infrastructure.
- Evidence bundle script creates `manifest.json`.
- Sample XML exists and can be normalized by `normalize_sysmon_event_1()`.
- Sample ML JSON exists and can be scored by the existing ML anomaly path.
- Tests monkeypatch indexing helpers and do not require live infrastructure.

## Commands to run

Focused tests:

```powershell
python -m pytest tests\test_art_sysmon_demo_docs.py
```

Full regression:

```powershell
python -m pytest tests
```

Manual fixture validation:

```powershell
python scripts\demo\run_art_sysmon_demo_validation.py --input fixture --engine all --output summary
```

Manual Sysmon XML validation:

```powershell
python scripts\demo\run_art_sysmon_demo_validation.py --input xml --xml-path .\samples\sysmon\art_t1059_001_powershell_event.xml --engine all --output summary
```

Manual ML anomaly validation:

```powershell
python scripts\demo\run_art_sysmon_demo_validation.py --input json --event-path .\samples\sysmon\ml_suspicious_process_event.json --engine ml-anomaly --output summary
```

Manual evidence bundle:

```powershell
python scripts\demo\build_demo_evidence_bundle.py --output-dir reports\demo_evidence
```

## Acceptance criteria

- [ ] Atomic Red Team backed VM demo docs exist.
- [ ] Windows VM docs clearly state isolated lab-only usage.
- [ ] Docs warn not to run Atomic Red Team on production endpoints.
- [ ] Sysmon Event ID 1 export docs exist.
- [ ] Attack case catalog exists with safe lab-only cases.
- [ ] Attack case catalog documents primary `T1059.001` PowerShell validation through Atomic Red Team.
- [ ] Attack case catalog includes the safe manual fallback command.
- [ ] Kibana validation docs exist.
- [ ] Evidence checklist exists.
- [ ] Sample PowerShell Sysmon XML can be normalized.
- [ ] Sample ML suspicious JSON can produce an ML anomaly alert.
- [ ] Demo validation script fixture mode runs without live infrastructure.
- [ ] Demo validation script XML mode normalizes Sysmon Event ID 1 XML and runs native plus Sigma-like detection.
- [ ] Demo validation script JSON mode runs the existing ML anomaly path.
- [ ] Optional event, alert, and response indexing only happens when the matching write flag is provided.
- [ ] Evidence bundle script creates `manifest.json`.
- [ ] Evidence bundle includes final report files when present and records optional missing files.
- [ ] README links the VM attack demo and dashboard validation docs.
- [ ] Tests pass without live VM, Atomic Red Team, Kafka, Elasticsearch, or Kibana.
- [ ] Core detection, Kafka, SOAR, and ML semantics remain unchanged.

## Blocked by

- `.scratch/phase-1-foundation/PRD.md`
- `.scratch/phase-2-detection-engine-mvp/issues/06-native-detection-pipeline-with-alert-indexing.md`
- `.scratch/phase-3-live-telemetry-pipeline/issues/01-live-telemetry-to-detection-pipeline.md`
- `.scratch/phase-3-live-telemetry-pipeline/issues/02-sigma-like-detection-mvp.md`
- `.scratch/phase-4-kafka-pipeline-mvp/issues/01-kafka-normalized-event-detection-pipeline.md`
- `.scratch/phase-5-soar-response-mvp/issues/01-soar-dry-run-response-pipeline.md`
- `.scratch/phase-6-ml-anomaly-mvp/issues/01-process-anomaly-detection-mvp.md`
- `.scratch/phase-7-dashboard-report-mvp/issues/01-final-demo-report-and-operator-dashboard.md`

## Out-of-scope boundaries

- Do not add offensive payloads.
- Do not add malware download commands.
- Do not add real containment.
- Do not add new detection semantics.
- Do not change existing native rule semantics.
- Do not change existing Sigma-like rule semantics.
- Do not change existing Kafka message semantics.
- Do not change existing SOAR response semantics.
- Do not change existing ML scoring semantics.
- Do not require Atomic Red Team in automated tests.
- Do not require a Windows VM in automated tests.
- Do not require Elasticsearch, Kafka, Docker, or Kibana in automated tests.
- Do not require Kibana saved object import for tests.

## Comments
