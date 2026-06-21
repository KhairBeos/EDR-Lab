Status: done

# Sigma-like detection MVP

## Parent

`.scratch/phase-3-live-telemetry-pipeline/issues/01-live-telemetry-to-detection-pipeline.md`

## Goal

Implement a production-shaped Sigma-like detection MVP that can run alongside the existing native detection engine in the live telemetry pipeline.

This must not be smoke-only. It should be a second detection engine behind the live telemetry pipeline's engine selection.

## What to build

Add a minimal Sigma-like detection engine for `T1059.001` PowerShell process execution.

The implementation should:

- Add one Sigma-like YAML rule under `detection/rules/sigma_like/`.
- Load and validate Sigma-like YAML rule files from `detection/rules/sigma_like/`.
- Evaluate normalized ECS Sysmon Event ID 1 events in memory.
- Match current process PowerShell fields only.
- Build alert documents compatible with the existing alert shape.
- Include `detection.engine = sigma-like` and `detection.matched_fields`.
- Use deterministic alert IDs that cannot collide with native alert IDs.
- Reuse the existing alert indexer for optional alert indexing.
- Integrate Sigma-like evaluation into `scripts/pipeline/run_live_telemetry_pipeline.py`.

## Files to create or edit

Create:

- `detection/rules/sigma_like/t1059_001_powershell_process_start.yml`
- `detection/rules/sigma_like/__init__.py`
- `detection/rules/sigma_like/loader.py`
- `detection/rules/sigma_like/evaluator.py`
- `detection/rules/sigma_like/alerts.py` if needed, but prefer reusing existing alert shape and helper behavior where possible.
- `tests/test_sigma_like_detection.py`
- `tests/test_live_pipeline_sigma_integration.py`
- `docs/sigma_detection_mvp.md`

Edit:

- `scripts/pipeline/run_live_telemetry_pipeline.py`
- `docs/live_telemetry_pipeline_mvp.md` if a short cross-link is useful.

Do not edit unless a blocking bug is found:

- Existing native rule semantics.
- Existing normalizer.
- Existing alert indexer behavior.
- Existing smoke scripts.

## CLI integration

Add:

```text
--engine native|sigma-like|all
```

Default:

```text
native
```

Behavior:

- `--engine native`: current behavior unchanged.
- `--engine sigma-like`: run only Sigma-like rules.
- `--engine all`: run native and Sigma-like engines and return alerts from both.

## Rule requirements

The Sigma-like rule must detect only current process PowerShell execution.

Hard gate:

- `event.dataset = windows.sysmon_operational`
- `event.code = 1`

Match current process fields:

- `process.name` equals `powershell.exe`
- OR `process.executable` ends with `\powershell.exe`
- OR `process.command_line` contains `powershell.exe`

Other requirements:

- Matching must be case-insensitive.
- Parent-only PowerShell must not match.
- Raw payloads must not match.
- Missing optional fields must not crash.

## Sigma-like YAML metadata

The first rule should include:

- `id: sigma_like.t1059_001.powershell_process_start`
- `title` or `name: PowerShell Process Execution`
- `status: experimental`
- `description`
- `author` or project field if useful
- `logsource.product: windows`
- `logsource.service: sysmon`
- `logsource.category: process_creation`
- `detection.selection` fields for process name, executable, and command line
- `detection.condition: selection`
- `level` or `severity: medium`
- `confidence: high`
- `attack.technique_id: T1059.001`
- `attack.technique_name: PowerShell`
- `attack.tactic: [Execution]`

Do not implement full Sigma syntax. Support only the minimal subset required for this MVP.

## Alert requirements

Sigma-like alert documents must include:

- `alert.*`
- `rule.*`
- `attack.*`
- `event.*`
- `process.*`
- `host` and `user` if present
- `detection.engine = sigma-like`
- `detection.matched_fields`

Alert IDs must be deterministic and include engine/rule identity in the stable material so native and Sigma-like alerts do not collide.

## Commands to run

Focused tests:

```powershell
python -m pytest tests\test_sigma_like_detection.py
python -m pytest tests\test_live_pipeline_sigma_integration.py
```

Full regression:

```powershell
python -m pytest tests
```

Manual checks:

```powershell
python scripts\pipeline\run_live_telemetry_pipeline.py --input fixture --fixture-detectable-powershell --engine native
python scripts\pipeline\run_live_telemetry_pipeline.py --input fixture --fixture-detectable-powershell --engine sigma-like
python scripts\pipeline\run_live_telemetry_pipeline.py --input fixture --fixture-detectable-powershell --engine all
```

## Acceptance criteria

- [ ] Existing native behavior remains unchanged by default.
- [ ] A Sigma-like rule exists for `T1059.001` PowerShell process execution.
- [ ] Sigma-like loader validates required rule metadata.
- [ ] Sigma-like evaluator matches `process.name = powershell.exe`.
- [ ] Sigma-like evaluator matches `process.executable` ending with `\powershell.exe`.
- [ ] Sigma-like evaluator matches `process.command_line` containing `powershell.exe`.
- [ ] Sigma-like matching is case-insensitive.
- [ ] Raw payloads do not match.
- [ ] Non Event ID 1 events do not match.
- [ ] `cmd.exe` with parent PowerShell does not match.
- [ ] Missing optional process fields do not crash.
- [ ] `--engine sigma-like --fixture-detectable-powershell` produces one Sigma-like alert.
- [ ] `--engine all --fixture-detectable-powershell` produces two alerts: one native and one Sigma-like.
- [ ] Sigma-like alert includes `detection.engine = sigma-like`.
- [ ] Sigma-like alert can be indexed to `edr-alerts-native-YYYY.MM.DD`.
- [ ] Tests pass without live Elasticsearch.

## Blocked by

- `.scratch/phase-3-live-telemetry-pipeline/issues/01-live-telemetry-to-detection-pipeline.md`
- `.scratch/phase-2-detection-engine-mvp/issues/06-native-detection-pipeline-with-alert-indexing.md`

## Out-of-scope boundaries

- Do not add full SigmaHQ import.
- Do not add pySigma dependency.
- Do not add Kafka.
- Do not add ML.
- Do not add SOAR.
- Do not add TheHive.
- Do not create dashboards.
- Do not add new Sysmon Event IDs.
