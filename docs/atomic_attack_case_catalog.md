# Atomic Attack Case Catalog

This catalog defines safe lab-only validation cases for the Phase 8 VM demo. It does not add new detection semantics.

## Primary Case: T1059.001 PowerShell

- Technique: `T1059.001` PowerShell.
- Tool: Atomic Red Team.
- Goal: trigger native and Sigma-like PowerShell process-start detection.

Expected telemetry:

- Sysmon Event ID 1.
- `process.name = powershell.exe`.
- `process.command_line` contains an Atomic Red Team marker or demo marker.

Expected detections:

- Native `rule.id = det.t1059_001.powershell_process_start`.
- Sigma-like `rule.id = sigma_like.t1059_001.powershell_process_start`.

Fallback safe manual command:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Write-Output EDR_DEMO_T1059_001"
```

The fallback manual command is not the primary attack simulator. Primary validation should use Atomic Red Team when available.

## ML Demo Case

Use `samples/sysmon/ml_suspicious_process_event.json`, a crafted normalized ECS-like Sysmon Event ID 1 event. It includes encoded-command and download-keyword indicators for deterministic ML-style anomaly scoring.

Safety boundaries:

- No malicious payloads.
- No malware downloads.
- No network command is executed by the JSON sample.

Expected result:

- `detection.engine = ml-anomaly`.
- One ML anomaly alert from the existing ML scoring path.

Command:

```powershell
python scripts\demo\run_art_sysmon_demo_validation.py --input json --event-path .\samples\sysmon\ml_suspicious_process_event.json --engine ml-anomaly --output summary
```

## Kafka Demo Case

Use the current fixture-detectable PowerShell path:

```powershell
python scripts\kafka\consume_and_detect.py --dry-run-fixture --engine all
```

Expected result:

- `processed_message_count = 1`.
- `alert_count = 2`.

This validates the Kafka contract without requiring a live broker.

## SOAR Demo Case

Use a fixture alert or an alert produced by the Phase 8 validation CLI.

Expected result:

- One dry-run response record for a single matching alert.
- Planned actions only.
- No real containment.

Command:

```powershell
python scripts\response\run_soar_response.py --input fixture-alert --output summary
```

