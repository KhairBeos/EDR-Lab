# Phase 1 Operator Runbook

This runbook is the happy path for operating the Phase 1 EDR Advanced foundation.

Phase 1 proves that the local Elastic Stack can receive ART-tagged telemetry, that the Windows VM endpoint can produce Sysmon Process Create telemetry, and that fixture-based Event ID 1 normalization can be verified end to end.

Use this as the primary entrypoint. Deeper references:

- `docs/windows_endpoint_setup.md`
- `docs/sysmon_baseline.md`
- `docs/art_integration.md`
- `docs/ecs_normalization.md`
- `docs/end_to_end_smoke_path.md`

## Architecture

```text
Developer Host
  Docker Compose
    Elasticsearch :9200
    Kibana        :5601
    Logstash HTTP :8080
        |
        v
  edr-raw-events-*

Windows VM
  Sysmon Phase 1 baseline
  PowerShell logging
  Atomic Red Team runner for T1059.001
        |
        v
  Sysmon Event ID 1 and PowerShell Operational logs

Fixture Smoke Path
  Sysmon Event ID 1 XML fixture
        |
        v
  ECS normalization
        |
        v
  raw payload + normalized payload
        |
        v
  optional Logstash HTTP post
```

## Scope

In scope:

- Start and verify the local Elastic lab.
- Prepare a Windows VM endpoint.
- Install and verify the Sysmon Phase 1 baseline.
- Run the ART runner dry-run.
- Optionally run the one approved VM-only ART execution.
- Run the fixture-based smoke path.
- Post smoke payloads to Logstash.
- Query Elasticsearch and verify in Kibana by `art.technique_id`.

Out of scope:

- Elastic Agent.
- Winlogbeat.
- Kafka implementation.
- Detection rules.
- Additional Sysmon event IDs.
- Production ingestion hardening.

## 1. Start Elastic Lab

Run on: **Developer Host**

Start Docker Desktop or Docker Engine first.

```powershell
docker compose up -d
```

Alternative if using the setup script:

```bash
scripts/setup/deploy_stack.sh
```

## 2. Verify Elasticsearch, Kibana, And Logstash

Run on: **Developer Host**

```powershell
docker compose ps
```

Expected services:

- `edr-elasticsearch`
- `edr-kibana`
- `edr-logstash`

Verify Elasticsearch:

```powershell
curl.exe -s "http://localhost:9200/_cluster/health?pretty"
```

Verify Kibana:

```powershell
curl.exe -s "http://localhost:5601/api/status"
```

Verify Logstash:

```powershell
curl.exe -s "http://localhost:9600/_node/pipelines?pretty"
```

## 3. Prepare Windows VM

Run on: **Windows VM**

Use a Windows 10/11 VM as the Phase 1 endpoint. A physical endpoint is not recommended for Phase 1.

Follow `docs/windows_endpoint_setup.md`, then confirm:

- [ ] VM snapshot exists.
- [ ] You are using a local administrator account.
- [ ] VM networking mode is selected: bridged, NAT, or host-only.
- [ ] The VM can reach the Developer Host Logstash port.

Set endpoint variables:

```powershell
$env:EDR_DOCKER_HOST_IP = "<developer-host-ip-reachable-from-vm>"
$env:EDR_LOGSTASH_URL = "http://$env:EDR_DOCKER_HOST_IP:8080"
$env:EDR_KIBANA_URL = "http://$env:EDR_DOCKER_HOST_IP:5601"
```

Check Logstash reachability:

```powershell
Test-NetConnection $env:EDR_DOCKER_HOST_IP -Port 8080
```

## 4. Install Sysmon Baseline

Run on: **Windows VM**

Acquire Sysmon manually from Microsoft Sysinternals. This repository does not download Sysmon binaries.

Install the Phase 1 baseline:

```powershell
.\Sysmon64.exe -accepteula -i .\collection\sysmon\sysmon_config.xml
```

Update an existing Sysmon install:

```powershell
.\Sysmon64.exe -c .\collection\sysmon\sysmon_config.xml
```

Verify service and channel:

```powershell
Get-Service Sysmon64
Get-WinEvent -ListLog "Microsoft-Windows-Sysmon/Operational"
```

Details live in `docs/sysmon_baseline.md`.

## 5. Verify Sysmon Event ID 1

Run on: **Windows VM**

Generate a safe Process Create event:

```powershell
cmd.exe /c whoami
```

Verify recent Sysmon Event ID 1 records:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 50 |
  Where-Object { $_.Id -eq 1 } |
  Select-Object -First 5 TimeCreated, Id, ProviderName, Message
```

## 6. Run ART Runner Dry-Run

Run on: **Developer Host** or **Windows VM**

Dry-run does not execute Atomic Red Team. It verifies the allowlisted `T1059.001` path and prints verification commands.

```powershell
python atomic-red-team\execution\runner.py --mode dry-run
```

Expected:

- Technique is `T1059.001`.
- Test is `PowerShell Command Execution`.
- No ART command is executed.
- Sysmon and PowerShell verification commands are printed.

Details live in `docs/art_integration.md`.

## 7. Optional VM-Only ART Execute

Run on: **Windows VM**

Only run this after taking a VM snapshot and manually installing/importing Invoke-AtomicRedTeam.

```powershell
python atomic-red-team\execution\runner.py --mode execute --confirm-vm
```

This runs exactly one approved command:

```powershell
Invoke-AtomicTest T1059.001 -TestGuids a538de64-1c74-46ed-aa60-b995ed302598
```

Do not run the full Atomic Red Team suite. Do not run broad T1059.001 execution.

Verify PowerShell in Sysmon:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 100 |
  Where-Object { $_.Id -eq 1 -and $_.Message -match "powershell.exe" } |
  Select-Object -First 5 TimeCreated, Id, Message
```

Verify PowerShell Operational logs:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -MaxEvents 100 |
  Select-Object -First 10 TimeCreated, Id, Message
```

## 8. Run Fixture-Based Smoke Path

Run on: **Developer Host**

This does not require a Windows VM.

Generate raw and normalized payloads from the existing Sysmon Event ID 1 fixture:

```powershell
python scripts\smoke\end_to_end_art_telemetry_smoke.py
```

Print payloads:

```powershell
python scripts\smoke\end_to_end_art_telemetry_smoke.py --print-payloads
```

Details live in `docs/end_to_end_smoke_path.md` and `docs/ecs_normalization.md`.

## 9. Post Smoke Events To Logstash

Run on: **Developer Host**

Requires the Elastic lab to be running.

```powershell
python scripts\smoke\end_to_end_art_telemetry_smoke.py --post-logstash
```

Expected:

- One raw payload is posted with `event.dataset = "edr.raw"`.
- One normalized payload is posted with `event.dataset = "windows.sysmon_operational"`.
- Both payloads include `art.technique_id = "T1059.001"`.

## 10. Query Elasticsearch By art.technique_id

Run on: **Developer Host**

```powershell
curl.exe -s "http://localhost:9200/edr-raw-events-*/_search?q=art.technique_id:T1059.001&size=5&pretty"
```

Expected:

- At least one event contains `art.technique_id = "T1059.001"`.
- Raw payload has `event.dataset = "edr.raw"`.
- Normalized payload has `event.dataset = "windows.sysmon_operational"`.
- Normalized payload includes `process.name`, `process.executable`, and `host.name`.

## 11. Verify In Kibana

Run on: **Developer Host**

Open:

```text
http://localhost:5601
```

Use this filter:

```text
art.technique_id : "T1059.001"
```

If Kibana asks for a data view, create one for:

```text
edr-raw-events-*
```

Expected:

- ART-tagged smoke events are visible.
- Raw and normalized payloads are distinguishable by `event.dataset`.

## Automated Validation

Run on: **Developer Host**

```powershell
python -m pytest tests validation\tests
```

Expected:

- Event ID 1 normalization tests pass.
- End-to-end fixture smoke path tests pass.
- Existing validation placeholders pass.

## Troubleshooting

| Symptom | Likely cause | Check |
| --- | --- | --- |
| Elasticsearch is unhealthy | Docker resources, startup delay, or container failure | `docker compose ps`; `docker logs edr-elasticsearch --tail 100` |
| Kibana is unreachable | Kibana still starting or Elasticsearch unavailable | `curl.exe -s "http://localhost:5601/api/status"` |
| Logstash is unreachable | Logstash not running or port `8080` unavailable | `docker compose ps`; `curl.exe -s "http://localhost:9600/_node/pipelines?pretty"` |
| Smoke POST fails | Elastic lab not running or wrong Logstash URL | `python scripts\smoke\end_to_end_art_telemetry_smoke.py --post-logstash --logstash-url http://localhost:8080` |
| No Elasticsearch results | Smoke events were not posted or wrong query/index | Query `edr-raw-events-*` by `art.technique_id:T1059.001` |
| Kibana shows no data | Missing data view or wrong filter | Create data view `edr-raw-events-*`; filter `art.technique_id : "T1059.001"` |
| Missing Sysmon Event ID 1 | Sysmon not installed, config not loaded, or channel disabled | `Get-Service Sysmon64`; `Get-WinEvent -ListLog "Microsoft-Windows-Sysmon/Operational"` |
| ART dry-run fails | Python path or selected technique config issue | `python atomic-red-team\execution\runner.py --mode dry-run` |
| ART execute fails | Not in VM, missing `--confirm-vm`, or Invoke-AtomicTest unavailable | `Get-Command Invoke-AtomicTest`; verify VM snapshot |
| Normalized payload malformed | Fixture or normalizer regression | `python -m pytest tests\test_sysmon_event_1_normalization.py` |

## Phase 1 Acceptance Criteria

Phase 1 is accepted when:

- [ ] Elastic lab starts successfully on the Developer Host.
- [ ] Elasticsearch, Kibana, and Logstash are reachable.
- [ ] Windows VM endpoint is prepared and can reach Logstash.
- [ ] Sysmon baseline is installed in the Windows VM.
- [ ] Sysmon Event ID 1 is observed after a safe process creation.
- [ ] ART runner dry-run succeeds for `T1059.001`.
- [ ] Fixture-based smoke path generates raw and normalized payloads.
- [ ] Smoke payloads can be posted to Logstash.
- [ ] Elasticsearch can query events by `art.technique_id:T1059.001`.
- [ ] Kibana shows raw ART-tagged smoke events by `art.technique_id`.

The key completion signal is: **raw ART-tagged smoke events are visible in Kibana by `art.technique_id`.**
