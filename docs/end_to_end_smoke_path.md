# End-to-End ART Telemetry Ingestion Smoke Path

This smoke path connects the Phase 1 pieces without requiring a live Windows VM.

It uses:

- `collection/sysmon/fixtures/sysmon_event_1_process_create.xml`
- `normalization/sysmon/process_create_normalizer.py`
- `atomic-red-team/execution/runner.py` as the source of the approved `T1059.001` execution path
- `docker-compose.yml` for optional Logstash/Elasticsearch/Kibana validation

## What The Smoke Path Proves

- A Sysmon Event ID 1 fixture can be loaded.
- The fixture can be normalized into ECS-compatible JSON.
- ART metadata for the Phase 1 PowerShell test can be attached.
- One raw payload and one normalized payload can be generated.
- The payloads are distinguishable by `event.dataset`.
- The payloads can optionally be sent to Logstash HTTP ingest.
- Kibana/Elasticsearch can filter ingested smoke events by `art.technique_id`.

For the Phase 2 detection-layer smoke workflow that turns normalized Event ID 1 PowerShell execution into an in-memory alert document, see `docs/phase_2_detection_engine_mvp.md`.

## Payload Contract

ART metadata attached to both payloads:

```json
{
  "art": {
    "technique_id": "T1059.001",
    "test_guid": "a538de64-1c74-46ed-aa60-b995ed302598",
    "test_name": "PowerShell Command Execution",
    "platform": "windows",
    "executor": "powershell"
  }
}
```

Raw payload marker:

```json
{
  "event": {
    "dataset": "edr.raw"
  }
}
```

Normalized payload markers:

```json
{
  "event": {
    "dataset": "windows.sysmon_operational"
  },
  "tags": ["ecs_normalized", "sysmon_event_1"]
}
```

## Generate Payloads Without Posting

This command loads the fixture, generates the raw and normalized payloads, and prints verification commands:

```powershell
python scripts\smoke\end_to_end_art_telemetry_smoke.py
```

Print both payloads:

```powershell
python scripts\smoke\end_to_end_art_telemetry_smoke.py --print-payloads
```

This mode does not require Docker, Logstash, Elasticsearch, Kibana, or a Windows VM.

## Optional Logstash Ingestion

Start the Elastic lab:

```powershell
docker compose up -d
```

Wait until services are healthy:

```powershell
docker compose ps
```

Post both payloads to Logstash:

```powershell
python scripts\smoke\end_to_end_art_telemetry_smoke.py --post-logstash
```

Use a custom Logstash URL:

```powershell
python scripts\smoke\end_to_end_art_telemetry_smoke.py --post-logstash --logstash-url http://localhost:8080
```

## Verification

Elasticsearch query:

```powershell
curl.exe -s "http://localhost:9200/edr-raw-events-*/_search?q=art.technique_id:T1059.001&size=5&pretty"
```

Kibana filter:

```text
art.technique_id : "T1059.001"
```

Expected search result:

- At least one raw event with `event.dataset = "edr.raw"`.
- At least one normalized event with `event.dataset = "windows.sysmon_operational"`.
- `art.technique_id = "T1059.001"` on both payloads.
- `event.original` preserved.
- `process.name`, `process.executable`, and `host.name` on the normalized payload.

## Manual Windows VM Checklist

This smoke path does not require a live VM, but it aligns with the manual Phase 1 endpoint flow:

- [ ] Start Elastic lab on the developer host.
- [ ] Confirm the Windows VM can reach Logstash.
- [ ] Run the ART runner dry-run:

```powershell
python atomic-red-team\execution\runner.py --mode dry-run
```

- [ ] If executing in the VM, run only the approved command:

```powershell
python atomic-red-team\execution\runner.py --mode execute --confirm-vm
```

- [ ] Verify Sysmon Event ID 1 for PowerShell:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 100 |
  Where-Object { $_.Id -eq 1 -and $_.Message -match "powershell.exe" } |
  Select-Object -First 5 TimeCreated, Id, Message
```

- [ ] Verify PowerShell Operational logs:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -MaxEvents 100 |
  Select-Object -First 10 TimeCreated, Id, Message
```

## Kafka Topic Intent

Kafka is not implemented in this smoke path. The intended topic architecture remains documented in `collection/kafka/topics.yml`:

- `sysmon-raw`
- `windows-events-raw`
- `art-executions`
- `normalized-events`
- `enriched-events`
- `alerts`

The smoke path uses direct Logstash HTTP ingest for Phase 1 simplicity.

## Out Of Scope

- Sysmon Event IDs other than 1.
- Elastic Agent.
- Winlogbeat.
- Kafka implementation.
- Detection rules.
- Metadata persistence framework.
- Production index templates or ILM.
