# SOAR Response MVP

## Purpose

Phase 5 adds a dry-run SOAR response planning pipeline. It consumes existing alert documents, selects a local playbook, builds planned response action records, and can optionally index those records into Elasticsearch.

This MVP is production-shaped, but intentionally safe: it plans actions only.

## Pipeline

```text
alert document
  -> playbook selection
  -> dry-run response record
  -> optional response index
```

The initial playbook is `response/soar/playbooks/powershell_execution.yml`. It matches native PowerShell alerts, Sigma-like PowerShell alerts, or equivalent alert documents with ATT&CK technique `T1059.001`.

## Commands

Fixture alert:

```powershell
python scripts\response\run_soar_response.py --input fixture-alert
```

Fixture alert summary:

```powershell
python scripts\response\run_soar_response.py --input fixture-alert --output summary
```

Alert JSON:

```powershell
python scripts\response\run_soar_response.py --input alert-json --alert-path .\alert.json
```

Elasticsearch alert query:

```powershell
python scripts\response\run_soar_response.py --input elasticsearch --elasticsearch-url http://localhost:9200 --alert-index-pattern edr-alerts-native-*
```

Response indexing:

```powershell
python scripts\response\run_soar_response.py --input fixture-alert --write-response --response-index-date 2026-06-17
```

## Response Index

Response action records are indexed to:

```text
edr-response-actions-YYYY.MM.DD
```

The Elasticsearch document ID is always `response.id`, which is deterministic for the same alert, playbook, and action IDs. It does not depend on wall-clock time.

## Dry-Run Safety Boundaries

This pipeline does not execute production containment or modify endpoints.

- No production containment
- Lab-only kill-process requires explicit Phase 10 protection flags outside this SOAR dry-run path
- No host isolation
- No network block
- No endpoint modification
- No external ticketing
- No TheHive yet

All playbook actions remain:

```json
{
  "status": "planned"
}
```

## Expected Response Record Shape

```json
{
  "response": {
    "id": "soar-response-...",
    "status": "planned",
    "mode": "dry-run",
    "created": "2026-06-17T10:00:00Z",
    "severity": "medium"
  },
  "alert": {
    "id": "det-t1059-001-powershell-process-start-...",
    "rule_id": "det.t1059_001.powershell_process_start",
    "technique_id": "T1059.001"
  },
  "playbook": {
    "id": "soar.playbook.powershell_execution",
    "name": "PowerShell Execution Response"
  },
  "actions": [
    {
      "id": "notify_analyst",
      "type": "notification",
      "status": "planned",
      "description": "Notify analyst about PowerShell execution alert."
    },
    {
      "id": "collect_process_context",
      "type": "collection",
      "status": "planned",
      "description": "Collect process, parent process, host, and user context from alert document."
    },
    {
      "id": "recommend_host_review",
      "type": "recommendation",
      "status": "planned",
      "description": "Recommend host review; no containment action is executed."
    }
  ]
}
```

## Related Final Docs

- [Architecture](architecture.md)
- [Final demo script](final_demo_script.md)
- [Final demo report MVP](final_demo_report_mvp.md)
