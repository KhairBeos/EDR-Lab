# Protection Reports

Phase 10 protection records document guarded lab-only kill-process actions.

## Artifacts

Protection records can be indexed to:

```text
edr-protection-actions-*
```

Each record includes:

- `protection.action`
- `protection.mode`
- `protection.status`
- `target.pid`
- `target.process_name`
- `alert.id`
- `alert.rule_id`
- `safety.checks`

## Regenerate Demo Evidence

Dry-run:

```powershell
python scripts\response\run_protection_action.py --input fixture-alert --action kill-process --output summary
```

Index a protection record:

```powershell
python scripts\response\run_protection_action.py --input alert-json --alert-path .\alert.json --action kill-process --write-protection --elasticsearch-url http://localhost:9200
```

Execute mode is lab-only and requires both `--execute-protection` and `--lab-allow-execute`.
