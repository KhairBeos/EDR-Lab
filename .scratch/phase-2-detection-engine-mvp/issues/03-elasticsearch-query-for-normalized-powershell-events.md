Status: done

# Elasticsearch query for normalized PowerShell events

## Parent

`.scratch/phase-2-detection-engine-mvp/PRD.md`

## Goal

Query Elasticsearch for candidate normalized Sysmon Event ID 1 ECS documents that may match the `T1059.001` PowerShell detection rule. This slice should add the first live query seam while keeping rule evaluation and alert generation deterministic.

## What to build

Create a small Elasticsearch query client for the detection engine. The client should query the local Elastic lab defaults, target the existing index pattern, filter to normalized Sysmon Process Create events, and return candidate event envelopes that the existing rule evaluator can process.

The query layer should narrow candidates but not replace local rule evaluation. Elasticsearch failures should produce predictable errors so smoke validation can distinguish "Elastic unavailable" from "no matching event".

## Files to create or edit

- Create or edit detection-layer Elasticsearch client.
- Create query construction tests that do not require a live Elasticsearch container.
- Create optional live smoke behavior that runs only when Elasticsearch is available.
- Edit detection engine wiring so query results can feed the PowerShell rule and alert builder.

## Commands to run

```powershell
python -m pytest tests
```

For optional local Elastic validation:

```powershell
docker compose up -d
python scripts\smoke\end_to_end_art_telemetry_smoke.py --post-logstash
curl.exe -s "http://localhost:9200/edr-raw-events-*/_search?q=art.technique_id:T1059.001&size=5&pretty"
```

If focused tests are added for this slice, also run:

```powershell
python -m pytest tests\test_detection_elasticsearch_query.py
```

## Acceptance criteria

- [ ] Elasticsearch URL, index pattern, timeout, and result size are configurable.
- [ ] Defaults align with the local Phase 1 Elastic lab.
- [ ] Query construction filters to `event.dataset = windows.sysmon_operational`.
- [ ] Query construction filters to `event.code = 1`.
- [ ] Query construction searches PowerShell evidence in supported process and parent process fields.
- [ ] Query results are converted into a stable internal event envelope or plain normalized event shape for rule evaluation.
- [ ] Raw `edr.raw` payloads are not treated as detection candidates.
- [ ] Elasticsearch connection errors and malformed responses produce predictable errors.
- [ ] Tests cover query construction without requiring Docker or Elasticsearch.
- [ ] Optional live validation can find smoke events when the local Elastic lab is running and fixture payloads have been posted.

## Blocked by

- `.scratch/phase-2-detection-engine-mvp/issues/01-native-powershell-detection-rule.md`
- `.scratch/phase-2-detection-engine-mvp/issues/02-alert-document-for-powershell-rule.md`

## Out-of-scope boundaries

- Do not implement production index templates or ILM.
- Do not add Elasticsearch authentication, TLS, or multi-node deployment.
- Do not implement Kafka streaming.
- Do not query new Sysmon Event IDs.
- Do not import SigmaHQ rules.
- Do not implement broad ATT&CK coverage.
- Do not require Elasticsearch for core unit tests.
