# Demo Evidence Checklist

Use this checklist for the final teacher demo evidence bundle. Generated local artifacts are the deterministic baseline. Manual live-lab evidence is optional and should be added only when Elasticsearch/Kibana or the Windows VM is available.

Final report, alert, SOAR response, Sysmon, Atomic Red Team, Windows VM, and Kibana evidence should be reviewed when the matching deterministic or live-lab artifact is available.

## Generated Local Artifacts

- [ ] `final_demo_report.md` included.
- [ ] `final_demo_report.json` included.
- [ ] `detection_coverage_report.md` included.
- [ ] `detection_coverage_report.json` included.
- [ ] `case_matrix.md` included or available from `reports/demo_cases/case_matrix.md`.
- [ ] `case_matrix.json` included or available from `reports/demo_cases/case_matrix.json`.
- [ ] `dashboard_data.json` included or available from `reports/demo_cases/dashboard_data.json`.
- [ ] `attack_navigator/edr_attack_layer.json` included or available from `reports/attack_navigator/edr_attack_layer.json`.
- [ ] `attack_navigator/coverage_summary.md` included or available from `reports/attack_navigator/coverage_summary.md`.
- [ ] Alert evidence reviewed in the generated final report or Kibana.
- [ ] SOAR response evidence reviewed in the generated final report or Kibana.
- [ ] `manifest.json` reviewed.
- [ ] Evidence bundle generated.

## Manual Live-lab Evidence

- [ ] Kibana screenshots captured if Elasticsearch/Kibana is used.
- [ ] Optional VM Sysmon exported XML captured if doing a live Windows VM / Atomic Red Team demo.
- [ ] Optional protection execution screenshot captured only if isolated lab execution is explicitly intended.
- [ ] Windows VM booted if live VM evidence is used.
- [ ] Sysmon service running if live VM evidence is used.
- [ ] Sysmon Event ID 1/3/11/13 evidence visible if live VM evidence is used.
- [ ] Atomic Red Team `T1059.001` executed only in an isolated lab VM if live ART evidence is used.

Missing optional screenshots or VM artifacts do not mean the deterministic demo failed. They only mean the live-lab enhancement was skipped.

Evidence bundle command:

```powershell
python scripts\demo\build_demo_evidence_bundle.py --output-dir reports\demo_evidence
```
