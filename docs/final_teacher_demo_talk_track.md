# Final Teacher Demo Talk Track

## Opening: Project Goal

This project demonstrates a local EDR learning pipeline with deterministic evidence. It validates selected ATT&CK techniques with normalized Sysmon telemetry, rule-based detections, ML-style anomaly scoring, behavioral correlation, dry-run response planning, and lab-only protection evidence. It does not claim production containment or full ATT&CK coverage.

The goal is to show an end-to-end EDR project: collect endpoint telemetry, normalize it, detect suspicious behavior, correlate related events, plan a safe response, and package the evidence for review.

## Architecture: Collection To Reporting

The architecture follows this path:

```text
collection -> normalization -> detection -> correlation -> response -> reporting
```

Sysmon XML or deterministic fixtures enter the collection layer. The normalization layer converts them into ECS-style events. Detection engines produce alert documents. Behavioral correlation links process, network, file, and registry evidence into sequence detections. Response planning stays dry-run. Reporting produces the final report, case matrix, dashboard data, ATT&CK Navigator layer, and evidence bundle.

## Telemetry

The demo uses selected Sysmon telemetry:

- Sysmon Event ID 1: process creation.
- Sysmon Event ID 3: network connection.
- Sysmon Event ID 11: file creation.
- Sysmon Event ID 13: registry value set.

These events are enough to tell the demo story for process execution, ingress transfer, registry persistence, file evidence, and behavioral sequences.

## Detection Engines

Native detection is the direct Python rule path. It proves that normalized events can trigger project-owned detection rules.

Sigma-like detection shows a second rule style without claiming full Sigma compiler support.

ML anomaly detection is deterministic ML-style scoring. It is useful for demonstrating feature extraction and anomaly scoring, but it is not trained production ML.

Behavioral correlation links multiple events into higher-level behavior, such as process/network/file or process/registry sequences. This is how the project moves beyond single-event matching while still staying deterministic and testable.

## ATT&CK Coverage

The current demo coverage focuses on selected techniques:

- `T1059.001`: PowerShell execution.
- `T1105`: ingress tool transfer.
- `T1547.001`: registry run key persistence.
- `T1218-lite`: constrained LOLBin proxy execution demo coverage.

The ATT&CK Navigator layer visualizes these covered techniques. The score is a communication score based on local evidence sources, not a production maturity score.

## Case Matrix

The case matrix explains what the detector should and should not catch:

- TP means a malicious or attack-like case was expected to alert and did alert.
- TN means a benign case was expected to stay quiet and stayed quiet.
- FP means a benign case alerted.
- FN means an attack-like or limitation case did not alert.

Do not hide FP/FN. The false positive and false negative are useful because they show honest evaluation boundaries and future tuning work.

## Response

SOAR is dry-run only. It creates planned response records so the workflow can be reviewed without taking destructive action.

Protection is lab-only kill-process. The default mode is safe and does not kill a process. Real execution requires explicit lab flags and should only be used in an isolated VM.

## Dashboard/Evidence

If Kibana is available, show normalized events, alerts, response actions, and protection action records in the relevant index patterns.

The Navigator layer shows the ATT&CK technique coverage in a visual format.

The evidence bundle packages generated reports and artifacts so the teacher can review the final state without rerunning every command.

## Limitations And Future Work

This is not full ATT&CK coverage. It is selected coverage for a learning-focused EDR project.

The demo rules are deterministic. That makes the project testable and repeatable, but it is not the same as production detection tuning.

`T1218-lite` is constrained. It demonstrates deterministic LOLBin coverage, not complete LOLBin analytics.

There is no production containment. SOAR is dry-run and protection is lab-only.

There are no real credential dumping or malware payloads. The project uses safe fixtures, Atomic Red Team style evidence, and controlled lab-only workflows.
