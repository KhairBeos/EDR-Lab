# EDR Advanced Context

This project is an Endpoint Detection and Response platform built around test-driven detection.

## Core Terms

- Atomic Red Team: the primary source for adversary emulation events and detection validation.
- Detection rule: a Sigma, ML, or behavioral detector that must be validated against an Atomic Red Team test.
- Detection validation: the feedback loop that checks whether expected alerts fire after Atomic Red Team execution.
- Coverage matrix: the mapping between MITRE ATT&CK techniques and implemented detection coverage.
- Collection and normalization: the pipeline that converts endpoint telemetry into ECS-compatible events.
- Analysis and correlation: enrichment, scoring, case creation, and ATT&CK coverage updates.
- Response automation: SOAR and containment actions triggered by validated alerts.
