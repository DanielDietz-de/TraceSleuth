# ADR 0002: Incremental migration over a one-shot rewrite

- **Status:** Accepted
- **Date:** 2026-07-09

## Context

The imported SD-WAN Triage baseline already contains substantial Go and React functionality: PCAP/PCAPNG processing, CLI and web interfaces, packet inspection, reporting, transport and service analysis, protocol detectors, timeline views, and streaming comparison concepts.

TraceSleuth requires a materially different architecture built around capture trust, normalized observations, evidence-backed findings, detector metadata, explicit certainty, correlation, topology reasoning, and generalized multi-capture analysis.

A complete rewrite would create a long period in which existing functionality disappears, tests lose their value, and correctness regressions become difficult to localize.

## Decision

TraceSleuth uses an incremental migration strategy.

The inherited runtime remains operational while new architecture is introduced beside it. Priority sequence:

1. establish provenance, versioning and CI;
2. secure inherited critical defaults;
3. introduce capture identity and quality models;
4. introduce normalized packet references and observations;
5. introduce the finding/evidence contract;
6. migrate priority detectors;
7. migrate API, UI and reports;
8. remove legacy structures only after equivalent tested behavior exists.

Major phases should leave the repository buildable and testable.

## Consequences

### Positive

- Existing useful functionality remains available during migration.
- Regression tests keep value.
- Behavior changes are reviewable in smaller units.
- Security fixes do not need to wait for complete architecture replacement.

### Negative

- Temporary compatibility layers will exist.
- Some legacy and target abstractions coexist during pre-1.0 development.
- Migration requires disciplined deprecation and cleanup.

## Rejected alternatives

### Full rewrite before further releases

Rejected because it creates excessive correctness, schedule and regression risk.

### Preserve upstream architecture indefinitely

Rejected because the inherited monolithic report and packet-analyzer interfaces do not satisfy TraceSleuth's evidence, certainty, capture-trust and detector-lifecycle requirements.

## Guardrails

- Do not create empty placeholder packages merely to resemble the target tree.
- Do not remove useful inherited functionality without a documented reason.
- Do not maintain easy upstream rebasing at the expense of TraceSleuth architecture quality.
- Do not remove legacy structures until their replacement is implemented and tested.
