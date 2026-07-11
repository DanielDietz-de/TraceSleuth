# ADR 0001: Deterministic-first diagnosis

- **Status:** Accepted
- **Date:** 2026-07-09
- **Decision owners:** TraceSleuth project

## Context

TraceSleuth analyzes packet captures and may produce findings that influence high-impact network troubleshooting decisions. An unsupported diagnosis can cause engineers to disable healthy interfaces, alter spanning-tree topology, change routing, or misattribute packet loss and outages.

Generative AI can produce fluent explanations without proving the underlying network condition. Packet-capture diagnosis therefore requires a stronger trust boundary than natural-language plausibility.

## Decision

Primary findings are produced by deterministic protocol parsing, explicit state machines, packet correlation, frame fingerprinting, time-series analysis, documented statistics, standards-based validation, and transparent heuristics.

An LLM or other generative model is never the primary authority deciding whether a network loop, STP failure, LACP problem, MLAG inconsistency, retransmission problem, packet-loss condition, or other network pathology exists.

Optional AI functionality may:

- explain existing deterministic findings;
- summarize multiple findings;
- produce investigation guidance from established evidence;
- translate technical results for different audiences.

Optional AI functionality may not fabricate packet observations or elevate an unsupported hypothesis into a finding.

TraceSleuth must function without cloud services, external APIs, Internet connectivity, telemetry, or AI models.

## Consequences

### Positive

- Findings can be independently validated.
- Offline operation remains possible.
- Detector behavior can be regression-tested.
- Confidence and limitations can be documented precisely.
- AI-provider availability cannot block core analysis.

### Negative

- Protocol and detector engineering requires more implementation effort.
- Some conditions remain uncertain because a PCAP lacks sufficient evidence.
- TraceSleuth must sometimes answer "insufficient evidence" instead of producing an impressive diagnosis.

## Rejected alternatives

### LLM-first packet diagnosis

Rejected because it cannot provide a reliable primary authority for binary protocol state, packet identity, timing, or causality.

### AI-assisted detector thresholds by default

Rejected for the initial architecture because opaque threshold adaptation would undermine deterministic regression testing and reproducibility. Future learned models would require explicit opt-in, versioning, offline operation, explainable input/output contracts, and independent deterministic safeguards.

## Validation

This decision is enforced by:

- detector metadata and versioning;
- packet references;
- structured evidence;
- certainty classes;
- documented confidence contributions and penalties;
- positive, negative and adversarial fixtures;
- golden tests;
- explicit capture limitations.
