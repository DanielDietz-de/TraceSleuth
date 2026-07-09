# ADR 0004: Capture trust precedes fault diagnosis

- **Status:** Accepted
- **Date:** 2026-07-09

## Context

Packet captures can be incomplete, duplicated, truncated, timestamp-disordered, filtered, sampled, asymmetrical, or missing relevant link-layer and control-plane traffic. These conditions can create false retransmissions, apparent loops, impossible latency, missing packets, and misleading topology conclusions.

The inherited baseline validates PCAP/PCAPNG magic and decodes packets, but it does not provide a first-class preflight result that downstream detectors consume.

## Decision

TraceSleuth performs capture-integrity and capability analysis before network-fault diagnosis.

The preflight stage should determine, where available:

- capture format;
- link-layer type;
- packet/byte counts;
- first/last timestamps and duration;
- timestamp resolution and monotonicity;
- PCAPNG interface metadata;
- snap length and truncation rate;
- reported drops;
- capture gaps;
- malformed/parser failures;
- unsupported encapsulations;
- file truncation;
- Ethernet/L2 availability;
- control-plane observability;
- suspicious fixed-factor or source-dependent capture duplication.

Detectors declare the capture capabilities they require. Missing prerequisites can block a detector, reduce confidence, or add explicit limitations depending on the detector contract.

## Consequences

### Positive

- Loop and retransmission false positives can be reduced.
- Findings communicate why certainty is limited.
- Multi-capture timing can respect clock uncertainty.
- Users see whether a capture is suitable for a requested diagnosis.

### Negative

- Capture analysis adds an initial processing stage.
- Some historical findings will receive lower confidence or be withheld.
- Interface metadata varies significantly between capture formats and capture tools.

## Guardrails

- Absence of observed BPDUs is not automatically proof that spanning tree is absent or broken.
- Duplicate packets alone are not proof of a network loop.
- Unsynchronized clocks must not produce microsecond-precision one-way latency claims.
- A single capture without switch-state visibility cannot prove the complete MAC table or unknown-unicast condition.
- Capture limitations are visible, never silently discarded.
