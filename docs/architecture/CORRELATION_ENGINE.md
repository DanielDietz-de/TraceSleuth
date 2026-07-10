# Correlation engine

## Purpose

TraceSleuth should not behave as a collection of isolated alarm generators. The correlation engine combines independently supported observations and findings into higher-level diagnostic hypotheses while preserving evidence, uncertainty, alternatives, and capture limitations.

The correlation engine is deterministic and explainable. It is not an opaque machine-learning classifier and it does not allow a generative AI system to invent the underlying diagnosis.

## Core rule

Correlation may strengthen or weaken a conclusion only through explicit contributions.

A correlation result must be able to answer:

- which findings/observations contributed;
- which conditions were required;
- which conditions were optional;
- which capture limitations reduced confidence;
- which alternative explanations remain;
- how the final confidence/certainty was derived.

## Example: probable Layer-2 loop

Possible independent signals:

```text
exact frame fingerprint recurrence
normalized frame fingerprint recurrence
broadcast multiplication
multicast multiplication
repeated ARP/ND fingerprints
rate acceleration
periodic recurrence intervals
multiple copies without sender retransmission
STP root/topology changes before amplification
multiple capture interfaces seeing the same traffic
TTL recurrence where routed traffic is involved
capture duplication indicators
```

A rule may combine them conceptually:

```text
+ repeated frame amplification
+ accelerating broadcast growth
+ multiple independent ARP fingerprints repeated
+ STP instability immediately before event
- probable fixed-factor SPAN duplication
- significant packet truncation
= probable Layer-2 loop
```

A duplicate frame by itself is insufficient.

## Example: multi-chassis redundancy inconsistency

Possible signals:

```text
LACP partner identity changed
LACP synchronization lost
collecting/distributing state lost
same unicast flow duplicated across independently identified capture points
FHRP multiple-active event
path observations alternate unexpectedly
capture duplication is unlikely
```

A higher-level finding may be:

```text
Probable multi-chassis forwarding inconsistency
```

Possible causes may include:

- MLAG split-brain;
- peer-link problem;
- keepalive failure;
- VLAN consistency problem;
- orphan-port behavior;
- dual-active forwarding;
- member failure;
- LACP misconfiguration;
- STP interaction;
- capture duplication.

The engine must not select one cause as fact without sufficient evidence.

## Inputs

Correlation may consume:

- normalized observations;
- detector findings;
- capture-quality limitations;
- capture-point metadata;
- topology evidence;
- timing uncertainty;
- user-supplied context that is explicitly marked as external metadata.

## Rule metadata

A correlation rule should expose at least:

```text
id
version
name
description
input finding IDs
input observation types
required conditions
optional conditions
exclusion conditions
confidence contributions
confidence penalties
certainty ceiling
alternative explanations
references
```

## Contribution model

Each contribution has:

```text
signal ID
weight or contribution function
reason
source evidence references
```

Example:

```text
Signal: broadcast_growth_acceleration
Contribution: +20
Reason: Peak broadcast pps increased by >500x over baseline within 2 seconds
Evidence: metrics + packet references
```

A penalty has the same transparency:

```text
Signal: probable_capture_duplication
Penalty: -25
Reason: Exact duplicate factor remained fixed at 2 with near-zero inter-copy delay
Evidence: capture-duplication finding
```

The final numerical model must be documented and calibrated with positive, negative, and adversarial fixtures. The values shown here are examples only.

## No arbitrary additive confidence

Simple addition is not automatically valid. Some signals are dependent and must not be double-counted.

Example:

```text
ARP request repetition
broadcast growth caused entirely by those same ARP frames
```

Those are correlated signals, not necessarily independent evidence worth two full contributions.

The implementation must define signal groups, saturation, dependency rules, or other explicit techniques to avoid double-counting.

## Required conditions

Some correlations require prerequisites.

Example:

```text
probable_l2_loop:
  requires:
    - Ethernet visibility
    - minimum event duration or sufficient packet count
  requires_any:
    - frame amplification
    - broadcast/multicast amplification
  strengthens_with:
    - STP instability
    - repeated ARP/ND fingerprints
  penalized_by:
    - probable capture duplication
    - truncation
```

A rule must decline to produce a conclusion when prerequisites are not met.

## Exclusion conditions

Exclusion conditions suppress a conclusion when a known alternative is strongly supported.

Example:

```text
stable duplicate factor of exactly two
+ consistent near-zero inter-copy delay
+ identical ordering
+ no amplification
+ same behavior throughout capture
```

This strongly supports duplicate capture and may suppress a probable-loop conclusion unless independent loop evidence exists.

## Time correlation

Temporal proximity can strengthen a hypothesis but does not prove causality.

A rule may consider:

- event A occurred before event B;
- gap between events;
- whether the gap falls within a documented window;
- clock uncertainty;
- capture-point synchronization.

Example:

```text
STP root change at 10:03:12.100
Broadcast acceleration at 10:03:12.400
Gap: 300 ms
```

The result may say the events are temporally correlated. It must not claim causation solely from the 300 ms ordering.

## Multi-capture timing confidence

When captures come from different systems, the engine must know whether clocks are:

- synchronized and trusted;
- synchronized but with known error;
- adjusted using estimated offset;
- unsynchronized;
- unknown.

One-way latency and causal ordering across capture points must include timing confidence.

## Certainty ceiling

A rule should define the strongest certainty it can produce.

Example:

```text
MLAG symptom inference certainty ceiling: strongly_inferred
```

Unless direct vendor-specific protocol evidence or supplementary telemetry explicitly exposes the state, a generic PCAP-based MLAG rule must not produce an `observed` claim that a peer link is down.

## Correlated finding structure

A correlated finding should include:

```text
finding fields
source finding IDs
source evidence IDs
positive contributions
negative contributions
exclusions considered
final confidence
certainty
alternatives
capture limitations
```

## Rule versioning

Changing any of the following should normally change the rule/detector version:

- contribution weights;
- required conditions;
- exclusion conditions;
- timing windows;
- certainty ceiling;
- confidence penalties;
- evidence selection.

Golden tests should detect material output changes.

## Testing

Each correlation rule needs:

- positive fixtures;
- negative fixtures;
- false-positive fixtures;
- threshold boundary tests;
- capture-quality degradation cases;
- deterministic repeatability tests;
- golden output tests.

High-risk rules such as probable loops and MLAG symptoms require multiple adversarial false-positive cases.

## Current imported correlator

The baseline includes an underlay/overlay correlator that records BGP events, TCP retransmissions, and RTT spikes and produces `RootCauseChain` output.

That is a useful concept to retain. It does not yet provide the full target model of stable rule IDs, explicit contribution/penalty accounting, packet evidence references, capture limitations, or generalized multi-domain correlation.

## Implementation approach

1. Define normalized finding/evidence IDs.
2. Define a small correlation-rule interface.
3. Implement explainable contribution structures.
4. Start with one narrow rule after capture quality and evidence models exist.
5. Add golden tests.
6. Add suppression/penalty behavior from capture duplication.
7. Expand to L2 and redundancy only after adversarial fixtures exist.

Do not implement correlation by converting prose strings into conclusions.