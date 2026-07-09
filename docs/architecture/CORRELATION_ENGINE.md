# Correlation engine

## Purpose

TraceSleuth must not behave as a collection of isolated alarm generators. The correlation engine combines independent observations and findings into higher-order diagnoses while preserving the complete reasoning path.

Correlation is evidence composition, not magic scoring.

## Core rules

1. Never invent observations.
2. Preserve every contributing finding/evidence item.
3. Distinguish temporal correlation from causal proof.
4. Explain positive contributions and penalties.
5. Prefer independent signals over repeated variants of the same signal.
6. Avoid double-counting evidence derived from the same packets or metric.
7. Capture-quality limitations can reduce or block conclusions.
8. Weak indirect evidence alone must not produce critical MLAG or loop conclusions.
9. Correlation rules are versioned, documented and tested.

## Correlation inputs

Potential inputs include:

- normalized protocol observations;
- capture-quality findings;
- duplicate-frame findings;
- traffic-rate findings;
- STP state changes;
- LACP state changes;
- FHRP transitions;
- ARP/ND mapping churn;
- TCP retransmission/handshake/window findings;
- DNS/DHCP/service failures;
- multi-capture disappearance/duplication/modification evidence;
- topology evidence;
- user-supplied capture-point metadata.

## Correlation dimensions

Signals may correlate by:

```text
time window
capture ID
capture point
VLAN
MAC address
IP address
flow
protocol entity
bridge ID
LACP actor/partner ID
FHRP group
packet fingerprint
physical/logical topology relationship
```

Temporal proximity alone is insufficient when unrelated traffic dominates a large capture.

## Contribution model

A correlation rule should expose a contribution trace such as:

```text
+25 repeated frame amplification
+20 broadcast acceleration
+20 STP instability within 250 ms before amplification
+15 independent repeated ARP fingerprint
-15 probable fixed-factor capture duplication
-10 18% packet truncation
---------------------------------------------
 55 final confidence
```

These values are illustrative. Final weights require implementation, fixture calibration and documentation.

## Independence and double counting

The engine must identify evidence families.

Example: these may all derive from the same packets and should not automatically count as three independent signals:

```text
exact duplicate count
same-fingerprint recurrence rate
same-fingerprint packet multiplicity
```

Conversely, these are more independent:

```text
STP root change
broadcast rate acceleration
ARP fingerprint recurrence
TCP retransmission spike
```

A correlation rule should declare dependencies and evidence families.

## Temporal windows

Rules define meaningful temporal relationships.

Example:

```text
STP instability precedes broadcast amplification by <= 2 seconds
```

This is stronger than merely observing both somewhere in a 30-minute capture.

Rules should record:

- relationship direction;
- maximum gap;
- overlapping duration requirements;
- clock uncertainty for multi-capture inputs.

## Capture-quality penalties

Examples:

### Probable capture duplication

May reduce confidence in:

- duplicate-frame storm;
- probable L2 loop;
- duplicate forwarding;
- MLAG symptom inference;
- TCP retransmission.

It should not necessarily reduce confidence in:

- directly decoded LACP partner system-ID change;
- directly decoded STP root ID;
- directly decoded DHCP NAK.

### Truncation

May reduce confidence in parsers requiring fields beyond snap length.

### Missing Ethernet headers

Blocks or limits L2 loop, MAC, VLAN, STP, LACP and LLDP/CDP conclusions.

### Unsynchronized capture clocks

Reduces cross-capture latency precision and may weaken ordering-based correlation.

## Example correlation: probable Layer-2 loop

Potential strong signals:

- exact frame recurrence across multiple independent fingerprints;
- normalized frame recurrence where expected mutable fields change;
- broadcast/multicast amplification;
- rate acceleration rather than stable high baseline;
- repeated ARP/ND fingerprints;
- stable/periodic recurrence intervals;
- STP topology/root changes before amplification;
- multiple interfaces seeing the same evolving traffic;
- lack of corresponding sender retransmission evidence.

Potential penalties/alternatives:

- stable factor-of-two duplication;
- near-zero inter-copy delay;
- identical order throughout capture;
- dual-source SPAN;
- packet broker;
- port-channel member mirroring;
- ERSPAN duplication;
- TAP aggregation;
- capture from both sides of a link;
- severe timestamp disorder.

A critical strongly-inferred loop finding should generally require multiple independent positive signals and no stronger capture-duplication explanation.

## Example correlation: multi-chassis redundancy inconsistency

Potential inputs:

```text
observed LACP partner ID change
+ synchronization loss
+ collecting/distributing loss
+ duplicate unicast forwarding across identified capture interfaces
+ FHRP multiple-active behavior
+ topology changes
```

Possible output:

```text
probable multi-chassis forwarding inconsistency
```

Not:

```text
MLAG peer-link is down
```

unless direct evidence proves that state.

## Example correlation: network fault cascade

```text
10:03:12.100  STP root change
10:03:12.212  topology-change BPDU
10:03:12.400  broadcast rate accelerates
10:03:12.811  duplicate frame multiplicity rises
10:03:13.020  TCP retransmission rate spikes
10:03:13.140  DNS timeout rate rises
```

The engine may state that the timing is consistent with a network event preceding transport/service degradation. It must not claim causal proof unless evidence supports it.

## Rule metadata

Conceptual correlation-rule metadata:

```text
id
version
title
description
required_inputs
optional_inputs
blocking_limitations
time_window
entity_join_keys
evidence_families
positive_contributions
penalties
certainty_ceiling
severity_policy
references
```

## Certainty ceilings

Some rules should never exceed a certainty class without direct evidence.

Examples:

- generic duplicate packets alone: at most `possible` for a network loop;
- LACP state transition alone: at most `possible` for MLAG fault;
- directly decoded partner ID change: `observed` for the change itself;
- multi-signal redundancy symptoms without vendor control protocol: generally no stronger than `probable` for a specific MLAG cause.

## Correlated finding structure

A higher-order finding should preserve:

- IDs of contributing findings;
- IDs of contributing evidence items;
- time alignment;
- entity joins;
- contribution/penalty trace;
- alternatives considered;
- capture limitations;
- correlation rule ID/version.

## Rule testing

Every correlation rule requires:

- positive fixture;
- negative fixture;
- false-positive/adversarial fixture;
- threshold boundary tests;
- time-window boundary tests;
- capture-quality penalty tests;
- duplicate-evidence-family tests;
- deterministic output tests.

High-risk loop/MLAG rules require multiple adversarial false-positive scenarios.

## Determinism

Correlation results must not depend on map iteration order or nondeterministic goroutine completion.

Inputs should be normalized and sorted by stable keys where output order matters.

## Multi-capture uncertainty

Correlation across capture points must carry clock metadata:

```text
synchronized
known_offset
estimated_offset
unknown
```

One-way delay findings must include uncertainty. Do not report microsecond-level certainty from unsynchronized clocks.

## Suppression and confidence reduction

A capture-duplication finding should be consumable by downstream correlation.

Possible behavior:

- suppress duplicate-frame fault finding when fixed-factor duplication fully explains observations;
- reduce confidence when duplication explains some but not all amplification;
- leave direct control-plane findings unchanged;
- explain the decision in the finding.

Suppression must be visible and auditable, not silent.

## Versioning

Correlation rules are versioned independently. Changing contribution values, time windows, evidence dependencies or certainty ceilings changes rule behavior and should change its version.

## Migration

The inherited code already has `correlator.go` and root-cause-chain concepts. TraceSleuth should reuse useful concepts but replace opaque string confidence and protocol-specific direct mutation with normalized, versioned correlation rules.

## Current status

This document defines the target correlation contract. The complete engine is not claimed as implemented in TraceSleuth `0.1.0`.
