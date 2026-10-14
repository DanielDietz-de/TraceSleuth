# Confidence model

## Purpose

TraceSleuth uses confidence to communicate how strongly available evidence supports a finding. Confidence is not severity, certainty, detector maturity, or probability of business impact.

A confidence value must never be decorative.

## Range

Normalized confidence uses:

```text
0..100
```

Higher numbers mean stronger support from the evidence available to TraceSleuth, after capture limitations and alternative explanations are considered.

## Confidence is not severity

Example:

- A directly observed single TCP reset may have very high confidence but low operational severity.
- A possible network loop may have potentially critical impact but low confidence if only generic duplicates exist.

Do not raise severity merely because confidence is high.

## Confidence is not certainty

TraceSleuth uses separate certainty classes:

```text
observed
strongly_inferred
probable
possible
informational
```

A directly decoded protocol field change can be `observed` even if it does not prove a higher-level root cause.

Example:

```text
LACP partner system ID changed: observed
Link aggregation instability is consistent with the sequence: strongly_inferred
MLAG peer-link failure caused it: possible unless directly proven
```

## Evidence contribution model

A detector or correlation rule should expose explainable contributions and penalties.

Illustrative example:

```text
+25 repeated-frame amplification across independent fingerprints
+20 broadcast rate acceleration
+20 STP instability immediately before amplification
+15 repeated ARP fingerprint recurrence
-15 probable fixed-factor SPAN duplication
-10 high packet truncation rate
---------------------------------------------
 55 final confidence
```

The values above are illustrative, not universal weights.

Every implemented detector/rule must document and test its own contribution model.

## Rules

1. Contributions must represent observable evidence or documented context.
2. Penalties must represent genuine uncertainty, conflicting evidence, or capture limitations.
3. The same underlying evidence must not be counted repeatedly through aliases.
4. Final values must be clamped to `0..100`.
5. A detector may define a confidence ceiling when evidence cannot prove more.
6. A detector may refuse to emit a finding when prerequisites are absent.
7. Capture quality can reduce confidence but should not weaken directly observed protocol facts that remain parseable.
8. Confidence changes require detector/rule version review and tests.

## Evidence independence

These may be one evidence family rather than independent signals:

```text
exact duplicate count
same-fingerprint recurrence count
same-fingerprint multiplicity
```

These are more independent:

```text
STP root change
broadcast acceleration
repeated ARP fingerprints
TCP retransmission spike
```

Correlation rules must avoid double counting correlated derivatives of the same packets.

## Capture-quality penalties

Potential limitations include:

- high truncation rate;
- no Ethernet headers;
- unsupported link type;
- parser failures;
- timestamp disorder;
- coarse timestamp resolution;
- capture loss;
- no PCAPNG interface metadata;
- no ingress-interface context;
- one-sided flow visibility;
- probable capture duplication;
- missing expected control-plane visibility;
- unsynchronized multi-capture clocks;
- capture starts after the fault;
- capture ends before recovery.

The relevance of a limitation is detector-specific.

Example:

- probable capture duplication should penalize duplicate-frame, loop, duplicate-forwarding, and retransmission conclusions;
- it should not necessarily penalize a directly decoded LACP partner-system-ID change.

## Confidence ceilings

A detector may impose a maximum confidence or certainty when evidence type is inherently limited.

Examples:

### Generic duplicate packets

Without amplification, independent fingerprints, control-plane correlation, or capture-duplication analysis, generic duplicates should not yield a high-confidence network-loop conclusion.

### MLAG symptoms

Weak indirect evidence alone must not create a critical high-confidence MLAG finding.

A specific peer-link failure should not exceed `possible` unless direct vendor-specific evidence or supplementary telemetry proves it.

### Unknown-unicast flooding

A single passive capture without switch MAC-table context may support only symptoms, not a definitive unknown-unicast diagnosis.

### One-way latency

Unsynchronized clocks cap timing confidence and precision.

## Recommended interpretation bands

These bands are presentation guidance, not a substitute for detector-specific rules:

```text
90-100  very strong support
75-89   strong support
55-74   moderate support
30-54   limited support
1-29    weak support
0       no support / suppressed / not applicable
```

The UI should still display certainty and limitations. A number alone is insufficient.

## Observed facts

Direct protocol facts should generally receive high confidence when:

- the packet is not truncated before the relevant fields;
- the parser is deterministic and validated;
- the field is directly present on the wire;
- there is no ambiguity about capture decoding.

Examples:

- STP root bridge ID in a valid BPDU;
- LACP partner system ID in a valid LACPDU;
- TCP zero advertised window in a decodable segment;
- DHCP message type;
- DNS response code.

The fact itself may be high-confidence even when its operational interpretation is uncertain.

## Statistical findings

Rate, latency, jitter, retransmission, or storm findings should expose:

- sample count;
- time window;
- baseline when used;
- threshold;
- measured value;
- timestamp resolution;
- capture quality;
- whether duplicate observations may inflate the metric.

Sparse samples should reduce confidence.

## Confidence and thresholds

Threshold crossing is not automatically high confidence.

Example:

```text
Observed 51 DHCP discovers; threshold is 50.
```

This proves the threshold was crossed. It does not prove a network fault, attack, or misconfiguration.

Confidence should reflect whether the threshold has validated diagnostic meaning in the capture context.

## Correlation confidence

Higher-order correlation should record:

- contributing finding IDs;
- evidence IDs;
- time relationships;
- entity joins;
- positive contributions;
- penalties;
- evidence-family deduplication;
- final confidence;
- certainty ceiling;
- rule ID and version.

## Suppression

Suppression must be visible and explainable.

Example:

```text
Duplicate-frame storm candidate suppressed because a stable factor-of-two capture-duplication pattern explains the observations with near-zero inter-copy delay and no amplification.
```

Do not silently discard contradictory evidence.

## Calibration

Confidence weights should be calibrated using:

- positive fixtures;
- negative fixtures;
- adversarial false-positive fixtures;
- boundary cases;
- real redistributable captures where licensed;
- regression history.

Do not invent scientific precision. A confidence of `96` must not imply a proven 96% statistical probability unless a validated probabilistic model actually supports that interpretation.

## Testing requirements

Confidence tests should cover:

- each contribution;
- each penalty;
- duplicate-evidence-family handling;
- minimum and maximum clamp;
- certainty ceilings;
- capture-quality degradation;
- threshold boundaries;
- stable deterministic output.

## Versioning

A material change to:

- weights;
- penalties;
- evidence dependencies;
- time windows;
- ceilings;
- threshold defaults;

requires detector or correlation-rule version review and changelog consideration.

## Current bootstrap status

TraceSleuth `0.1.0` defines this model but has not yet migrated all inherited detectors to it. Existing string confidence fields or direct heuristic conclusions must not be described as compliant until they emit the normalized evidence-backed contract.
