# Finding and evidence model

## Purpose

TraceSleuth findings must be technically defensible, traceable to original packets and honest about uncertainty. A finding is not merely a severity plus a text message.

The normalized model defined here is the contract toward which inherited protocol-specific report structures will migrate.

## Core epistemic rule

TraceSleuth distinguishes:

```text
observed
strongly_inferred
probable
possible
informational
```

A directly decoded LACP partner system-ID change may be `observed`. A conclusion that the behavior is consistent with aggregation instability may be `strongly_inferred`. A specific MLAG peer-link failure is usually only `possible` unless packet or supplementary telemetry directly proves it.

## Finding structure

Conceptual normalized finding:

```text
id
detector_id
detector_version
schema_version
title
summary
category
subcategory
severity
confidence
certainty
status
first_seen
last_seen
duration
affected_entities
protocols
vlans
capture_points
packet_references
evidence
metrics
thresholds
correlated_findings
alternative_explanations
capture_limitations
wireshark_filters
recommended_validation
recommended_actions
risk_warnings
references
tags
```

The exact Go types and JSON schema will be versioned when implemented.

## Stable IDs

### Finding ID

A finding ID identifies a concrete finding instance within an analysis. It should be stable for deterministic golden tests when the same input/configuration yields the same semantic finding.

Do not derive IDs from Go map order, random numbers or presentation text alone.

### Detector ID

Detector IDs are stable machine-readable identifiers, for example:

```text
capture.duplication.fixed_factor
l2.frame_duplicate_storm
l2.broadcast_storm
l2.probable_forwarding_loop
stp.root_change
lacp.partner_instability
redundancy.probable_multichassis_inconsistency
tcp.zero_window
dns.transaction_timeout
```

Names are examples until the detector catalogue formally establishes them.

### Detector version

Detector versions change when meaningful detection behavior changes.

## Severity

Normalized severity values:

```text
critical
high
medium
low
info
```

Severity represents potential operational impact, not confidence.

A low-confidence suspected critical-impact condition should not be mislabeled as confidently critical. Prefer a lower-certainty finding with explicit confidence and alternatives.

## Certainty

### `observed`

The finding states a directly decoded or measured fact.

Example:

> LACP partner system ID changed from A to B at packet 1289.

### `strongly_inferred`

Multiple independent observed signals support the conclusion and credible alternatives are materially weaker.

Example:

> Repeated frame amplification, broadcast acceleration and preceding STP instability are strongly consistent with a Layer-2 forwarding loop.

### `probable`

Evidence favors the conclusion but important alternatives remain.

### `possible`

Evidence is compatible with the conclusion but insufficient to prefer it strongly over alternatives.

### `informational`

Context or observation that is useful but not a fault diagnosis.

## Confidence

Confidence is an integer from `0` through `100`.

It is not decorative. It must derive from documented contributions and penalties.

A confidence explanation should be representable as:

```text
+25 repeated-frame amplification across independent fingerprints
+20 broadcast rate acceleration
+20 STP instability immediately before amplification
+15 repeated ARP fingerprint recurrence
-15 probable dual-source SPAN duplication
-10 high truncation rate
----------------------------------------
 55 final confidence
```

The exact contribution values are detector/correlation-policy decisions and require tests. Arbitrary arithmetic without calibration is prohibited.

## Status

Recommended lifecycle values:

```text
active
resolved_within_capture
suppressed
invalidated
```

The first implementation may use a smaller set but should not overload severity/certainty as lifecycle status.

## Time model

Every temporal finding should support:

```text
first_seen
last_seen
duration
```

Single-packet observations may have identical `first_seen` and `last_seen`.

Time precision must reflect actual capture timestamp precision and clock confidence.

## Affected entities

Entities should be structured, not only embedded in prose.

Examples:

```text
MAC address
IP address
IPv6 address
VLAN
bridge ID
LACP system ID
LACP port
VRRP/HSRP group
DNS server
flow
SSRC
capture interface
capture point
device identity inferred from LLDP/CDP
```

Each entity may carry a type, value, role and confidence.

## Packet references

A packet reference should include at least:

```text
capture_id
packet_number
timestamp
capture_interface_id (where available)
capture_point_label (where configured)
reason
relevant_fields
```

Example:

```json
{
  "capture_id": "cap-...",
  "packet_number": 1289,
  "timestamp": "2026-07-09T10:03:12.212345Z",
  "capture_interface_id": 1,
  "reason": "First BPDU showing the new root bridge ID",
  "relevant_fields": {
    "stp.root_id": "4096/00:11:22:33:44:55"
  }
}
```

Never fabricate packet references.

## Evidence items

Evidence is a typed collection.

Recommended evidence classes:

```text
packet
metric
state_transition
fingerprint_recurrence
rate_series
correlation
capture_quality
topology
configuration_context
```

### Packet evidence

Points to an exact source packet and explains why it matters.

### Metric evidence

Example:

```text
metric: broadcast_packets_per_second
baseline: 42 pps
peak: 31,872 pps
window: 8.3 seconds
```

### State-transition evidence

Example:

```text
protocol: LACP
entity: actor 80:00:aa:bb:cc:dd:ee:01 / port 7
field: synchronization
from: true
to: false
packet: 9921
```

### Fingerprint recurrence evidence

Records fingerprint policy/version, count, recurrence interval distribution, amplification behavior and representative packets.

### Capture-quality evidence

Records the limitation or quality signal that changed confidence.

## Metrics and thresholds

Findings must expose material thresholds and measured values.

Bad:

> Excessive topology changes detected.

Better:

```text
Observed: 14 root bridge changes
Window: 120 seconds
Configured threshold: 3 changes / 60 seconds
```

Threshold overrides used for an analysis must be preserved with the report.

## Alternative explanations

Every important heuristic finding must list plausible alternatives considered.

Example for duplicate frames:

```text
multiple-source SPAN
capturing both sides of a link
port-channel member mirroring
packet broker replication
ERSPAN duplication
TAP aggregation
NIC offloading
sender/application retransmission
intentional protocol replication
```

The detector should explain why alternatives were strengthened, weakened or left unresolved.

## Capture limitations

Examples:

```text
No Ethernet headers are present.
18.4% of packets are truncated at 96 bytes.
No PCAPNG interface metadata is available.
No STP BPDUs were observed.
Only one direction of the flow appears visible.
Capture clocks are not synchronized.
The capture started after the first observed fault symptoms.
```

A limitation may reduce confidence, block a detector or merely inform the user.

## Wireshark filters

Filters must be valid Wireshark display-filter expressions based on actually observable fields.

Examples must be tested against supported Wireshark syntax before being marked stable.

The finding may contain multiple filters for:

- all involved traffic;
- control-plane packets;
- exact flow;
- representative packet neighborhood;
- protocol state.

## Recommended validation

Validation guidance should be independent of TraceSleuth.

Example:

```text
1. Open the source capture in Wireshark.
2. Apply the supplied display filter.
3. Inspect packets 1289, 1310 and 1422.
4. Confirm the root bridge ID and topology-change flags.
5. Compare the event timestamps with the broadcast-rate acceleration window.
```

## Recommended actions

Actions should normally be investigative before prescriptive.

Good:

> Check the STP root and blocked-port state on switches participating in VLAN 120 during the finding time window.

Unsafe:

> Disable port Gi1/0/24 immediately.

A PCAP often cannot prove which physical interface should be shut down. Remediation guidance must include risk warnings where an incorrect action can cause outage.

## References

References may include:

- standards/RFCs/IEEE documents;
- vendor protocol documentation;
- Wireshark dissector/display-filter documentation;
- TraceSleuth detector documentation.

Do not invent standards citations or vendor behavior.

## Capture-level context

A report should include analysis-wide context in addition to finding fields:

```text
TraceSleuth version
detector versions
analysis time
input capture hashes
capture metadata
capture quality
capture limitations
detector configuration
threshold overrides
```

## Example: probable L2 loop finding

```text
Severity: critical
Certainty: strongly_inferred
Confidence: 96

Observed:
- 287,431 repeated Ethernet frames in 8.3 seconds.
- Broadcast rate increased from 42 pps to 31,872 pps.
- One ARP request fingerprint appeared 4,721 times.
- Median recurrence interval was 630 microseconds.
- An STP topology-change event occurred 112 ms before amplification began.

Alternatives considered:
- Multiple-source SPAN duplication.
- Packet-broker replication.
- Port-channel member mirroring.

Why less likely:
- Multiplicity increased over time instead of remaining at a fixed factor.
- Multiple independent broadcast fingerprints amplified.
- STP instability preceded amplification.

Limitations:
- No ingress-port metadata was available.

Validation:
- Inspect listed packet references and supplied Wireshark filters.
```

This is an illustrative schema example, not a claim that the detector is implemented in `0.1.0`.

## Example: MLAG symptom finding

Never state:

> MLAG peer-link is down.

unless direct evidence proves that state.

Prefer:

> Duplicate forwarding, LACP identity behavior and correlated path anomalies are consistent with a multi-chassis forwarding inconsistency. A peer-link problem, split-brain condition, VLAN inconsistency, member failure or capture duplication remain possible explanations.

## JSON stability

Once the normalized finding API is declared stable, field semantics are a compatibility contract. Golden tests should protect:

- detector IDs;
- severity;
- certainty;
- confidence;
- evidence schema;
- packet references;
- Wireshark filters.

Dynamic timestamps and unordered maps should be normalized only when necessary to prevent meaningless test failures.

## Privacy

Evidence exports and findings may reveal sensitive network data. Packet payloads can contain credentials, tokens, cookies, personal data, DNS names, file contents and application content.

The model must not automatically embed full payload data into every finding. Evidence references should minimize duplication while remaining traceable.

## Migration from `TriageReport`

The current `TriageReport` remains during migration.

Planned strategy:

1. add normalized finding/evidence types;
2. emit them from new priority detectors;
3. adapt UI/API/reporting to consume normalized findings;
4. provide compatibility mapping for legacy fields where practical;
5. migrate inherited detectors incrementally;
6. retire legacy fields only after equivalent tested behavior exists.
