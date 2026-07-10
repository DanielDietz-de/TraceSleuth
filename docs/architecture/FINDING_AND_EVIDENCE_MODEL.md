# Finding and evidence model

## Status

This document defines the target TraceSleuth finding and evidence contract. The imported `models.TriageReport` remains in use during the migration and will be adapted incrementally. This document is not a claim that the normalized model is fully implemented yet.

## Goals

The model must make every significant conclusion answerable and auditable:

- what was observed;
- which packets support it;
- when it happened;
- which entities were affected;
- why the evidence indicates a problem;
- how confident TraceSleuth is;
- whether the conclusion is observed or inferred;
- what else could explain the evidence;
- which capture limitations reduce confidence;
- how an engineer can validate independently.

## Finding fields

A normalized `Finding` must be able to represent at least:

```text
id
detector_id
detector_version
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

## Severity

Recommended values:

```text
critical
high
medium
low
info
```

Severity describes potential operational impact, not certainty.

A low-confidence hypothesis must not be promoted to critical merely because the hypothetical cause would be severe.

## Certainty

Recommended values:

```text
observed
strongly_inferred
probable
possible
informational
```

### observed

The condition itself is directly present in the capture.

Example:

```text
The LACP partner system ID changed from A to B.
```

### strongly_inferred

Multiple independent signals make the conclusion highly consistent with the evidence, while the physical cause is not directly visible.

Example:

```text
The bundle experienced LACP partner instability.
```

### probable

The evidence supports the explanation more than alternatives but material ambiguity remains.

### possible

The evidence is compatible with the explanation but insufficient to make it the leading conclusion.

### informational

Context or observation that is not itself a fault diagnosis.

## Confidence

Confidence uses a documented numerical range:

```text
0..100
```

Confidence is not decorative. A detector or correlation rule must be able to explain contributions and penalties.

Example:

```text
+25 repeated frame amplification
+20 broadcast growth
+20 STP instability immediately before event
+15 repeated ARP fingerprint
-15 probable SPAN duplication
-10 truncated capture
--------------------------------
 55 final confidence
```

The exact values above are illustrative. Actual detector contributions must be engineered, tested, and documented in `docs/detectors/CONFIDENCE_MODEL.md` before use.

## Finding ID

A finding ID identifies one finding instance in one analysis.

It should be stable within a saved analysis and safe for API/UI references.

A finding ID is distinct from `detector_id`.

Example:

```text
finding ID: 01J... or UUID
Detector ID: l2.probable_loop
```

## Detector identity

Every normalized finding includes:

```text
detector_id
detector_version
```

Detector IDs should be stable machine identifiers such as:

```text
capture.quality.truncation
capture.duplication
l2.exact_duplicate_storm
l2.broadcast_storm
l2.probable_loop
stp.root_change
lacp.partner_instability
redundancy.probable_duplicate_forwarding
tcp.retransmission_anomaly
dns.timeout_retry
```

Final naming must be governed by a detector catalogue and compatibility policy.

## Time range

A finding should capture:

```text
first_seen
last_seen
duration
```

For an instantaneous observation, `first_seen` and `last_seen` may be equal.

Time precision must not exceed capture timestamp quality.

## Affected entities

Entities may include:

- MAC address;
- IP address;
- IPv6 address;
- VLAN;
- capture point;
- PCAPNG interface;
- flow;
- TCP conversation;
- bridge ID;
- LACP actor/partner system ID;
- LACP member;
- VRRP/HSRP group;
- DNS server;
- DHCP server;
- SIP/RTP stream;
- tunnel endpoint.

An entity should include a type and stable representation rather than relying only on display strings.

## Packet reference

A packet reference connects a finding to the actual evidence packet.

Recommended fields:

```text
capture_id
capture_name
packet_number
timestamp
interface_id
capture_point
reason
relevant_fields
```

`packet_number` must correspond consistently to the packet numbering used by TraceSleuth's packet viewer/export and validation guidance.

Packet references must not be fabricated.

## Evidence item

An evidence item may represent:

- packet field observation;
- protocol state transition;
- metric or rate;
- fingerprint multiplicity;
- before/after identity;
- timing relationship;
- cross-capture match;
- correlation contribution.

Recommended conceptual shape:

```text
id
type
summary
observed_value
expected_value
unit
first_seen
last_seen
packet_references
metrics
source_observation_ids
```

Evidence remains distinct from prose explanation.

## Metrics and thresholds

Findings should expose the values that triggered them.

Example:

```text
metric:
  name: broadcast_packets_per_second_peak
  value: 31872
  unit: pps

threshold:
  name: broadcast_storm_min_pps
  value: 5000
  source: default
```

Thresholds may come from:

- built-in default;
- configuration file;
- environment variable;
- CLI override;
- adaptive baseline algorithm.

The source of an override should be visible where useful.

## Alternative explanations

Every high-risk heuristic detector should list plausible alternatives considered.

Example for repeated frames:

```text
- multiple-source SPAN duplication
- packet broker replication
- TAP aggregation
- port-channel member mirroring
- capturing both sides of a link
- legitimate sender retransmission
- intentional application replication
```

Alternatives should not be generic boilerplate detached from the actual detector.

## Capture limitations

A finding carries limitations inherited from capture quality when relevant.

Examples:

```text
- no Ethernet headers available
- 18.4% of packets truncated
- timestamp resolution too coarse for recurrence analysis
- probable fixed-factor capture duplication
- no PCAPNG interface metadata
- only one side of the path observed
- STP control plane not observed
- capture started after fault onset
```

Limitations may:

- reduce confidence;
- lower certainty;
- suppress a detector entirely;
- alter the wording of conclusions.

## Wireshark filters

A finding may include one or more exact display filters when technically correct.

Filters must be validated against actual Wireshark field names before publication.

Do not invent display-filter syntax.

A filter entry should describe its purpose:

```text
purpose: Show relevant LACP frames for the affected actor/partner
filter: <validated filter>
```

## Recommended validation

Validation guidance tells an engineer how to independently inspect the conclusion.

Examples:

- review listed packet numbers;
- apply provided display filter;
- inspect recurrence interval;
- compare actor/partner system ID fields;
- inspect root bridge changes;
- verify capture point configuration;
- compare switch state/logs.

Validation should be actionable and evidence-specific.

## Recommended actions

Actions should distinguish investigation from remediation.

Safe investigation guidance can be direct. Remediation guidance must avoid destructive or topology-changing actions without appropriate warnings.

Example:

```text
Investigation:
- Verify which switch interfaces were included in the SPAN session.
- Check the current STP root and recent topology-change logs.

Remediation caution:
- Do not shut interfaces solely from this PCAP finding without validating topology and redundancy impact.
```

## Correlated findings

A finding may reference related findings by ID.

Examples:

```text
stp.root_change
l2.broadcast_storm
l2.exact_duplicate_storm
l2.probable_loop
```

The correlation record should show whether each related finding contributed positively, negatively, or informationally.

## Example normalized finding

Illustrative only:

```yaml
id: 0190-example
 detector_id: l2.probable_loop
 detector_version: 1.0.0
 title: Probable Layer-2 forwarding loop
 severity: critical
 confidence: 96
 certainty: strongly_inferred
 first_seen: 2026-07-11T10:03:12.400Z
 last_seen: 2026-07-11T10:03:20.700Z
 protocols:
   - ethernet
   - arp
 evidence:
   - type: frame_amplification
     summary: 287431 repeated Ethernet frames in 8.3 seconds
   - type: broadcast_growth
     summary: Broadcast rate increased from 42 pps to 31872 pps
 alternative_explanations:
   - Multiple-source SPAN duplication
   - Packet broker replication
 capture_limitations:
   - No PCAPNG interface metadata
```

The example exists to illustrate schema semantics. Real findings must use evidence from the actual capture.

## Compatibility with imported `TriageReport`

Migration should be incremental.

Recommended approach:

1. Add normalized finding/evidence types without deleting legacy fields.
2. Implement new capture-quality and L2 detectors only on the normalized model.
3. Add adapters that expose normalized findings through JSON/API/UI.
4. Migrate inherited detectors one family at a time.
5. Deprecate legacy fields explicitly.
6. Remove incompatible legacy fields only through a documented compatibility decision.

## Privacy

Evidence and packet payloads can contain sensitive information.

The finding model should avoid copying payload bytes by default. Packet references should point back to the capture. Evidence exports must make sensitivity explicit.

## Acceptance criteria

The normalized model is not considered complete until:

- major findings serialize deterministically;
- packet references resolve correctly;
- confidence and certainty are documented;
- capture limitations can influence findings;
- alternatives are supported structurally;
- JSON output is tested;
- UI can render the model;
- golden tests normalize dynamic values without hiding meaningful changes.