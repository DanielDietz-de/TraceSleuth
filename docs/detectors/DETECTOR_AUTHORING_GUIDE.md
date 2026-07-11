# Detector authoring guide

## Purpose

This guide defines how new TraceSleuth detectors should be designed, implemented, validated, documented, and presented.

A detector is not complete because it can emit an alert. TraceSleuth detectors must be explicit about what they observe, what they infer, how capture quality affects them, which alternatives can explain the same traffic, and which packets support the conclusion.

## 1. Start with an observable question

Good detector question:

> Did the observed LACP partner system ID change for the same actor/port context during this capture?

Weak detector question:

> Is MLAG broken?

The first is directly observable. The second may require multiple indirect signals, vendor-specific control traffic, topology, or supplementary telemetry.

Define:

- protocol/domain;
- observable fields;
- capture prerequisites;
- state required;
- what is fact versus inference;
- what alternative explanations exist;
- what the detector cannot know.

## 2. Choose a stable detector ID

Target naming pattern:

```text
<domain>.<specific_condition>
```

Examples:

```text
capture.duplication.fixed_factor
l2.frame_duplicate_storm
l2.broadcast_storm
l2.probable_forwarding_loop
stp.root_change
lacp.partner_instability
tcp.zero_window
dns.transaction_timeout_retry
```

IDs are machine-readable compatibility identifiers. Do not derive them from display text.

Before declaring an ID stable:

- search the catalogue;
- check for duplicate IDs;
- decide whether the condition is one detector or several independent facts;
- avoid embedding thresholds or versions in the ID.

## 3. Define detector metadata

Target metadata should include:

```text
ID
Name
Version
Category
Description
RequiredObservations
RequiredCaptureCapabilities
StateRequirements
DefaultThresholds
StandardsReferences
Maturity
```

A detector version changes when behavior materially changes, including:

- algorithm;
- thresholds;
- confidence contributions;
- protocol parsing that changes evidence;
- false-positive/false-negative behavior;
- finding semantics.

## 4. Declare capture prerequisites

Examples:

```text
requires Ethernet headers
requires VLAN visibility
requires LACP frames
requires PCAPNG interface IDs for cross-interface conclusions
requires bidirectional TCP visibility
requires synchronized or bounded-offset clocks for one-way latency
```

When a prerequisite is missing, decide explicitly whether to:

- skip;
- emit an informational limitation;
- reduce confidence;
- cap certainty.

Never silently assume missing context.

## 5. Parse once, observe many times

Preferred architecture:

```text
packet decoder
      |
      v
normalized protocol observation
      |
      +--> detector A
      +--> detector B
      +--> topology evidence
      +--> correlation
```

Do not duplicate custom binary parsing across detectors.

A normalized observation retains source context such as:

```text
capture_id
packet_number
timestamp
interface_id
capture_point
link_type
source/destination MAC
VLAN context
source/destination IP
ports
flow ID
protocol fields
fingerprint where relevant
```

Avoid copying entire payloads into every observation.

## 6. Design bounded state

For every map, cache, queue, or time series, answer:

- what key cardinality is possible?
- what is the eviction policy?
- what happens on a 100-million-packet capture?
- can state be summarized?
- does finalization release state?
- is the state detector-local?
- is concurrent access safe?

Examples of bounded strategies:

- LRU caches;
- fixed-duration windows;
- top-N heavy hitters;
- count-min/sketch only when collision semantics are acceptable and documented;
- sampled representative packet references;
- capped evidence lists with total counts preserved.

Do not use unbounded maps by default.

## 7. Separate observations from conclusions

Example LACP sequence:

### Observed

```text
packet 501: partner system ID A
packet 721: partner system ID B
packet 726: synchronization bit cleared
packet 735: collecting/distributing cleared
```

### Possible conclusion

```text
LACP partner instability
```

### Possible higher-order inference

```text
Behavior is consistent with a redundancy or multi-chassis identity inconsistency.
```

### Not justified without more evidence

```text
MLAG peer-link is down.
```

Keep these levels separate in code and output.

## 8. Define evidence before implementation

A major finding should specify what evidence it will expose.

Packet evidence:

```text
capture_id
packet_number
timestamp
interface_id
reason
relevant_fields
```

Metric evidence:

```text
name
value
unit
window
baseline
threshold
sample_count
```

State transition evidence:

```text
entity
field
from
to
timestamp
packet_reference
```

Correlation evidence:

```text
contributing finding IDs
entity joins
time relationship
positive contributions
penalties
```

If a finding cannot identify supporting evidence, reconsider whether it should be emitted.

## 9. Define severity independently from confidence

Severity answers:

> How serious could this condition be operationally?

Confidence answers:

> How strongly does the available evidence support this finding?

Certainty answers:

> Is this directly observed, strongly inferred, probable, possible, or informational?

Do not merge these concepts.

## 10. Design confidence contributions

Document:

- positive evidence contributions;
- penalties;
- evidence families to prevent double counting;
- confidence ceiling;
- certainty ceiling;
- capture-quality interactions.

Illustrative loop correlation:

```text
+ repeated-frame amplification
+ broadcast acceleration
+ repeated independent ARP fingerprints
+ STP instability before amplification
- fixed-factor SPAN duplication signature
- high truncation rate
```

Exact values require fixture calibration and tests.

See `CONFIDENCE_MODEL.md`.

## 11. Enumerate alternatives

For every heuristic detector, write alternatives before coding.

### Duplicate frames / loop

- multiple SPAN sources;
- both sides of a link captured;
- port-channel member mirroring;
- packet broker;
- ERSPAN;
- TAP aggregation;
- sender retransmission;
- intentional replication;
- redundancy mechanisms.

### LACP / MLAG symptoms

- valid failover;
- device reboot;
- member link flap;
- timeout-mode difference;
- two unrelated links captured together;
- capture duplication;
- ordinary configuration change.

### TCP retransmission

- duplicate capture;
- out-of-order packets;
- timestamp disorder;
- offloading;
- one-sided visibility;
- capture starting mid-flow.

Each relevant alternative should become a negative or adversarial fixture.

## 12. Define thresholds transparently

For every threshold:

- name;
- unit;
- default;
- rationale;
- minimum/maximum if configurable;
- time window;
- interaction with capture duration;
- boundary tests.

Required tests:

```text
threshold - 1
threshold
threshold + 1
```

Crossing a threshold proves only that the threshold was crossed. It does not automatically prove a fault or malicious intent.

## 13. Build positive fixtures

A positive fixture should be minimal and explainable.

Record:

- source/license;
- generator;
- packet count;
- expected detector ID;
- expected packet references;
- expected severity/certainty/confidence range when stable;
- forbidden unrelated findings.

Prefer synthetic captures.

## 14. Build negative fixtures

A negative fixture should resemble realistic healthy behavior.

Examples:

- stable LACP periodic exchange;
- stable STP root;
- ordinary ARP resolution;
- valid DHCP allocation;
- healthy TCP handshake;
- normal multicast service discovery.

## 15. Build adversarial false-positive fixtures

Required for high-risk heuristics.

The fixture should deliberately look superficially similar to the fault while having a known alternative explanation.

A loop detector that has never seen a dual-source SPAN fixture is not ready to be called stable.

## 16. Test malformed input

Custom parser tests should include:

- truncated headers;
- short TLVs;
- invalid lengths;
- unexpected subtype/version;
- oversized lengths;
- duplicate TLVs where applicable;
- unknown fields;
- malformed-but-recoverable packets.

Expected behavior:

- no routine panic;
- bounded allocation;
- explicit parse error/metric;
- no fabricated observation.

## 17. Add fuzzing for binary trust boundaries

High-priority custom parsers:

- LACP;
- STP/RSTP/MSTP;
- LLDP/CDP TLVs;
- DHCP options;
- IPv6 ND options;
- tunnel headers;
- custom capture handling.

Persist minimized crashes as regression fixtures.

## 18. Provide Wireshark validation

Stable findings should provide valid display filters where applicable.

Requirements:

- use real Wireshark field names;
- test filter syntax;
- do not invent vendor fields;
- include packet numbers and time windows as complementary evidence.

A filter may target:

- all protocol packets;
- affected entities;
- exact flow;
- control-plane state;
- representative evidence packets.

## 19. Add finding presentation

A mature finding should show:

1. What happened.
2. Why TraceSleuth thinks it happened.
3. Observed evidence.
4. Packet references.
5. Timeline.
6. Alternative explanations.
7. Wireshark validation.
8. Next investigation steps.
9. Safe remediation guidance where justified.
10. Limitations.

Do not prescribe destructive network changes when the PCAP cannot identify the exact physical fault location.

## 20. Add JSON/API output

The same normalized finding should drive CLI, JSON, API, UI, and reports.

Do not let presentation layers independently derive new unsupported diagnoses.

Golden tests protect stable fields.

## 21. Add catalogue entry

Every detector entry should include:

```text
ID
Display name
Version
Category
Maturity
Purpose
Protocols
Required capture context
Algorithm summary
Thresholds
Confidence model
False-positive risks
False-negative risks
Wireshark filters
Positive fixture
Negative fixture
False-positive fixture(s)
Standards references
Current implementation status
```

## 22. Add changelog entry

Record:

- new detector;
- behavior change;
- threshold change;
- confidence change;
- fixed false positive/negative;
- migration impact.

## 23. Review checklist

Before calling a detector stable:

- [ ] Unique stable ID.
- [ ] Detector version.
- [ ] Parser/observations validated.
- [ ] Required capabilities declared.
- [ ] Bounded state reviewed.
- [ ] Positive fixture.
- [ ] Negative fixture.
- [ ] Adversarial fixture where relevant.
- [ ] Boundary tests.
- [ ] Malformed tests.
- [ ] Fuzzing where binary parsing is custom/high risk.
- [ ] Evidence packet references.
- [ ] Metrics/thresholds exposed.
- [ ] Confidence contributions documented/tested.
- [ ] Certainty semantics correct.
- [ ] Alternatives documented.
- [ ] Capture limitations applied.
- [ ] Wireshark validation tested.
- [ ] JSON output.
- [ ] UI presentation.
- [ ] Catalogue entry.
- [ ] Changelog entry.
- [ ] Race/determinism review.
- [ ] Performance/state growth measured where relevant.

## Current bootstrap status

The inherited detector framework does not yet satisfy this complete contract. New TraceSleuth detector work should target the normalized architecture, while inherited detectors are migrated incrementally with compatibility layers where necessary.
