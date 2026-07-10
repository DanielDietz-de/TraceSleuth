# Analysis pipeline

## Purpose

This document defines the intended packet-analysis flow for TraceSleuth. The target pipeline separates capture trust, decoding, normalized observations, protocol state, detector conclusions, evidence, and correlation so that findings remain explainable and false-positive controls can be applied consistently.

## Pipeline overview

```text
1. Input admission
2. Capture identity and format validation
3. Capture-quality preflight
4. Streaming decode
5. Normalized observation emission
6. Protocol state machines
7. Detector evaluation
8. Evidence construction
9. Finding construction
10. Correlation
11. Topology/timeline derivation
12. Output and evidence export
```

Each stage has a distinct responsibility.

---

## 1. Input admission

Inputs are untrusted.

Admission is responsible for:

- maximum request/file size enforcement before expensive parsing;
- internal random capture ID generation;
- safe internal filenames;
- display-name sanitization;
- safe temporary directory creation;
- file magic validation;
- supported-format rejection;
- cleanup on failure.

The original client filename is metadata only. It must never be trusted as a filesystem path.

---

## 2. Capture identity and format validation

Create immutable capture metadata including:

```text
capture_id
original_display_name
internal_path
sha256
format
file_size
analysis_version
```

Capture hashes identify the exact input analyzed and should appear in reports.

The current imported reader already recognizes PCAP and PCAPNG magic values. That behavior should be retained and extended rather than duplicated.

---

## 3. Capture-quality preflight

Preflight runs before high-level network pathology conclusions.

It should determine, where available:

```text
format
link-layer type
capture duration
packet count
byte count
first timestamp
last timestamp
timestamp resolution
capture interfaces
PCAPNG interface metadata
snap length
truncated packet rate
reported drops
timestamp monotonicity
timestamp jumps
duplicate-frame prevalence
suspicious capture duplication
capture gaps
unsupported encapsulations
parser failures
malformed packets
file truncation
L2 visibility
control-plane observability
```

The result is structured and reusable by detectors.

Example:

```text
Capture quality: LIMITED

Reasons:
- 18.4% of packets are truncated at 96 bytes.
- No PCAPNG interface metadata is available.
- STP conclusions are limited because no BPDUs were observed.
- Duplicate-frame diagnosis may be affected by probable dual-source SPAN capture.
```

The absence of a protocol is not automatically proof that the protocol is not operating. Capture point and duration matter.

---

## 4. Streaming decode

Packets should be decoded in streaming order where practical.

Requirements:

- no mandatory retention of every full packet object;
- packet number assigned consistently;
- capture timestamp retained;
- original capture length and wire length retained;
- interface ID retained for PCAPNG where present;
- link-layer type retained;
- malformed packet counters visible;
- recover safely at appropriate trust boundaries;
- routine malformed input must not use panic as normal control flow.

The imported processor already streams through `ReadPacketData`. The target architecture should build on that property.

---

## 5. Normalized observation emission

Parsers emit facts, not conclusions.

Examples:

```text
EthernetFrameObservation
VLANObservation
ARPObservation
NDObservation
STPObservation
LACPObservation
LLDPObservation
CDPObservation
FHRPObservation
TCPObservation
DNSObservation
DHCPObservation
ICMPObservation
RoutingObservation
TunnelObservation
CaptureInterfaceObservation
```

Common source context should include, where applicable:

```text
capture_id
packet_number
timestamp
pcapng_interface_id
capture_point
link_layer_type
source_mac
destination_mac
vlan_id
outer_vlan
inner_vlan
source_ip
destination_ip
protocol
source_port
destination_port
flow_id
relevant protocol fields
frame fingerprint
```

Do not copy full payloads into every observation.

---

## 6. Protocol state machines

State machines aggregate observations when the protocol itself has state.

Examples:

- TCP connection state;
- LACP actor/partner/member state;
- STP root and topology transitions;
- FHRP master/active transitions;
- DHCP allocation sequence;
- DNS request/response correlation;
- RTP sequence progression.

State must be:

- bounded where possible;
- explicit about expiration;
- deterministic;
- unit-testable;
- resettable;
- safe under the chosen concurrency model.

---

## 7. Detector evaluation

Detectors consume observations, state, and capture capabilities.

A detector should declare:

- ID;
- name;
- version;
- category;
- description;
- required observations;
- required capture capabilities;
- state requirements;
- default thresholds;
- standards references;
- known confidence limitations.

A detector may decline to run when prerequisites are not met.

Example:

```text
Detector: probable_l2_loop
Requirement: Ethernet visibility
Optional evidence: STP observations, PCAPNG interfaces
Limitation: probable capture duplication
Result: run with confidence penalty, or suppress if evidence is insufficient
```

---

## 8. Evidence construction

Evidence is a structured record of why a finding exists.

Evidence may include:

- packet references;
- field values;
- before/after state;
- rate series;
- recurrence intervals;
- duplicate factors;
- thresholds;
- correlated events;
- capture-quality limitations.

Evidence must never contain fabricated packet examples.

A packet reference should include:

```text
capture_id
packet_number
timestamp
interface_id
reason
relevant_fields
```

Where practical, findings should support evidence mini-PCAP export.

---

## 9. Finding construction

A finding turns evidence into an explicit conclusion.

At minimum, major findings should include:

- title and summary;
- severity;
- numerical confidence;
- certainty classification;
- time range;
- affected entities;
- evidence;
- alternatives;
- capture limitations;
- Wireshark filters;
- validation guidance;
- recommended next investigation steps.

Conclusions must not exceed evidence.

Example:

```text
Observed: LACP partner system ID changed.
Strong inference: The bundle experienced partner instability.
Possible cause: MLAG identity inconsistency.
Not justified without more evidence: MLAG peer link is down.
```

---

## 10. Correlation

Correlation combines independently supported observations/findings through documented rules.

Example:

```text
repeated frame amplification
+ broadcast growth
+ repeated ARP fingerprint
+ STP instability immediately before event
- probable SPAN duplication
- truncated capture
= probable L2 loop with explainable confidence
```

Correlation must show contribution and penalty rationale.

No arbitrary opaque score addition is allowed.

---

## 11. Topology and timeline derivation

Timeline is built from ordered evidence-backed events such as:

```text
10:03:12.100  STP root change
10:03:12.212  Topology-change BPDU
10:03:12.400  Broadcast rate begins rising
10:03:12.811  Duplicate-frame count accelerates
10:03:13.020  TCP retransmission rate spikes
10:03:13.140  DNS timeout rate rises
```

Temporal ordering alone does not prove causation.

Topology edges are classified as:

- direct adjacency;
- inferred relationship;
- communication relationship.

Every inferred edge should carry evidence and confidence.

---

## 12. Output and evidence export

Consumers include:

- human CLI;
- JSON;
- API;
- web UI;
- HTML reports;
- evidence PCAP export;
- time-window export;
- flow export.

Reports should include:

- TraceSleuth version;
- detector versions;
- analysis time;
- capture hashes;
- capture metadata and quality;
- thresholds and overrides;
- findings and evidence;
- limitations.

Secrets from application configuration must never be included.

---

## Current imported behavior versus target pipeline

| Area | Imported baseline | Target |
|---|---|---|
| Input | extension check + later magic parse | bounded request + internal filename + immediate magic validation |
| Capture quality | no first-class preflight | mandatory preflight before diagnosis |
| Decode | streaming `ReadPacketData` | preserve and extend |
| Observations | detector-specific packet interpretation | normalized reusable observations |
| Detector metadata | name only | stable ID/version/prerequisites/thresholds |
| Evidence | protocol-specific report fields | structured packet evidence model |
| Findings | large aggregate `TriageReport` | normalized finding schema + compatibility adapters |
| Correlation | limited underlay/overlay correlator | explainable multi-domain contribution model |
| Multi-capture | hardcoded LAN/WAN comparison | arbitrary capture points + timing confidence |
| Cancellation | job state only | context cancellation through pipeline |

## Execution invariants

The target engine should maintain these invariants:

1. Capture trust runs before high-level fault inference.
2. A finding can identify which detector version produced it.
3. Significant findings can trace to real evidence.
4. Confidence penalties from capture limitations are explainable.
5. A detector cannot silently run without required capture capabilities.
6. No unbounded worker creation per packet.
7. Cancellation reaches the packet-processing loop.
8. Results remain deterministic where packet ordering and configuration are identical.
9. The engine can operate without Internet access.
10. Parser errors and skipped packets are visible metrics, not silently lost.
