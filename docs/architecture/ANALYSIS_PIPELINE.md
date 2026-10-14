# Analysis pipeline

## Purpose

The TraceSleuth analysis pipeline converts untrusted packet captures into reproducible, evidence-backed findings. The ordering is intentional: capture trust is established before fault diagnosis, protocol facts are normalized before detectors interpret them, and higher-order conclusions are correlated from explicit lower-level evidence.

## Pipeline overview

```text
1. Intake and identity
2. Capture format validation
3. Capture metadata extraction
4. Capture quality and capability assessment
5. Packet decoding
6. Normalized observation emission
7. Detector processing
8. Detector finalization
9. Evidence normalization
10. Finding generation
11. Cross-detector correlation
12. Topology reasoning
13. Confidence/certainty finalization
14. Reporting, API and UI presentation
15. Evidence export
```

No later stage may invent facts that are absent from earlier packet/capture observations.

## 1. Intake and identity

Input may arrive through CLI, web upload, server API or future supported integration.

Required behavior:

- generate an internal random capture ID;
- preserve the original filename only as untrusted display metadata;
- never use the original filename directly as a filesystem path;
- compute SHA-256 for the original input;
- enforce configured byte limits while streaming;
- record ingestion time and source mode;
- store original data according to explicit retention policy.

## 2. Capture format validation

Before packet decoding:

- validate magic values;
- distinguish PCAP and PCAPNG;
- reject unsupported formats with a useful error;
- detect obvious truncation/corruption;
- bound lengths before allocation;
- count parser failures rather than silently dropping them.

The inherited `pcapgo`-based PCAP/PCAPNG reader is a useful starting point.

## 3. Capture metadata extraction

Capture metadata should include where available:

```text
capture_id
filename_display
sha256
format
file_size
link_types
snap_length
packet_count
byte_count
first_timestamp
last_timestamp
duration
timestamp_resolution
interface_count
pcapng_interfaces
reported_drops
capture_point_metadata
```

Metadata extraction should be streaming or single-pass where possible.

## 4. Capture quality and capability assessment

This stage runs before network-fault detectors.

### Quality signals

- truncated-packet count and rate;
- malformed record count;
- parser failure count;
- file truncation;
- timestamp monotonicity;
- timestamp jumps;
- suspicious capture gaps;
- reported drops from metadata;
- suspicious exact-duplicate prevalence;
- likely fixed-factor capture duplication;
- unsupported encapsulation/link types.

### Capability signals

Examples:

```text
has_ethernet_headers
has_vlan_visibility
has_pcapng_interface_ids
has_ingress_interface_context
stp_observable
lacp_observable
lldp_observable
cdp_observable
arp_observable
ipv6_nd_observable
bidirectional_tcp_likely
multi_capture_clock_quality
```

A detector declares required capabilities. If a prerequisite is missing, the detector should skip, emit informational limitation metadata, or reduce confidence according to documented policy.

### Capture quality result

Recommended levels:

```text
GOOD
DEGRADED
LIMITED
UNSUITABLE
```

The level is not decorative; it is accompanied by structured reasons and metrics.

## 5. Packet decoding

Packet decoding must:

- isolate malformed input safely;
- avoid panic for routine malformed packets;
- recover at trust boundaries where appropriate;
- retain packet index/number and timestamp;
- retain capture interface ID where available;
- avoid unnecessary payload copies;
- expose parsing failures as metrics.

## 6. Normalized observation emission

Protocol parsing produces facts. Detectors should not independently reimplement the same binary parsing.

Example observations:

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

Common source context should support:

```text
capture_id
packet_number
timestamp
capture_interface_id
capture_point_label
link_type
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
frame_fingerprint
```

Not every observation carries every field.

## 7. Detector processing

Each detector consumes declared observations/capabilities.

Requirements:

- stable detector ID;
- detector version;
- explicit configuration/default thresholds;
- bounded state where practical;
- deterministic registration;
- duplicate-ID rejection;
- no hidden cloud dependency;
- testable initialization and reset;
- cancellation support;
- explicit prerequisites and limitations.

A detector may emit lower-level facts, evidence items or preliminary findings depending on its contract.

## 8. Detector finalization

Time-series and state-machine detectors often cannot conclude until capture end.

Examples:

- out-of-order percentage;
- state-transition rate;
- root bridge duration distribution;
- duplicate amplification slope;
- DNS timeout rate;
- DHCP allocation completion rate;
- RTP sequence loss;
- capture-wide duplication factor.

Finalization must be deterministic and should release detector state afterward.

## 9. Evidence normalization

Evidence records should include enough context for independent validation.

Typical packet evidence:

```text
capture_id
packet_number
timestamp
interface_id
reason
relevant_fields
wireshark_filter
```

Metric evidence may include:

```text
metric_name
value
unit
window
baseline
threshold
sample_count
```

Transition evidence may include:

```text
entity
from_state
to_state
timestamp
packet_reference
```

## 10. Finding generation

A finding is not merely a string and severity.

It should contain:

- stable ID;
- detector ID/version;
- title/summary;
- category/subcategory;
- severity;
- numerical confidence;
- certainty class;
- time range;
- affected entities;
- packet references;
- evidence;
- metrics and thresholds;
- alternatives;
- capture limitations;
- Wireshark filters;
- validation steps;
- recommended next investigation actions;
- risk warnings;
- references and tags.

## 11. Cross-detector correlation

Correlation can raise or lower confidence when independent findings overlap in time, entities, VLANs, capture points or packet fingerprints.

Example:

```text
STP root change
+ topology-change storm
+ broadcast acceleration
+ repeated ARP fingerprints
+ duplicate-frame amplification
- probable fixed-factor SPAN duplication
- severe truncation
= probable Layer-2 forwarding loop with explained score
```

Correlation does not overwrite lower-level findings. The user must be able to inspect each contributing item.

## 12. Topology reasoning

Topology may use:

- LLDP/CDP;
- STP bridge IDs;
- LACP actor/partner identities;
- ARP/ND/FHRP;
- capture interface metadata;
- user-supplied capture-point metadata;
- communication relationships.

Edges must be labeled as direct, inferred or communication-only.

## 13. Confidence and certainty finalization

Certainty values:

```text
observed
strongly_inferred
probable
possible
informational
```

Confidence uses `0..100` and must be tied to documented contributions/penalties.

Examples of penalties:

- probable capture duplication;
- high truncation rate;
- missing Ethernet headers;
- missing PCAPNG interface metadata;
- one-sided capture;
- missing expected control-plane visibility;
- unsynchronized multi-capture clocks.

## 14. Presentation

The same normalized findings power:

- CLI human output;
- JSON/JSONL;
- versioned API;
- web findings view;
- timeline;
- topology;
- reports;
- evidence export.

Presentation layers must not independently reinterpret raw packets into new unsupported diagnoses.

## 15. Evidence export

Where implemented, a finding may expose:

- exact packet list;
- evidence-only mini-PCAP;
- time-window PCAP;
- flow-specific PCAP;
- Wireshark display filters.

Export must preserve original packet bytes and timestamps. It must not fabricate or normalize packet payloads silently.

## 16. Multi-capture pipeline

For multiple captures:

```text
independent capture trust per input
        |
        v
capture-point metadata + clock model
        |
        v
cross-capture fingerprint correlation
        |
        +--> disappearance
        +--> duplication
        +--> modification
        +--> NAT
        +--> TTL/DSCP changes
        +--> encapsulation changes
        +--> latency with uncertainty
        +--> duplicate forwarding paths
```

One-way latency precision must never exceed clock-quality evidence.

## 17. Error handling

Routine malformed packets should result in bounded errors/metrics, not application panic.

Fatal analysis errors must include:

- capture ID;
- processing stage;
- safe error summary;
- whether partial findings are valid;
- cleanup status.

Secrets and sensitive payload content must not be logged casually.

## 18. Resource controls

The target pipeline requires:

- maximum upload bytes;
- streaming byte enforcement;
- maximum concurrent analyses;
- per-analysis timeout;
- context cancellation;
- bounded detector state;
- bounded WebSocket/subscription counts;
- temporary-storage quotas;
- retention cleanup;
- optional expensive-detector disablement.

## 19. Determinism

The same capture, version, detector configuration and threshold set should produce semantically identical findings independent of Go map iteration order or nondeterministic goroutine scheduling.

Golden tests normalize only truly dynamic metadata; they must not hide meaningful output drift.

## 20. Migration from the inherited pipeline

Initial migration order:

1. add capture metadata and quality models beside current code;
2. expose capture-quality result without changing legacy detector conclusions;
3. add capture duplication signal;
4. introduce normalized packet source references;
5. introduce new finding/evidence types;
6. migrate priority L2 detectors first;
7. migrate STP/LACP/redundancy;
8. migrate TCP/services;
9. migrate API/UI/reporting;
10. retire legacy report fields only after compatibility and migration are complete.

The pipeline must remain buildable and testable after every phase.
