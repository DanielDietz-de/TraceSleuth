# TraceSleuth roadmap

> **Packets tell the story. TraceSleuth finds the problem.**

This roadmap describes the controlled transformation from the imported SD-WAN Triage baseline into the independent TraceSleuth product.

Roadmap items are not implementation claims. Only shipped code, tests and documentation establish actual capability.

## Product mission

TraceSleuth is an open-source PCAP analysis platform that automatically detects network faults, anomalies, protocol issues, loops, redundancy failures and other network pathologies.

Primary promise:

> Upload or analyze a packet capture and receive evidence-backed findings showing what appears wrong, why TraceSleuth reached that conclusion, which packets support it, how confident the diagnosis is, what alternative explanations exist, and how to validate the result independently.

## Current status

**Current version line:** `0.1.0` bootstrap  
**Production status:** not production-ready  
**Stable detector catalogue:** not yet established  
**Target stable release:** `1.0.0`

## Phase 0 — Baseline and provenance

### Goals

- preserve legal attribution;
- identify exact source baseline;
- inspect actual source before refactoring;
- record imported architecture and risks;
- define deliberate upstream workflow.

### Deliverables

- [x] `UPSTREAM.md`
- [x] exact upstream baseline SHA
- [x] nearest prior upstream tag and relationship
- [x] `docs/history/ORIGIN.md`
- [x] `docs/development/UPSTREAM_WORKFLOW.md`
- [x] `docs/audits/INITIAL_BASELINE_AUDIT.md`
- [x] document that the current TraceSleuth repository uses a one-commit import rather than full upstream Git history

### Acceptance criteria

- provenance is exact and reproducible;
- MIT attribution remains intact;
- no claim of upstream endorsement exists;
- actual source code has been inspected;
- security, architecture, detector, storage, test and CI baseline are documented honestly.

## Phase 1 — TraceSleuth bootstrap

**Target line:** `0.1.x`

### Goals

- establish independent product identity;
- establish independent version lineage;
- add architecture contracts;
- add repository quality gates;
- keep the inherited application buildable during migration.

### Deliverables

- [x] authoritative root `VERSION`
- [x] `CHANGELOG.md`
- [x] versioning policy
- [x] release process
- [x] target architecture document
- [x] analysis pipeline document
- [x] finding/evidence model contract
- [x] correlation engine contract
- [x] scope/limitations
- [x] detailed roadmap
- [ ] complete controlled runtime rename to `tracesleuth`
- [ ] update Go module path without breaking imports
- [ ] migrate product-facing UI title, API metadata, reports and storage names
- [ ] establish full project README
- [ ] add visible About/upstream attribution in UI
- [ ] add normal CI workflow
- [ ] add static analysis/security workflows
- [ ] add repository hygiene/version alignment tests
- [ ] remove universal default credentials
- [ ] replace JWT fallback secret with fail-closed behavior

### Acceptance criteria

- build/test state is not degraded;
- product-facing identity is consistently TraceSleuth except intentional historical/compatibility references;
- `VERSION` is authoritative and CI blocks drift;
- general CI runs on pull requests and pushes;
- inherited security defects are either fixed or explicitly block production claims;
- documentation clearly distinguishes implemented versus planned capability.

## Phase 2 — Capture trust

**Target line:** `0.2.x`

### Goals

Diagnose the capture before diagnosing the network.

### Deliverables

- capture identity and SHA-256;
- PCAP/PCAPNG metadata;
- link types;
- capture duration/counts;
- timestamp resolution;
- PCAPNG interfaces;
- snap length;
- truncation rate;
- reported drops where available;
- timestamp monotonicity/jumps;
- capture gaps;
- unsupported encapsulations;
- parser/malformed counts;
- file truncation classification;
- L2/control-plane observability;
- capture quality result;
- dedicated capture duplication detector.

### Acceptance criteria

- capture-quality stage executes before fault detectors;
- detectors can consume capture capabilities/limitations;
- malformed input cannot crash normal analysis boundaries;
- capture duplication reduces relevant downstream confidence;
- positive, negative and malformed fixtures exist;
- no diagnostic finding silently assumes missing capture context.

## Phase 3 — Evidence architecture

**Target line:** `0.3.x`

### Goals

- normalized observations;
- common detector metadata/lifecycle;
- first-class evidence;
- normalized findings;
- explainable confidence;
- correlation primitives.

### Deliverables

- packet source reference model;
- normalized Ethernet/VLAN/ARP/TCP and priority protocol observations;
- stable detector IDs and versions;
- duplicate detector-ID rejection;
- detector prerequisites/capabilities;
- `Initialize/Observe/Finalize/Findings/Reset`-equivalent lifecycle;
- normalized `Finding` schema;
- certainty classification;
- confidence contribution/penalty model;
- evidence packet references;
- detector catalogue endpoint/data;
- golden schema tests.

### Acceptance criteria

- new priority detectors do not directly mutate ad-hoc protocol-specific report arrays as their primary output;
- every major finding has evidence, time range, confidence, certainty, alternatives and limitations;
- detector output is deterministic;
- confidence is explainable and documented;
- compatibility with legacy views is tested during migration.

## Phase 4 — Layer-2 diagnostics

**Target line:** `0.4.x`

### Goals

Make Layer-2 pathology analysis a primary TraceSleuth differentiator.

### Deliverables

- exact Ethernet frame fingerprinting;
- documented fingerprint policy/version;
- selected normalized near-duplicate fingerprints;
- exact duplicate frame storm detector;
- broadcast storm detector;
- multicast storm detector;
- ARP storm detector;
- conflicting ARP mappings;
- ND anomaly foundation;
- probable L2 loop correlation;
- SPAN/capture duplication safeguards;
- evidence-only PCAP export foundation.

### Acceptance criteria

- loop detection never fires solely because duplicate packets exist;
- multiple-source SPAN, packet-broker, both-sides-of-link and port-channel-mirror fixtures exist;
- high-severity loop inference requires multiple independent signals unless a direct protocol violation is definitive;
- packet references and Wireshark filters are present;
- frame state is bounded for large captures;
- positive, negative, boundary and adversarial fixtures exist.

## Phase 5 — Redundancy diagnostics

**Target line:** `0.5.x`

### Goals

Deep deterministic analysis of spanning tree, link aggregation, FHRP and multi-chassis symptoms.

### Deliverables

#### STP family

- STP;
- RSTP;
- MSTP where technically feasible;
- PVST+/Rapid-PVST framing where observable;
- root bridge changes;
- root flapping;
- apparent multiple roots;
- topology-change storms;
- TCN storms;
- BPDU timing/message-age anomalies;
- proposal/agreement churn;
- convergence correlation.

#### LACP

- EtherType `0x8809` Slow Protocols;
- LACP subtype `0x01`;
- actor/partner system priority/ID/key/port/state;
- collector delay;
- activity/timeout/aggregation/synchronization/collecting/distributing/defaulted/expired bits;
- identity changes;
- key changes/mismatch;
- synchronization loss;
- collecting/distributing loss;
- partner churn;
- timeout mismatch;
- member inconsistency where distinguishable.

#### FHRP and multi-chassis

- VRRP improvements;
- HSRP improvements;
- GLBP consideration;
- multiple-active symptoms;
- probable duplicate forwarding;
- multi-chassis forwarding inconsistency;
- MLAG symptom inference;
- vendor enrichment plugin framework.

### Acceptance criteria

- protocol parsing has positive/negative/malformed tests;
- no generic MLAG universal parser is invented;
- weak indirect evidence cannot produce a critical MLAG conclusion by itself;
- alternatives include capture duplication where relevant;
- direct evidence and inference are clearly separated;
- vendor logic remains isolated from generic protocol parsing.

## Phase 6 — End-to-end network pathology

**Target line:** `0.6.x` or later according to implementation sequencing

### Goals

Extend evidence architecture through routing, transport, services, voice and tunnels.

### Deliverables

- TTL/hop-limit anomaly analysis;
- probable routing-loop symptoms;
- ICMP error correlation;
- fragmentation/PMTUD analysis;
- TCP retransmission refinement;
- fast/spurious retransmission inference where defensible;
- duplicate ACK storms;
- zero window/probes/window exhaustion;
- handshake failure/SYN retry/reset analysis;
- RTT/latency anomalies;
- DNS timeout/retry/latency/SERVFAIL/NXDOMAIN analysis;
- DHCP sequence/allocation/competing-server analysis;
- NTP analysis;
- RTP loss/jitter/reordering with correct sequence/clock context;
- tunnel/encapsulation anomalies.

### Acceptance criteria

- capture duplication and timestamp disorder influence TCP confidence;
- UDP loss percentages are never invented without sequence or multi-capture evidence;
- DNS/DHCP conclusions avoid categorical malicious intent without context;
- every migrated major detector meets detector definition of done.

## Phase 7 — Multi-capture intelligence

**Target line:** `0.6.x` / `0.7.x` according to sequencing

### Goals

Generalize the inherited LAN/WAN comparator into flexible capture-point-aware analysis.

### Deliverables

- arbitrary number of capture points;
- capture-point name/location/device/interface/direction;
- optional clock source/known offset;
- clock-offset estimation where defensible;
- packet disappearance;
- duplication;
- modification;
- NAT;
- TTL/DSCP/VLAN/encapsulation transformations;
- delay attribution with uncertainty;
- ordering changes;
- asymmetric visibility;
- duplicate forwarding paths.

### Acceptance criteria

- no fixed LAN/WAN assumption in the core model;
- timing precision never exceeds clock confidence;
- packet correlation has positive/negative collision tests;
- large captures use bounded/streaming state where practical.

## Phase 8 — Diagnostic experience

**Target line:** `0.7.x`

### Goals

Make evidence and causal timelines usable by network engineers.

### Navigation target

```text
Dashboard
Findings
Timeline
Topology
Conversations
Protocols
Packets
Capture Quality
Comparison
Reports
Settings
About
```

### Finding detail target

1. What happened
2. Why TraceSleuth thinks this
3. Observed evidence
4. Packet references
5. Timeline
6. Alternative explanations
7. Wireshark validation
8. Next investigation steps
9. Safe remediation guidance
10. Limitations

### Acceptance criteria

- UI consumes normalized findings;
- packet references are clickable;
- filters are copyable;
- evidence export works for supported finding types;
- timeline correlates control-plane and impact events;
- About page contains upstream attribution;
- experimental detectors are labeled honestly.

## Phase 9 — Production hardening

**Target line:** `0.8.x`

### Goals

Secure untrusted input, self-hosting and supply chain.

### Deliverables

- no universal default credentials;
- secure first-run/bootstrap admin;
- fail-closed JWT secret behavior;
- configurable listen address;
- safe behavior for non-loopback binding;
- secure headers/CORS/CSRF posture;
- streaming upload limits;
- internal random file names;
- path containment;
- retention and storage quotas;
- analysis timeout/cancellation;
- global concurrency limits;
- bounded WebSocket/subscriber resources;
- parser fuzzing;
- malformed corpus;
- `govulncheck`;
- CodeQL;
- secret scanning;
- dependency review;
- SBOM;
- container scanning;
- non-root container;
- systemd hardening;
- backup/retention docs;
- threat model and PCAP sensitivity docs.

### Acceptance criteria

- known critical inherited auth/path issues are fixed;
- malformed input tests and fuzz smoke tests pass;
- supported deployment modes are documented and tested;
- security policy is honest and contains no fake SLA;
- no required cloud service or telemetry exists.

## Phase 10 — Stable release

**Target:** `1.0.0`

### Goals

Release the first stable public TraceSleuth version only after detector validation, security review, documentation completion and performance characterization.

### Required stable domains

#### Core

- PCAP/PCAPNG;
- CLI and web;
- stable documented JSON findings;
- capture quality before diagnosis.

#### L2

- duplicate frames;
- broadcast/multicast storms;
- probable loop;
- capture duplication safeguards.

#### Spanning tree

- STP/RSTP;
- MSTP where implemented and documented;
- root/topology instability.

#### Aggregation/redundancy

- LACP actor/partner state;
- key/synchronization/collecting/distributing/churn;
- VRRP/HSRP;
- duplicate forwarding;
- MLAG symptom inference with explicit limitations.

#### Transport/services

- TCP retransmission;
- handshake failures;
- zero windows;
- RTT anomalies;
- DNS;
- DHCP;
- ICMP.

### 1.0 acceptance criteria

- every major finding has evidence, packet references, time range, confidence, certainty, alternatives and Wireshark validation;
- no universal default admin password;
- upload validation/resource limits/temporary-file safety exist;
- high-risk parsers are fuzzed;
- detector corpus/regression/golden/integration/frontend tests exist;
- performance baseline exists;
- API/config/deployment/security/development/release docs are complete;
- release candidate validation report is complete;
- no known critical release-blocking defect is hidden or waived without explicit documentation.

## Detector priority order

### Priority 0 — Capture trust

1. Capture integrity
2. Truncation
3. Timestamp anomalies
4. Capture duplication
5. Unsupported link-layer warning

### Priority 1 — Critical Layer 2

6. Exact duplicate frame storm
7. Broadcast storm
8. Multicast storm
9. Probable Layer-2 loop
10. ARP storm
11. Conflicting ARP mappings

### Priority 2 — Spanning tree

12. STP root change
13. Root flapping
14. Topology-change storm
15. TCN storm
16. BPDU timing anomaly
17. Multiple apparent roots

### Priority 3 — Link aggregation and redundancy

18. LACP partner instability
19. LACP key mismatch
20. LACP synchronization loss
21. LACP collecting/distributing loss
22. LACP defaulted/expired
23. Probable duplicate forwarding
24. Probable multi-chassis forwarding inconsistency
25. FHRP multiple-active symptoms
26. VRRP flapping
27. HSRP flapping

### Priority 4 — Transport

28. Failed TCP handshake
29. SYN retransmission storm
30. TCP retransmission anomaly
31. Duplicate ACK storm
32. Zero window
33. Window exhaustion
34. RTT anomaly
35. Connection-reset anomaly

### Priority 5 — Services

36. DNS timeout/retry
37. DNS latency
38. DHCP competing-server behavior
39. DHCP allocation failure
40. NTP anomaly

## Definition of done for a stable detector

A detector is not complete merely because code exists.

Required:

- unique stable ID;
- detector version;
- algorithm implementation;
- positive PCAP fixture;
- negative PCAP fixture;
- false-positive fixture where relevant;
- unit tests;
- boundary tests;
- confidence documentation;
- limitation documentation;
- Wireshark validation filter;
- UI presentation;
- JSON output;
- detector catalogue entry;
- evidence packet references;
- changelog entry.

## Deferred-item policy

Every implementation report must identify deferred items explicitly. A roadmap checkbox must not be checked until the repository contains the actual implementation and applicable tests.
