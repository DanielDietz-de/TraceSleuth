# TraceSleuth roadmap

**Packets tell the story. TraceSleuth finds the problem.**

This roadmap defines the controlled transformation from the imported SD-WAN Triage codebase into the independent TraceSleuth network fault-analysis platform.

The roadmap is capability-driven, not date-driven. A phase is complete only when its acceptance criteria are satisfied. Source code alone is not completion.

## Guiding rules

Every phase must:

1. inspect current implementation before changing it;
2. document current behavior and dependencies;
3. define acceptance criteria;
4. add or prepare tests before high-risk behavior changes;
5. keep the repository buildable;
6. run formatting, backend tests, frontend checks, and relevant security checks;
7. update documentation and changelog;
8. preserve attribution;
9. report deferred work honestly.

High-severity diagnoses require evidence and false-positive resistance. AI may explain deterministic findings later but must never invent the underlying observation.

---

## Phase 0 — Baseline and provenance

### Objectives

- inspect the actual imported repository;
- identify exact upstream baseline;
- preserve license and attribution;
- record the independent downstream relationship;
- establish an honest security/architecture/test baseline.

### Deliverables

- `docs/audits/INITIAL_BASELINE_AUDIT.md`
- `UPSTREAM.md`
- `docs/history/ORIGIN.md`
- `docs/development/UPSTREAM_WORKFLOW.md`

### Acceptance criteria

- exact upstream full commit SHA recorded;
- associated upstream release/tag recorded when applicable;
- TraceSleuth import commit recorded;
- baseline mapping independently verified through repository content;
- original MIT notice preserved;
- no upstream endorsement claimed;
- architecture, detector inventory, API, storage, auth, tests, workflows, security, concurrency, memory behavior, and hygiene debt documented;
- unimplemented capabilities are not claimed as present.

### Status

**Implemented in the 0.1.0 bootstrap branch.** Further detector-specific audits may deepen the baseline, but provenance and initial architecture/security inventory are established.

---

## Phase 1 — TraceSleuth bootstrap

### Objectives

- establish product identity;
- create independent version lineage;
- introduce repository quality gates;
- migrate product-facing naming without destructive global replacement.

### Deliverables

- `VERSION` beginning at `0.1.0`;
- `CHANGELOG.md`;
- product-facing README;
- versioning and release-process documentation;
- initial CI workflow;
- repository-hygiene checks;
- controlled executable/module/product rename plan.

### Acceptance criteria

- README identifies TraceSleuth and visibly acknowledges upstream;
- `VERSION` is authoritative;
- release lineage no longer inherits 6.x;
- CI runs on pull requests and pushes;
- supported Go and Node runtimes are used;
- no silent failing-test bypasses;
- remaining legacy product strings are inventoried and either historical, compatibility-related, or scheduled for migration;
- repository remains buildable after executable/module rename work.

### Status

**In progress.** Documentation identity and independent version lineage are established. Code-level rename, version-source wiring, and complete CI/security gates remain.

---

## Phase 2 — Capture trust

### Objectives

Diagnose the capture before diagnosing the network.

### Scope

- PCAP/PCAPNG file metadata;
- SHA-256 capture identity;
- link-layer type;
- packet/byte counts;
- first/last timestamps and duration;
- timestamp resolution;
- interface metadata;
- snap length;
- truncation rate;
- reported drops where available;
- monotonicity and jumps;
- parser failures;
- malformed packets;
- file truncation;
- unsupported encapsulations;
- L2 visibility;
- control-plane observability;
- duplicate-capture prevalence;
- probable SPAN/mirror duplication;
- capture gaps.

### Acceptance criteria

- capture preflight runs before pathology detectors;
- results produce `GOOD`, `LIMITED`, or equivalent documented quality levels;
- limitations are structured, not only text logs;
- downstream detectors can consume quality limitations and reduce confidence;
- malformed inputs do not cause uncontrolled panics;
- PCAP and PCAPNG fixtures cover good, truncated, malformed, mixed-link, and timestamp-anomaly cases;
- parser fuzz smoke tests exist.

### Planned release

`0.2.0`

---

## Phase 3 — Evidence architecture and detector lifecycle

### Objectives

Create a stable observation, evidence, finding, detector, and confidence foundation.

### Scope

- normalized observations;
- packet references;
- finding/evidence schema;
- stable detector IDs and versions;
- detector prerequisites;
- detector state requirements;
- configurable thresholds;
- machine-readable detector catalogue;
- confidence contributions;
- certainty classification;
- correlation primitives.

### Acceptance criteria

Every normalized major finding can represent:

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

Additional criteria:

- confidence is documented and explainable;
- certainty values distinguish observation from inference;
- packet references resolve to real packets;
- no fabricated evidence examples appear in real analysis output;
- detector registration rejects duplicate stable IDs;
- detector metadata is available to CLI/API/UI.

### Planned release

`0.3.0`

---

## Phase 4 — Layer-2 diagnostics

### Objectives

Build TraceSleuth's primary differentiation in Ethernet fault analysis.

### Scope

- exact frame fingerprints;
- carefully normalized near-duplicate fingerprints;
- capture-duplication detector;
- exact duplicate-frame storms;
- broadcast storms;
- multicast storms;
- unknown-unicast symptoms where observable;
- correlation-based probable Layer-2 loops;
- ARP storms and mapping conflict/churn;
- IPv6 ND anomalies.

### Acceptance criteria

- exact fingerprint algorithm documented;
- VLAN/QinQ handling documented;
- capture duplication reduces confidence of loop/duplicate-forwarding findings;
- loop detector requires independent signals unless one definitive violation exists;
- stable fixed-factor duplicate capture does not trigger a critical loop finding;
- rate amplification and baseline behavior are distinguished;
- positive, negative, boundary, and adversarial false-positive PCAP fixtures exist;
- packet references and Wireshark filters are present.

### Planned release

`0.4.0`

---

## Phase 5 — Redundancy diagnostics

### Objectives

Implement spanning tree, link aggregation, FHRP, MLAG symptom inference, and vendor enrichment.

### Scope

#### STP/RSTP/MSTP/PVST

- protocol version and BPDU type;
- root/sender bridge IDs;
- root cost and port ID;
- flags and topology-change state;
- timers and message age;
- MST region data where available;
- VLAN context where observable;
- root changes, root flapping, topology storms, TCN storms, timing anomalies, and apparent multiple-root conditions.

#### LACP

Parse `0x8809`, subtype `0x01`, including:

- actor/partner system priorities and IDs;
- keys;
- port priorities and IDs;
- activity, timeout, aggregation, synchronization, collecting, distributing, defaulted, and expired state bits;
- collector maximum delay.

Detect:

- partner/actor identity changes;
- key changes/mismatch;
- synchronization loss;
- collecting/distributing loss;
- defaulted/expired partner;
- churn;
- timeout mismatch;
- multiple inconsistent partners;
- member inconsistencies where capture context permits.

#### MLAG symptoms

Implement an inference framework, not a fake universal protocol parser.

Distinguish:

- direct evidence;
- strong indirect evidence;
- weak indirect evidence.

Weak evidence alone must not produce critical MLAG conclusions.

### Acceptance criteria

- extensive positive and negative LACP fixtures;
- valid LACP failover false-positive fixtures;
- STP conclusions state visibility limits;
- no claim about a physical blocking port unless observable;
- MLAG findings list alternative causes including capture duplication;
- vendor-specific enrichments remain isolated from generic analyzers;
- FHRP transitions are described precisely and do not equate every transition with failure.

### Planned release

`0.5.0`

---

## Phase 6 — End-to-end network pathology

### Objectives

Mature Layer 3, transport, services, voice, and tunnel diagnosis.

### Scope

- routing-loop symptoms;
- TTL/hop-limit recurrence;
- ICMP time-exceeded/unreachable correlation;
- fragmentation;
- MTU/PMTUD black-hole symptoms;
- TCP handshakes, SYN retries, resets, retransmissions, fast/spurious retransmission where inferable, duplicate ACKs, reordering, zero window, window exhaustion, RTT, stalls, MSS/options;
- DNS retry/timeout/latency/server inconsistency;
- DHCP competing-server and allocation-failure behavior;
- NTP;
- SIP/RTP;
- tunnels and encapsulations.

### Acceptance criteria

- TCP analysis explicitly accounts for capture duplication and timestamp quality;
- arbitrary UDP loss percentages are prohibited without sequence or multi-capture evidence;
- PMTUD findings require defensible correlated evidence;
- protocol parsers have malformed-input tests;
- relevant custom binary parsers have fuzz coverage.

---

## Phase 7 — Multi-capture intelligence

### Objectives

Generalize the imported hardcoded LAN/WAN comparison model.

### Scope

- arbitrary capture points;
- capture metadata: name, location, device, interface, direction, clock source, known offset;
- packet disappearance;
- duplication;
- modification;
- NAT;
- TTL/DSCP/VLAN changes;
- encapsulation/decapsulation;
- added latency;
- ordering changes;
- asymmetric visibility;
- duplicate forwarding;
- clock-offset estimation where technically justified.

### Acceptance criteria

- no hardcoded LAN/WAN semantics in core comparison model;
- synchronized and unsynchronized timing are distinguished;
- one-way latency precision never exceeds clock certainty;
- disappearance is not automatically stated as device drop;
- timing confidence is visible in findings/UI/API.

### Planned release

`0.6.0`

---

## Phase 8 — Diagnostic experience

### Objectives

Turn analysis output into a troubleshooting workflow.

### Target navigation

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

### Acceptance criteria

A major finding view shows:

1. what happened;
2. why TraceSleuth thinks this;
3. observed evidence;
4. packet references;
5. timeline;
6. alternative explanations;
7. Wireshark validation;
8. next investigation steps;
9. safe remediation guidance where appropriate;
10. limitations.

Additional criteria:

- evidence packet click-through;
- display-filter copy;
- evidence mini-PCAP export where implemented;
- timeline shows causal ordering without claiming causation solely from temporal proximity;
- topology distinguishes direct adjacency, inferred relationship, and communication relationship.

### Planned release

`0.7.0`

---

## Phase 9 — Production hardening

### Objectives

Make self-hosting secure, bounded, observable, and documented.

### Scope

- remove universal default credentials;
- secure first-run/bootstrap admin flow;
- persistent and rotatable secrets;
- restrictive CORS and origin validation;
- secure headers;
- CSRF protection where applicable;
- request body limits;
- sanitized/generated upload names;
- parser hardening;
- analysis time/resource limits;
- bounded concurrency;
- context cancellation;
- retention policy;
- restrictive filesystem permissions;
- fuzzing;
- dependency policy;
- vulnerability scanning;
- SBOM;
- native/systemd/container deployment;
- non-root container;
- hardening guidance.

### Acceptance criteria

- no universal administrator password;
- no secrets logged;
- CSPRNG failure fails closed;
- upload body bounded before multipart parsing;
- path traversal tests exist;
- malformed PCAP corpus exists;
- `go test -race ./...` passes where supported;
- no unbounded analysis queue;
- cancellation actually stops processing;
- retention and deletion are configurable/documented;
- deployment examples use restrictive defaults.

### Planned release

`0.8.0`

---

## Phase 10 — Release candidate and stable 1.0

### 0.9.0 release-candidate gate

- detector catalogue complete for shipped detectors;
- each claimed stable detector meets detector acceptance criteria;
- golden outputs stable;
- performance baseline measured;
- public test corpus has provenance metadata;
- security review complete;
- documentation is internally consistent;
- supported platforms validated.

### 1.0.0 definition of done

#### Product

- consistent TraceSleuth identity;
- upstream attribution intact;
- no misleading endorsement claim;
- independent version lineage.

#### Core

- PCAP and PCAPNG analysis;
- CLI and web interfaces;
- stable documented JSON findings;
- capture quality before fault diagnosis.

#### L2

- duplicate frames;
- broadcast storms;
- multicast storms;
- probable loop detection;
- capture/SPAN duplication safeguards.

#### Spanning tree and aggregation

- mature implemented STP family subset documented honestly;
- root/topology instability;
- LACP parsing and state tracking;
- key/identity/synchronization/collecting/distributing/churn findings.

#### Redundancy

- VRRP;
- HSRP;
- probable duplicate forwarding;
- MLAG symptom inference with explicit limitations.

#### Transport and services

At least mature handling for:

- TCP retransmissions;
- handshake failures;
- zero windows;
- RTT anomalies;
- DNS;
- DHCP;
- ICMP.

#### Evidence

Every major finding includes:

- evidence;
- packet references;
- time range;
- confidence;
- certainty;
- alternatives;
- validation guidance;
- limitations.

#### Security

- no universal default password;
- upload validation;
- temporary-file safety;
- resource limits;
- vulnerability scanning;
- parser fuzzing;
- security policy.

#### Testing

- CI passes;
- race tests pass where supported;
- detector corpus exists;
- regression suite exists;
- frontend tests exist;
- integration tests exist.

#### Documentation

- installation;
- architecture;
- detector catalogue;
- configuration;
- CLI;
- API;
- security;
- deployment;
- development;
- testing;
- release process;
- attribution;
- limitations.

---

## Detector acceptance criteria

A detector is not complete merely because code exists.

Each stable detector requires:

- unique stable ID;
- display name and purpose;
- detector version;
- implemented algorithm;
- positive PCAP fixture;
- negative PCAP fixture;
- false-positive fixture where relevant;
- unit tests;
- threshold boundary tests;
- documented confidence model;
- documented limitations;
- Wireshark validation filter;
- UI presentation;
- JSON output;
- detector catalogue entry;
- packet evidence references;
- changelog entry.

High-risk heuristic detectors require multiple adversarial false-positive fixtures.

---

## Explicit non-goals

TraceSleuth is not intended to become:

- a generic SIEM;
- a replacement for Wireshark;
- a full NDR platform;
- a cloud-only SaaS service;
- an opaque AI diagnosis engine;
- a vendor-specific switch-management application;
- a configuration-management system;
- a network controller.

TraceSleuth complements Wireshark by answering:

> What looks wrong in this capture, what evidence supports that conclusion, how confident are we, what else could explain it, and which packets should the engineer inspect?
