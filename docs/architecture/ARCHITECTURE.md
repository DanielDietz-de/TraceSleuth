# TraceSleuth architecture

## 1. Purpose

TraceSleuth is an open-source PCAP analysis platform for evidence-backed network fault diagnosis.

Its architecture is designed around a strict principle:

> A diagnosis is only as credible as the packet observations, capture context, correlation logic, limitations and reproducible evidence that support it.

TraceSleuth therefore separates packet parsing, normalized observations, detector reasoning, evidence, correlation, findings and presentation.

## 2. Product architecture principles

### Deterministic analysis first

Protocol parsers, state machines, time-series analysis, packet correlation, frame fingerprinting, explicit statistical methods and documented heuristics produce primary findings.

An LLM or generative system is never the primary authority deciding whether a loop, retransmission problem, LACP failure, STP instability or redundancy problem exists.

Optional AI may explain deterministic findings later. The application must remain fully functional without cloud services, external APIs, Internet access or AI models.

### Evidence before conclusion

Every major finding should identify:

- what was observed;
- supporting packet references;
- time range;
- affected entities;
- reasoning;
- confidence and certainty;
- direct observation versus inference;
- alternative explanations;
- capture limitations;
- Wireshark validation guidance;
- recommended next investigation steps.

### Capture trust precedes diagnosis

The pipeline diagnoses the capture before diagnosing the network. Truncation, timestamp problems, capture duplication, missing L2 headers, unsupported encapsulations and absent control-plane visibility can limit or invalidate other conclusions.

### False-positive resistance over spectacle

High-severity heuristic findings normally require multiple independent signals. Duplicate frames alone are not proof of a network loop. Multiple DHCP servers alone are not proof of a rogue server. LACP churn alone is not proof of MLAG split-brain.

### Bounded state and streaming processing

Large captures must not require storing every decoded packet object indefinitely. Observations should carry traceable evidence references without duplicating full payloads into every in-memory model.

### Local-first and self-hosted

No mandatory cloud dependency or telemetry is required. Native CLI, local web, server and container deployment modes should share the same analysis core.

## 3. Current inherited architecture

The imported baseline is organized around:

```text
capture -> pcapgo reader -> packet processor -> detector registry
                                         |-> shared AnalysisState
                                         |-> monolithic TriageReport
                                                  |-> CLI/JSON/HTML/UI
```

The current detector interface receives a raw `gopacket.Packet`, shared analysis state and shared report. The report contains protocol-specific arrays for DNS, TCP, ARP, LAN protocols, security findings, timeline data and other domains.

This architecture is retained temporarily for compatibility but is not the target TraceSleuth evidence architecture.

## 4. Target logical architecture

```text
                         +----------------------+
                         |  Capture ingestion   |
                         | PCAP / PCAPNG / meta |
                         +----------+-----------+
                                    |
                                    v
                         +----------------------+
                         | Capture trust layer  |
                         | quality/capabilities |
                         | duplication/gaps     |
                         +----------+-----------+
                                    |
                                    v
                         +----------------------+
                         | Protocol parsing     |
                         | normalized facts     |
                         +----------+-----------+
                                    |
                                    v
                         +----------------------+
                         | Observation stream   |
                         | bounded source refs  |
                         +----+------------+----+
                              |            |
                     +--------v--+      +--v----------------+
                     | Detectors |      | Topology evidence |
                     | state/rules|     | direct/inferred   |
                     +-----+-----+      +---------+---------+
                           |                      |
                           +----------+-----------+
                                      v
                         +----------------------+
                         | Evidence + findings  |
                         | certainty/confidence |
                         +----------+-----------+
                                    |
                                    v
                         +----------------------+
                         | Correlation engine   |
                         | explain contributions|
                         +----------+-----------+
                                    |
                  +-----------------+------------------+
                  |                 |                  |
                  v                 v                  v
             CLI / JSON          API / UI          Reports/export
```

## 5. Target package layout

The intended direction is:

```text
/
├── cmd/
│   └── tracesleuth/
├── internal/
│   ├── analysis/
│   │   ├── engine/
│   │   ├── pipeline/
│   │   ├── correlation/
│   │   ├── scoring/
│   │   └── timeline/
│   ├── capture/
│   │   ├── ingest/
│   │   ├── metadata/
│   │   ├── quality/
│   │   ├── fingerprint/
│   │   └── export/
│   ├── protocols/
│   │   ├── ethernet/
│   │   ├── vlan/
│   │   ├── stp/
│   │   ├── lacp/
│   │   ├── lldp/
│   │   ├── cdp/
│   │   ├── arp/
│   │   ├── nd/
│   │   ├── fhrp/
│   │   ├── ipv4/
│   │   ├── ipv6/
│   │   ├── tcp/
│   │   ├── udp/
│   │   ├── icmp/
│   │   ├── dns/
│   │   ├── dhcp/
│   │   ├── routing/
│   │   ├── voice/
│   │   └── tunnels/
│   ├── detectors/
│   │   ├── l2/
│   │   ├── redundancy/
│   │   ├── transport/
│   │   ├── routing/
│   │   ├── services/
│   │   ├── voice/
│   │   └── capturequality/
│   ├── evidence/
│   ├── findings/
│   ├── topology/
│   ├── reporting/
│   ├── storage/
│   ├── api/
│   ├── auth/
│   └── config/
├── web/frontend/
├── api/openapi/
├── docs/
├── testdata/
│   ├── pcaps/
│   ├── golden/
│   └── malformed/
├── tools/pcapgen/
└── deploy/
```

This is a target architecture, not permission for gratuitous churn. Existing packages move only when the new abstraction is implemented and tested.

## 6. Core domain layers

### 6.1 Capture identity and metadata

Every capture receives an internal identity independent of the untrusted original filename.

Expected metadata includes:

- capture ID;
- original display filename;
- SHA-256 hash;
- format;
- link types;
- first/last timestamp;
- duration;
- packet/byte count;
- timestamp resolution;
- interface metadata;
- user-supplied capture-point labels;
- device/location/interface/direction metadata;
- clock source/known offset when supplied.

### 6.2 Capture quality and capabilities

Capture quality produces structured observations before fault detectors run.

Examples:

- truncation rate;
- malformed record counts;
- file truncation;
- timestamp jumps;
- non-monotonic timestamps;
- capture gaps;
- interface metadata availability;
- L2 header availability;
- supported/unsupported link types;
- observed control-plane protocols;
- likely capture duplication.

Detectors consume capabilities and limitations rather than making assumptions.

### 6.3 Normalized observations

Protocol packages emit immutable or effectively immutable facts such as:

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

Observations retain enough source context to trace back to original packets without storing full duplicate payloads everywhere.

### 6.4 Detector engine

A target detector exposes metadata and lifecycle behavior conceptually equivalent to:

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

Initialize(context)
Observe(event)
Finalize()
Findings()
Reset()
```

Exact Go interfaces are introduced only after implementation tests prove the shape.

### 6.5 Evidence

Evidence is structured, source-traceable support for a finding. Evidence may include packet references, metrics, observed transitions, fingerprint multiplicity, control-plane events and correlation links.

Evidence never fabricates packet examples.

### 6.6 Findings

A finding is the normalized diagnosis/result object. It carries stable detector identity, severity, confidence, certainty, evidence, alternatives, limitations and validation instructions.

The target model is defined in `FINDING_AND_EVIDENCE_MODEL.md`.

### 6.7 Correlation

Correlation combines independent evidence and lower-level findings into higher-order conclusions. It must expose contributions and penalties rather than hide reasoning behind an arbitrary score.

### 6.8 Topology

Topology edges are classified as:

- direct adjacency;
- inferred relationship;
- communication relationship.

All edges carry provenance and confidence. Ordinary IP communication must not be drawn as a physical link.

## 7. Migration strategy

The transformation uses a strangler-style migration:

1. keep inherited CLI/web/report functionality operational;
2. add authoritative version/provenance/quality gates;
3. add capture metadata and quality models beside legacy report code;
4. add normalized observations for priority protocols;
5. add new findings/evidence model;
6. adapt priority detectors to emit new findings;
7. translate new findings into legacy views temporarily where needed;
8. migrate API/UI/reporting to the normalized contract;
9. remove obsolete legacy structures only after equivalent tested functionality exists.

A massive one-shot rewrite is explicitly rejected.

## 8. Concurrency model

Target properties:

- immutable observation events where practical;
- detector-local state by default;
- explicit concurrency contract per detector;
- bounded queues and maps;
- deterministic finalize order;
- context cancellation and deadlines;
- global maximum concurrent analyses;
- worker shutdown without goroutine leaks;
- reproducible findings independent of map iteration order;
- race testing in CI.

The current goroutine-per-independent-detector-per-packet pattern should be benchmarked and likely replaced by a bounded execution model.

## 9. Storage model

Required storage separation:

```text
configuration
capture originals
analysis metadata
normalized findings
reports/exports
temporary data
```

Retention must be configurable. Original captures must not be silently retained forever. Internal random IDs are used for filesystem storage. Original names are display metadata only.

## 10. API architecture

Target base path:

```text
/api/v1/
```

Core resources:

```text
health
version
captures
analyses
findings
detectors
reports
comparisons
```

The API must have an OpenAPI contract and schema-drift validation.

## 11. Security boundaries

Untrusted boundaries include:

- capture files;
- PCAPNG metadata;
- filenames;
- protocol payloads/TLVs;
- key-log files;
- API parameters;
- WebSocket connections;
- user-supplied capture-point metadata;
- external integration responses when enabled.

Parser panics, integer overflow, allocation abuse, path traversal, unsafe temporary files and unbounded workloads are security issues, not merely robustness defects.

## 12. Product non-goals

TraceSleuth is not intended to become:

- a generic SIEM;
- a Wireshark replacement;
- a full NDR platform;
- cloud-only SaaS;
- an opaque AI diagnosis engine;
- a vendor-specific switch manager;
- a configuration manager;
- a network controller.

## 13. Architecture decision records

Major decisions are recorded in `docs/architecture/adr/` and should include context, decision, alternatives and consequences.

Initial ADR subjects should include:

- deterministic-first diagnosis;
- incremental migration instead of rewrite;
- authoritative `VERSION` source;
- capture trust before diagnosis;
- normalized evidence and certainty semantics;
- local-first/no mandatory telemetry;
- detector IDs and versions;
- compatibility strategy for legacy `TriageReport`.

## 14. Current maturity

This document describes the target architecture and migration contract. It does not claim that all target packages or detectors already exist in `0.1.0`.

The inherited implementation remains operationally significant while the new architecture is introduced phase by phase.
