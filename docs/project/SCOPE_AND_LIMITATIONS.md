# Scope and limitations

## Product scope

TraceSleuth is an open-source packet-capture analysis platform for deterministic-first, evidence-backed diagnosis of network faults, anomalies, protocol issues, loops, redundancy failures and other network pathologies.

Primary promise:

> Upload or analyze a packet capture and receive evidence-backed findings showing what appears wrong, why TraceSleuth reached that conclusion, which packets support it, how confident the diagnosis is, what alternative explanations exist, and how to validate the result independently.

## Intended environments

TraceSleuth is intended for:

- campus networks;
- data-center networks;
- enterprise LANs;
- WANs;
- SD-WAN environments;
- traditional routed networks;
- Internet edge environments;
- server networks;
- highly redundant networks;
- LACP/MLAG-based architectures;
- voice networks;
- multi-vendor environments.

## Analysis domains

The target scope includes, where observable:

### Capture quality

- PCAP/PCAPNG format and metadata;
- link types;
- timestamps/resolution;
- truncation;
- reported drops;
- capture gaps;
- parser failures;
- malformed records;
- capture duplication;
- interface metadata;
- capture capability limitations.

### Layer 2

- exact frame duplication;
- selected near-duplicate analysis;
- broadcast/multicast storms;
- unknown-unicast flooding symptoms;
- probable forwarding loops;
- ARP/ND anomalies;
- MAC/path instability where inferable.

### Spanning tree

- STP;
- RSTP;
- MSTP where implemented;
- PVST+/Rapid-PVST symptoms where observable;
- root changes;
- topology-change storms;
- BPDU timing/state anomalies.

### Link aggregation and redundancy

- LACP actor/partner state;
- keys;
- synchronization;
- collecting/distributing;
- defaulted/expired state;
- identity churn;
- FHRP transitions;
- duplicate forwarding;
- multi-chassis forwarding inconsistency symptoms;
- MLAG-related inference with explicit limitations.

### Routing and path behavior

- TTL/hop-limit anomalies;
- routing-loop symptoms;
- ICMP correlation;
- fragmentation;
- PMTUD black-hole symptoms;
- DSCP/NAT/path changes across capture points;
- asymmetry where observable.

### Transport

- failed handshakes;
- SYN retries;
- retransmissions;
- duplicate ACKs;
- out-of-order conditions;
- zero window/window exhaustion;
- resets;
- RTT/latency anomalies;
- stalls and flow churn.

### Services and voice

- DNS;
- DHCP;
- NTP;
- SIP/RTP;
- selected application/tunnel protocols where evidence permits.

### Multi-capture

- packet disappearance;
- duplication;
- modification;
- NAT;
- TTL/DSCP/VLAN/encapsulation changes;
- delay attribution with clock uncertainty;
- duplicate forwarding paths;
- asymmetry.

## Explicit non-goals

TraceSleuth is not:

- a generic SIEM;
- a replacement for Wireshark;
- a full NDR platform;
- a cloud-only SaaS service;
- an opaque AI diagnosis engine;
- a vendor-specific switch-management application;
- a configuration-management system;
- a network controller.

TraceSleuth complements Wireshark by prioritizing likely problems and directing engineers to evidence.

## Fundamental capture limitations

A packet capture is an observation from one or more vantage points. It is not automatically a complete truth about the network.

Conclusions may be limited by:

- no Ethernet headers;
- unsupported link type;
- truncated packets;
- poor timestamp resolution;
- non-monotonic timestamps;
- capture loss;
- missing control-plane packets;
- one-sided flow visibility;
- asymmetric paths;
- no PCAPNG interface metadata;
- no ingress-interface context;
- encrypted control plane;
- capture started after the fault;
- capture ended before recovery;
- packet broker/SPAN/TAP duplication;
- NIC offloading;
- unsynchronized capture clocks;
- missing traffic due to sampling or filtering.

TraceSleuth must report these limitations instead of silently overstating confidence.

## Layer-2 loop limitations

Duplicate packets are not proof of a loop.

Alternative explanations include:

- multiple SPAN sources;
- both sides of a link captured;
- port-channel member capture;
- packet broker replication;
- ERSPAN duplication;
- TAP aggregation;
- NIC offloading;
- sender/application retransmission;
- intentional replication;
- redundancy protocols.

A high-confidence loop inference normally requires independent signals such as traffic amplification, repeated independent fingerprints, recurrence behavior and correlated topology/control-plane changes.

## MLAG limitations

MLAG is not a single universal wire protocol.

TraceSleuth therefore provides symptom inference, not a fake universal MLAG parser.

Without direct vendor control traffic or supplementary telemetry, TraceSleuth may observe behavior consistent with:

- duplicate forwarding across redundant paths;
- LACP identity inconsistency;
- multiple-active FHRP behavior;
- path alternation;
- redundancy convergence anomaly.

It generally cannot prove a specific peer-link or keepalive failure from generic packet symptoms alone.

## Unknown-unicast limitations

A single passive capture usually does not expose the complete MAC address table of a switch. TraceSleuth may identify flooding symptoms only when capture context provides sufficient visibility.

## Packet-loss limitations

For ordinary UDP traffic, TraceSleuth must not invent packet-loss percentages without:

- protocol sequence numbers;
- synchronized multi-capture comparison; or
- another direct evidence mechanism.

For TCP, retransmission and missing-segment symptoms are not identical to directly measured network loss.

## TCP limitations

Retransmission analysis may be confused by:

- duplicate capture;
- reordering;
- timestamp disorder;
- asymmetric visibility;
- capture starting mid-flow;
- offloading;
- snap length;
- retransmitted bytes with changed segmentation.

TraceSleuth should separate observed duplicate sequence behavior from stronger network-loss conclusions.

## DNS/DHCP limitations

Multiple DHCP servers are not automatically malicious or rogue. Multiple DNS resolvers are not automatically abnormal. Enterprise designs, relays, split DNS, high availability and migration states can be legitimate.

Detectors must report observable behavior and alternatives.

## Topology limitations

LLDP/CDP, STP, LACP, ARP, ND, FHRP and capture-point metadata may support a best-effort topology graph.

TraceSleuth must distinguish:

- direct adjacency;
- inferred relationship;
- communication relationship.

IP communication alone is not a physical link.

## Time and latency limitations

Cross-capture one-way latency depends on clock quality.

TraceSleuth must not report microsecond-accurate one-way delay when capture clocks are unsynchronized or offset uncertainty is larger than the claimed precision.

## Encrypted traffic

Encryption can hide application and control-plane fields. TraceSleuth may analyze observable metadata, handshake properties and traffic behavior but cannot claim visibility into encrypted payloads it cannot decrypt.

Optional key-log support must be handled as highly sensitive input.

## External lookups

Core TraceSleuth diagnosis must work offline.

Optional external integrations or lookups must be explicit. Their absence must not disable capture analysis.

## AI limitations

An AI model may later explain already-established deterministic findings, summarize them or generate investigation guidance.

It must not fabricate primary packet observations or become the authority deciding whether a loop, LACP failure, STP fault, retransmission problem or MLAG condition exists.

## Security and privacy limitations

Packet captures can contain:

- credentials;
- tokens;
- cookies;
- personal data;
- internal IP addresses;
- DNS names;
- file content;
- application payloads.

Local-first operation reduces mandatory disclosure to third parties but does not remove the operator's responsibility to secure storage, reports, backups and exported evidence.

## Current maturity: 0.1.0

TraceSleuth `0.1.0` is a bootstrap line.

It does not yet claim the target capture-quality engine, normalized finding/evidence model, Layer-2 loop engine, LACP analysis, MLAG symptom framework, generalized multi-capture model or production hardening as complete.

The inherited SD-WAN Triage functionality remains present while the architecture migrates in controlled phases.

## Honest status language

Use:

```text
implemented
experimental
beta
stable
planned
deferred
not supported
```

Do not use `stable` merely because code compiles.

A detector is complete only when its documented acceptance criteria, evidence model, positive/negative/false-positive fixtures, boundaries, limitations and presentation requirements are satisfied.
