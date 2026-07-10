# Scope and limitations

## Product mission

TraceSleuth is an open-source PCAP analysis platform intended to identify, correlate, explain, and present evidence-backed network faults, anomalies, protocol issues, loops, redundancy failures, and other network pathologies.

The core question is:

> What looks wrong in this capture, what evidence supports that conclusion, how confident are we, what else could explain it, and which packets should the engineer inspect?

## Intended environments

TraceSleuth is intended for:

- campus networks;
- data centers;
- enterprise LANs;
- WANs;
- SD-WAN environments;
- traditional routed networks;
- Internet edges;
- server networks;
- highly redundant LACP/MLAG architectures;
- voice networks;
- multi-vendor environments.

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

## Packet captures are partial observations

A PCAP does not automatically reveal the complete network state.

A capture may lack:

- one traffic direction;
- Layer-2 headers;
- ingress interface identity;
- PCAPNG interface metadata;
- STP/LACP/LLDP/CDP control traffic;
- packets dropped before the capture point;
- packets dropped by the capture mechanism;
- switch forwarding-table state;
- switch logs;
- MLAG peer-link state;
- device configuration;
- path topology;
- accurate synchronized clocks;
- encrypted control-plane content;
- events that occurred before capture start.

TraceSleuth must not infer more than the available evidence supports.

## Capture quality can invalidate diagnosis

Examples:

- heavy truncation may hide protocol fields;
- timestamp disorder may invalidate recurrence/latency analysis;
- fixed-factor duplicate capture may resemble packet duplication in the network;
- missing Ethernet headers make many L2 conclusions impossible;
- unsynchronized multi-capture clocks invalidate precise one-way latency;
- capture loss may resemble network packet loss.

The capture-quality layer is therefore a prerequisite for high-confidence diagnosis.

## L2 loop limitations

Repeated frames do not automatically prove a switching loop.

Alternative explanations include:

- SPAN source configuration;
- multiple SPAN source ports;
- capturing both sides of a link;
- port-channel member capture;
- packet brokers;
- ERSPAN duplication;
- TAP aggregation;
- NIC/offload effects;
- legitimate application retransmission;
- intentional packet replication;
- redundancy behavior.

A critical loop finding should generally require multiple independent signals unless one definitive protocol violation exists.

## Unknown-unicast limitations

A single passive capture usually does not expose the switch MAC address table. TraceSleuth may identify symptoms compatible with unknown-unicast flooding only when visibility is sufficient. It must not claim knowledge of forwarding-table contents it cannot observe.

## Spanning-tree limitations

A PCAP may expose BPDUs, root identity, sender bridge identity, costs, flags, timers, and transitions. It does not necessarily reveal:

- the complete physical topology;
- every bridge;
- every blocked port;
- switch configuration;
- which unobserved physical port is forwarding or blocking.

TraceSleuth must not claim a specific physical switch port is blocking unless that information is directly observable or supplied through external metadata.

## LACP limitations

LACP packets expose actor and partner state. They do not necessarily prove the physical cause of instability.

Observed partner-ID changes or synchronization loss may be caused by:

- legitimate failover;
- member link instability;
- port-channel mismatch;
- MLAG identity inconsistency;
- device reboot;
- capture across unrelated links;
- incomplete capture visibility.

Findings must list relevant alternatives.

## MLAG limitations

MLAG is not one universal standardized wire protocol. Different vendors implement different control planes and expose different information.

TraceSleuth therefore uses an **MLAG symptom inference framework**, not a fake universal MLAG parser.

Possible evidence classes:

### Direct evidence

- vendor-specific protocol explicitly exposes an MLAG state;
- documented vendor TLVs expose peer identity/state;
- future supplementary telemetry explicitly reports state.

### Strong indirect evidence

- duplicate unicast forwarding across independently identified capture interfaces;
- incompatible LACP partner identity behavior;
- duplicate flow without corresponding sender retransmission;
- FHRP multiple-active behavior;
- correlated LACP and topology changes.

### Weak indirect evidence

- generic duplicate packets;
- one LACP state transition;
- isolated broadcast spike.

Weak evidence alone must not produce a critical MLAG conclusion.

TraceSleuth should say:

```text
Evidence is consistent with a multi-chassis forwarding inconsistency.
Possible causes include split-brain, peer-link failure, keepalive failure,
VLAN inconsistency, orphan-port behavior, member failure, LACP mismatch,
STP interaction, or capture duplication.
```

It should not say:

```text
MLAG peer link is down.
```

unless directly supported.

## Packet-loss limitations

Generic UDP traffic does not inherently contain sequence numbers. TraceSleuth must not invent packet-loss percentages unless:

- the protocol exposes sequence information;
- multiple synchronized capture points enable direct correlation;
- another explicit mechanism makes loss measurable.

Capture loss must be considered as an alternative explanation.

## TCP limitations

TCP retransmission analysis can be confounded by:

- capture duplication;
- packet reordering;
- offloading;
- missing packets in the capture;
- one-sided visibility;
- timestamp disorder;
- asymmetric capture points.

TraceSleuth must distinguish network retransmission, sender behavior, and capture artifacts where possible.

## Latency limitations

A single capture can often estimate round-trip timing for suitable protocols. Multi-capture one-way latency requires synchronized clocks or explicit offset estimation.

TraceSleuth must not display microsecond-accurate one-way delay when clock uncertainty exceeds that precision.

## DNS limitations

A DNS timeout observed at one capture point does not automatically prove the DNS server failed. Possible causes include:

- request loss;
- response loss;
- asymmetric path visibility;
- capture loss;
- filtering;
- server delay;
- client retry behavior.

## DHCP limitations

Multiple DHCP servers are not automatically malicious or rogue. Legitimate redundant designs exist.

TraceSleuth should describe competing or conflicting offer behavior precisely and avoid attributing malicious intent without evidence.

## ARP/ND limitations

An IP-to-MAC mapping change is not automatically spoofing. Legitimate causes include:

- failover;
- FHRP movement;
- host migration;
- NIC replacement;
- clustering;
- proxy ARP;
- virtualization.

Context and rate matter.

## Vendor identification limitations

Vendor identity may be enriched through:

- MAC OUI;
- LLDP organizationally specific TLVs;
- CDP;
- protocol extensions;
- explicit metadata.

TraceSleuth must not infer vendor identity merely because an address uses a private range or resembles a common default.

## Encrypted traffic

Encryption limits payload visibility. TraceSleuth can still analyze observable metadata, timing, packet sizes, handshakes, transport behavior, and outer encapsulation, but it must state when encryption prevents deeper analysis.

Optional key-log support is sensitive and must be handled as untrusted secret-bearing input.

## Offline operation

Core capture analysis must work without Internet access, cloud services, external APIs, or AI models.

Optional external lookups or integrations may exist only when explicit and documented. Their absence must not disable core diagnosis.

## AI limitations

An AI model may later:

- explain findings;
- summarize multiple findings;
- generate investigation guidance;
- convert technical output into an executive summary.

It must not fabricate the observation, evidence, packet references, protocol fields, or detector result.

## Current pre-1.0 limitations

The imported baseline is undergoing transformation. As of the `0.1.0` bootstrap:

- product-facing code still contains inherited SD-WAN Triage names;
- the executable is not yet `tracesleuth`;
- the Go module path remains upstream;
- version values are not yet unified in code;
- capture-quality preflight is not implemented;
- normalized observation and evidence models are not implemented;
- stable detector IDs/versions are not implemented;
- LACP analysis is not implemented;
- MLAG symptom inference is not implemented;
- generalized multi-capture correlation is not implemented;
- inherited authentication/upload security defects remain to be fixed;
- not all inherited detectors have adequate false-positive fixtures.

The baseline audit is authoritative for the current imported state.

## Maturity vocabulary

Detectors use:

```text
experimental
beta
stable
```

A detector is not stable merely because source code exists.

Stable detectors require documented algorithms, positive/negative tests, false-positive tests where relevant, boundary tests, confidence/limitations documentation, Wireshark validation guidance, JSON/UI presentation, packet evidence references, and changelog coverage.

## Final principle

When evidence is insufficient, TraceSleuth should say so.

An honest limitation is more useful than a confident unsupported diagnosis.