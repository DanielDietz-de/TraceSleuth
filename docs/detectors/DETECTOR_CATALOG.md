# Detector catalogue

## Status of this catalogue

TraceSleuth `0.1.0` is a bootstrap release line. The inherited SD-WAN Triage code contains many analyzers and heuristics, but **no detector is automatically promoted to TraceSleuth stable status merely because code exists**.

The catalogue therefore distinguishes:

```text
inherited-unclassified  code exists in the imported baseline but has not completed TraceSleuth detector acceptance
experimental            TraceSleuth detector exists but validation is incomplete
beta                    substantial validation exists; behavior/schema may still change
stable                  complete acceptance criteria are satisfied
planned                 design/roadmap item; not implemented
```

The target maturity vocabulary exposed to end users should eventually use `experimental`, `beta`, and `stable`. `inherited-unclassified` is a migration-only label and must not be interpreted as a product capability guarantee.

## Stable detector definition of done

A stable detector requires:

- unique stable ID;
- detector version;
- description;
- implemented algorithm;
- declared required observations;
- declared required capture capabilities;
- positive PCAP fixture;
- negative PCAP fixture;
- false-positive fixture where relevant;
- unit tests;
- boundary tests;
- confidence documentation;
- limitations documentation;
- valid Wireshark validation filter;
- UI presentation;
- JSON output;
- evidence packet references;
- changelog entry.

High-risk loop and MLAG symptom detectors require multiple adversarial false-positive fixtures.

## Priority target detector catalogue

The following IDs are the intended target catalogue. IDs may be adjusted before implementation when package/API design requires it, but once declared stable they become compatibility identifiers.

### Capture trust

| Proposed detector ID | Display name | Purpose | Status |
|---|---|---|---|
| `capture.integrity` | Capture integrity | Summarize format, malformed input, parser failures, file truncation, interfaces, timestamps, snap length, and other trust signals. | planned |
| `capture.truncation` | Packet truncation | Measure truncated packet count/rate and affected parsing capabilities. | planned |
| `capture.timestamp_anomaly` | Timestamp anomaly | Detect non-monotonic timestamps, jumps, coarse resolution, and suspicious gaps. | planned |
| `capture.duplication.fixed_factor` | Capture duplication | Identify stable exact-copy patterns consistent with SPAN, packet broker, TAP, or multi-source capture duplication. | planned |
| `capture.unsupported_link_type` | Unsupported link-layer type | Report unsupported or capability-limiting link types. | planned |

### Layer 2

| Proposed detector ID | Display name | Purpose | Status |
|---|---|---|---|
| `l2.frame_duplicate_storm` | Exact duplicate frame storm | Detect repeated exact Ethernet frame fingerprints and bursts/amplification. | planned |
| `l2.broadcast_storm` | Broadcast storm | Detect abnormal broadcast rate, bandwidth, acceleration, and dominant contributors. | planned |
| `l2.multicast_storm` | Multicast storm | Detect abnormal multicast rate/replication while resisting normal multicast-heavy workloads. | planned |
| `l2.probable_forwarding_loop` | Probable Layer-2 forwarding loop | Correlate independent frame recurrence, traffic amplification, ARP/ND repetition, STP changes, and capture-duplication alternatives. | planned |
| `arp.storm` | ARP storm | Detect excessive ARP request/reply/gratuitous-ARP behavior with baseline and loop correlation. | planned |
| `arp.mapping_conflict` | Conflicting ARP mapping | Detect IP-to-MAC conflicts and mapping churn without automatically labeling every change as spoofing. | inherited-unclassified |
| `nd.mapping_conflict` | Conflicting IPv6 neighbor mapping | Detect incompatible IPv6 neighbor mappings where observable. | planned |
| `nd.excessive_traffic` | Excessive IPv6 ND traffic | Detect excessive NS/NA/RS/RA behavior with context. | planned |

### Spanning tree

| Proposed detector ID | Display name | Purpose | Status |
|---|---|---|---|
| `stp.root_change` | STP root bridge change | Report observed root bridge identity changes. | planned |
| `stp.root_flapping` | STP root flapping | Detect frequent root changes in a time window. | planned |
| `stp.topology_change_storm` | STP topology-change storm | Detect excessive topology-change indications. | inherited-unclassified |
| `stp.tcn_storm` | STP TCN storm | Detect excessive legacy TCN BPDU behavior where observable. | inherited-unclassified |
| `stp.bpdu_timing_anomaly` | BPDU timing anomaly | Detect BPDU interval/timer behavior inconsistent with observed protocol state. | planned |
| `stp.multiple_apparent_roots` | Multiple apparent STP roots | Report incompatible apparent roots with VLAN/instance/capture context. | planned |

### LACP and redundancy

| Proposed detector ID | Display name | Purpose | Status |
|---|---|---|---|
| `lacp.partner_instability` | LACP partner instability | Detect observed partner system identity changes and churn. | planned |
| `lacp.key_mismatch` | LACP key mismatch | Detect actor/partner or member key inconsistencies where context permits. | planned |
| `lacp.synchronization_loss` | LACP synchronization loss | Track synchronization state loss and recovery. | planned |
| `lacp.collecting_distributing_loss` | LACP collecting/distributing loss | Track loss of forwarding-state bits. | planned |
| `lacp.defaulted_expired` | LACP defaulted/expired state | Detect observed defaulted or expired partner behavior. | planned |
| `redundancy.duplicate_forwarding` | Probable duplicate forwarding | Detect same unicast traffic through redundant paths without corresponding sender retransmission. | planned |
| `redundancy.multichassis_inconsistency` | Probable multi-chassis forwarding inconsistency | Correlate LACP, duplicate forwarding, FHRP, topology, and capture-point evidence. | planned |
| `fhrp.multiple_active` | FHRP multiple-active symptoms | Detect simultaneous active/master claims where protocol evidence permits. | planned |
| `vrrp.flapping` | VRRP master/priority instability | Detect excessive observed VRRP changes. | inherited-unclassified |
| `hsrp.flapping` | HSRP state/active instability | Detect excessive HSRP transitions or active changes. | inherited-unclassified |

### Transport

| Proposed detector ID | Display name | Purpose | Status |
|---|---|---|---|
| `tcp.failed_handshake` | Failed TCP handshake | Detect incomplete/retried/refused/reset connection establishment. | inherited-unclassified |
| `tcp.syn_retry_storm` | SYN retransmission storm | Detect excessive SYN retries with capture-duplication safeguards. | inherited-unclassified |
| `tcp.retransmission_anomaly` | TCP retransmission anomaly | Detect retransmission behavior while separating duplicate capture, reordering, and sender behavior. | inherited-unclassified |
| `tcp.duplicate_ack_storm` | Duplicate ACK storm | Detect excessive duplicate acknowledgements in flow context. | planned |
| `tcp.zero_window` | TCP zero window | Report observed advertised zero-window conditions and duration. | inherited-unclassified |
| `tcp.window_exhaustion` | TCP receive-window exhaustion | Detect small/collapsing receive-window behavior with scaling/context. | inherited-unclassified |
| `tcp.rtt_anomaly` | TCP RTT anomaly | Detect excessive or spiking RTT with sample count and timing limits. | inherited-unclassified |
| `tcp.connection_reset_anomaly` | TCP reset anomaly | Detect excessive or contextually abnormal reset behavior. | inherited-unclassified |

### Network services

| Proposed detector ID | Display name | Purpose | Status |
|---|---|---|---|
| `dns.transaction_timeout_retry` | DNS timeout/retry | Detect unanswered queries and retries through transaction correlation. | inherited-unclassified |
| `dns.latency_anomaly` | DNS latency anomaly | Detect high response latency using measured request/response timing. | inherited-unclassified |
| `dhcp.competing_server_behavior` | DHCP competing-server behavior | Report multiple offer/server behavior without automatically alleging malicious intent. | inherited-unclassified |
| `dhcp.allocation_failure` | DHCP allocation failure | Detect failed/incomplete allocation sequences, NAK storms, and retries. | inherited-unclassified |
| `ntp.anomaly` | NTP anomaly | Report protocol anomalies, instability, and suspicious amplification-related behavior with explicit context. | inherited-unclassified |

## Inherited detector inventory

The source-level baseline audit is authoritative for exact source paths, thresholds, state, tests, and dispositions. This section provides a concise catalogue mapping.

### `pkg/detector/arp.go`

- **Target detector ID:** `arp.mapping_conflict`
- **Domain:** ARP
- **Current behavior:** observes ARP replies; reports an IP when a later reply maps the same IP to a different source MAC.
- **Evidence used:** ARP reply source protocol address and source hardware address.
- **State:** IP-to-MAC map.
- **Threshold:** none.
- **Current status:** `inherited-unclassified`.
- **Limitations:** mapping changes can be legitimate because of FHRP, failover, VM mobility, proxy behavior, network changes, or incomplete capture context. Current output is not yet normalized to TraceSleuth packet references/alternatives/limitations.
- **Required action:** retain direct mapping observations; redesign diagnosis and add positive, negative, failover, proxy, and FHRP fixtures.

### `pkg/detector/bgp.go`

- **Domain:** BGP/security indicator logic.
- **Current status:** `inherited-unclassified`.
- **Tests identified:** `bgp_test.go`.
- **Required action:** re-audit standards correctness, packet evidence, scope, and whether behavior belongs to routing pathology, security enrichment, or both.

### `pkg/detector/c2_beaconing.go`

- **Domain:** security/traffic timing.
- **Current behavior:** identifies periodic communication patterns interpreted as possible C2 beaconing.
- **Current status:** `inherited-unclassified`.
- **Tests identified:** `c2_beaconing_test.go`.
- **Nature:** heuristic.
- **Required action:** keep optional security signal separate from network-fault authority; document alternatives and false positives.

### `pkg/detector/common.go`

- **Domain:** shared packet helpers.
- **Current status:** infrastructure, not a detector.
- **Tests identified:** `common_test.go`.
- **Disposition:** migrate reusable parsing into normalized protocol/observation packages.

### `pkg/detector/ddos.go`

- **Domain:** traffic storms/security.
- **Current thresholds:** 100 SYN-without-ACK packets, 200 UDP packets, 100 ICMP packets in a nominal 10-second window.
- **Current status:** `inherited-unclassified`.
- **Tests identified:** `ddos_test.go`.
- **Limitations:** volume thresholds alone do not prove an attack; capture scope and baseline matter.
- **Disposition:** separate directly measured rates from attack attribution.

### `pkg/detector/dhcp.go`

- **Target IDs:** `dhcp.competing_server_behavior`, `dhcp.allocation_failure`.
- **Domain:** DHCP.
- **Current behavior:** tracks DISCOVER volume, OFFER sources, and NAK volume.
- **Current thresholds:** 50 DISCOVER messages per MAC, 10 NAKs, 60-second reset window.
- **Critical baseline issue:** any second observed DHCP server can be labeled a critical rogue server.
- **Current status:** `inherited-unclassified`.
- **Tests identified:** `dhcp_test.go`.
- **Required action:** remove malicious-intent implication from multiplicity alone; add transaction/context correlation, relay awareness, and legitimate multi-server fixtures.

### `pkg/detector/dns.go`

- **Target IDs:** `dns.transaction_timeout_retry`, `dns.latency_anomaly`, plus optional separate security heuristics.
- **Domain:** DNS.
- **Current behavior:** tracks DNS details and applies hard-coded resolver, public-domain/private-IP, TLD, label-count, and domain-length heuristics.
- **Current status:** `inherited-unclassified`.
- **Limitations:** split DNS, enterprise resolvers, CDNs, lab domains, internal namespaces, and legitimate long/deep names can invalidate categorical conclusions.
- **Required action:** separate deterministic transaction/error/latency analysis from optional security heuristics.

### `pkg/detector/dns_tunneling.go`

- **Domain:** DNS/security.
- **Current status:** `inherited-unclassified`.
- **Nature:** heuristic.
- **Required action:** document entropy/length/rate logic, capture context, and adversarial false-positive fixtures before stable use.

### `pkg/detector/geoip.go`

- **Domain:** metadata enrichment.
- **Current status:** `inherited-unclassified` informational enrichment.
- **Required action:** keep optional and local where configured; document database source, license, update behavior, and privacy.

### `pkg/detector/http.go`

- **Domain:** HTTP.
- **Current status:** `inherited-unclassified`.
- **Disposition:** preserve correct protocol facts; emit normalized service observations and explicit transaction evidence.

### `pkg/detector/icmp.go`

- **Domain:** ICMPv4.
- **Current status:** `inherited-unclassified`.
- **Disposition:** preserve error observations and add correlation with path, PMTUD, unreachable, and routing-loop evidence.

### `pkg/detector/icmpv6.go`

- **Domain:** ICMPv6.
- **Current status:** `inherited-unclassified`.
- **Disposition:** preserve correct observations; integrate with IPv6 ND and packet-too-big/path analysis.

### `pkg/detector/ioc.go`

- **Domain:** threat intelligence.
- **Current status:** `inherited-unclassified` optional security enrichment.
- **Disposition:** not part of core network-fault authority; feed source and freshness must be explicit.

### `pkg/detector/ipv6.go`

- **Domain:** IPv6.
- **Current status:** `inherited-unclassified`.
- **Disposition:** preserve correct parsing and expand ND/hop-limit evidence in normalized packages.

### `pkg/detector/lan_protocols.go`

- **Domains:** VRRP, HSRP, STP, CDP, LLDP.
- **Current behavior:** one combined analyzer tracks protocol-specific maps and basic state changes.
- **Current status:** `inherited-unclassified`.
- **Limitations:** combined state obscures protocol boundaries; maps require bounded-state review; packet evidence and capture prerequisites are not normalized.
- **Disposition:** split into protocol observations and independent detectors.

### `pkg/detector/ntp.go`

- **Target ID:** `ntp.anomaly`.
- **Current thresholds:** response size at least 468 bytes; 10 large responses; 3 stratum changes.
- **Current status:** `inherited-unclassified`.
- **Tests identified:** `ntp_test.go`.
- **Limitations:** large responses or mode behavior do not prove malicious attack intent without context.

### `pkg/detector/portscan.go`

- **Domain:** security.
- **Current status:** `inherited-unclassified`.
- **Disposition:** optional security detector; require timing, scope, alternatives, and scanner/monitoring false-positive fixtures.

### `pkg/detector/qos.go`

- **Domain:** QoS/DSCP.
- **Current status:** `inherited-unclassified`.
- **Disposition:** preserve observed markings; require policy or multi-capture context before calling a marking a fault.

### `pkg/detector/quic.go`

- **Domain:** QUIC.
- **Current status:** `inherited-unclassified`.
- **Disposition:** preserve correct parsing/traffic identification; faults require evidence-specific design.

### `pkg/detector/rtp.go`

- **Domain:** RTP/voice.
- **Current behavior:** heuristic RTP identification, SSRC/sequence tracking, loss/reordering/jitter metrics.
- **Current minimum:** five packets.
- **Known simplification:** jitter calculation assumes an 8 kHz clock in the inherited implementation.
- **Current status:** `inherited-unclassified`.
- **Disposition:** make codec/clock-rate context explicit and add positive/negative sequence fixtures before stable quality claims.

### `pkg/detector/sdwan_vendor.go`

- **Domain:** vendor inference/enrichment.
- **Current status:** `inherited-unclassified`.
- **Disposition:** preserve useful behavior where correct but isolate vendor enrichment from generic protocol analyzers and never infer a vendor from unrelated private-IP ranges.

### `pkg/detector/sip.go`

- **Domain:** SIP/voice signaling.
- **Current status:** `inherited-unclassified`.
- **Disposition:** preserve correct call-state observations and correlate with RTP evidence.

### `pkg/detector/stability_monitor.go`

- **Domains:** BFD, IKE, STP.
- **Current thresholds:** more than 3 BFD state transitions in 60 seconds; more than 3 IKE SA-init events in 60 seconds; more than 5 STP TCN BPDUs.
- **Current status:** `inherited-unclassified`.
- **Disposition:** split by protocol, add packet references, explicit time windows, capture limitations, and boundary tests.

### `pkg/detector/tcp.go`

- **Domains:** TCP handshake/retransmission/RTT/device fingerprinting.
- **Current behavior:** same-sequence payload retransmission heuristic, handshake tracking, RTT, fingerprints.
- **Current default RTT callback threshold:** 200 ms.
- **Current status:** `inherited-unclassified`.
- **Disposition:** preserve useful flow state but integrate capture-duplication, timestamp, reordering, one-sided capture, and packet-reference context.

### `pkg/detector/tcp_advanced.go`

- **Target IDs:** `tcp.zero_window`, `tcp.window_exhaustion`, future out-of-order finding.
- **Current thresholds:** 3 zero windows; 5 windows at or below 1024; out-of-order at least 10 packets, at least 2%, and at least 20 total packets; greater than 10% treated as critical.
- **Current status:** `inherited-unclassified`.
- **Limitations:** receive-window scaling, capture duplication, retransmission, timestamp disorder, and ordinary reordering require stronger handling.

### `pkg/detector/tcp_handshake.go`

- **Target ID:** `tcp.failed_handshake`.
- **Domain:** TCP connection establishment.
- **Current status:** `inherited-unclassified`.
- **Tests identified:** `tcp_handshake_test.go`.
- **Disposition:** preserve deterministic handshake state; add normalized packet evidence and capture limitation handling.

### `pkg/detector/tls.go`

- **Domain:** TLS.
- **Current status:** `inherited-unclassified`.
- **Disposition:** preserve directly decoded facts; keep policy/security interpretations separate.

### `pkg/detector/tls_ja3.go`

- **Domain:** TLS fingerprint enrichment.
- **Current status:** `inherited-unclassified`.
- **Disposition:** verify canonical fingerprint generation and treat as enrichment, not standalone fault authority.

### `pkg/detector/tls_security.go`

- **Domain:** TLS/security heuristics.
- **Current status:** `inherited-unclassified`.
- **Disposition:** separate protocol facts, policy assumptions, and threat heuristics; document false-positive risks.

### `pkg/detector/traffic.go`

- **Domain:** traffic classification/statistics.
- **Current status:** infrastructure/inherited analysis.
- **Disposition:** preserve useful statistics but do not conflate traffic distribution with faults.

### `pkg/detector/tunnel.go`

- **Domain:** tunnels/encapsulation.
- **Current status:** `inherited-unclassified`.
- **Tests identified:** `tunnel_test.go`.
- **Disposition:** preserve correct identification and move transformations into normalized multi-capture analysis.

## Secondary inherited namespace: `pkg/detectors`

### `kerberos.go`

- **Domain:** Kerberos.
- **Current status:** `inherited-unclassified`.
- **Concern:** lives in a second detector namespace.
- **Disposition:** consolidate architecture and preserve correct protocol facts.

### `ldap.go`

- **Domain:** LDAP.
- **Current status:** `inherited-unclassified`.
- **Concern:** duplicate detector namespace.

### `packet_loss.go`

- **Domain:** packet-loss inference.
- **Current status:** `inherited-unclassified`.
- **High-risk limitation:** ordinary UDP loss percentages must not be invented without protocol sequence numbers, synchronized multi-capture evidence, or another direct mechanism.
- **Disposition:** re-audit algorithm before any stable claim.

### `smb.go`

- **Domain:** SMB.
- **Current status:** `inherited-unclassified`.
- **Concern:** duplicate detector namespace.

## Detector-adjacent inherited analyzers

### `pkg/analyzer/security_detector.go`

Higher-level security finding logic. It must remain separate from authoritative network-pathology conclusions unless it consumes normalized evidence with explicit semantics.

### `pkg/analyzer/issue_detector_core.go`

Core issue generation. Current findings are not yet emitted through the normalized evidence schema.

### `pkg/analyzer/issue_detector_infra.go`

Infrastructure issue generation requiring migration to normalized findings.

### `pkg/analyzer/issue_detector_m365.go`

Microsoft 365-specific issue logic. Product-specific assumptions should likely become optional profiles/rules rather than core network-fault semantics.

### `pkg/analyzer/issue_detector_transport.go`

Transport issue generation requiring packet references, capture-quality penalties, stable IDs, and detector versions.

### `pkg/analyzer/correlator.go`

Contains useful correlation/root-cause-chain concepts but does not yet implement the versioned explainable contribution model defined by TraceSleuth.

## Required catalogue fields after migration

Each implemented TraceSleuth detector entry will include:

```text
Detector ID
Display name
Detector version
Category
Maturity
Purpose
Protocols
Required observations
Required capture context/capabilities
Algorithm summary
Default thresholds
State requirements and bounds
Confidence model
Certainty ceiling
False-positive risks
False-negative risks
Capture limitations
Wireshark filters
Positive fixture
Negative fixture
False-positive fixture(s)
Standards references
JSON/API schema status
UI status
```

## Standards references

No detector should cite a standard merely to look authoritative. Standards and vendor references must be verified against actual behavior implemented by the parser/detector.

## Current conclusion

TraceSleuth `0.1.0` has a broad inherited analysis base, but the stable TraceSleuth detector catalogue remains intentionally empty until detectors satisfy the evidence, tests, limitations, packet-reference, confidence, UI, JSON, and documentation acceptance criteria.
