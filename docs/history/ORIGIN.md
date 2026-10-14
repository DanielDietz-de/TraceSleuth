# Origin and evolution

## From SD-WAN Triage to TraceSleuth

TraceSleuth originated from the open-source **SD-WAN Triage** project maintained by Gocisse and distributed under the MIT License.

The exact TraceSleuth source baseline is upstream commit:

```text
43c6cd412860a5219577be6d30feca2db7f57309
```

That commit is one upstream commit after the `v6.2.0.0` tag. The release tag points to `2855ef6d1cd26909e70e60b893c13341efab9767`; the following upstream commit added the upstream `README.md` and `LICENSE`. The source was imported into TraceSleuth on 2026-07-09 as TraceSleuth commit `da35429b7284bb6a2bc61f2049209dfff299703c`.

The authoritative provenance record is `UPSTREAM.md`.

## What the upstream project contributed

The imported codebase already provided substantial engineering value. Important inherited capabilities include:

- offline PCAP processing;
- PCAP and PCAPNG handling through Go packet-processing components;
- a Go backend and React/Vite frontend;
- a local web application and CLI;
- JSON, HTML, CSV and report-generation functionality;
- packet inspection and stream views;
- TCP handshake, retransmission, RTT and other transport analysis;
- protocol analysis spanning DNS, DHCP, NTP, ARP, ICMP, HTTP, TLS, QUIC, SIP, RTP and several tunnel protocols;
- existing LAN protocol support for VRRP, HSRP, STP, LLDP and CDP;
- SD-WAN vendor heuristics;
- a streaming LAN/WAN comparison engine;
- timeline and troubleshooting workflows; and
- a set of unit and integration tests.

TraceSleuth intentionally preserves useful inherited functionality unless correctness, security, maintainability, or the new product mission requires a change.

## Why TraceSleuth is a separate product

The primary mission changes materially.

SD-WAN Triage centered on SD-WAN troubleshooting, security analysis, network health reporting and LAN/WAN comparison. TraceSleuth is being developed as a general-purpose, deterministic-first network fault-analysis platform whose central question is:

> What looks wrong in this capture, what evidence supports that conclusion, how confident are we, what else could explain it, and which packets should the engineer inspect?

TraceSleuth therefore requires a broader architecture and stronger epistemic controls. Planned differentiation includes:

- capture-integrity analysis before fault diagnosis;
- normalized packet and protocol observations;
- a first-class finding and evidence model;
- explicit distinction between observed facts, strong inference, probability, possibility and information;
- packet-number and timestamp references for important conclusions;
- detector prerequisites and capture-capability declarations;
- confidence scoring with explainable contributions and penalties;
- correlation across independent detectors;
- exact and normalized frame fingerprinting;
- dedicated capture-duplication detection for SPAN and packet-broker false-positive control;
- Layer-2 loop and storm analysis;
- deeper STP/RSTP/MSTP and vendor spanning-tree analysis;
- full LACP state analysis;
- MLAG symptom inference that never pretends MLAG is a single standardized protocol;
- topology reasoning from directly observed and inferred relationships;
- generalized multi-capture correlation beyond a fixed LAN/WAN model;
- evidence-only PCAP export and Wireshark validation workflows;
- secure, configurable retention and resource limits; and
- an independent semantic-versioning and release lifecycle.

## Architectural evolution policy

TraceSleuth will evolve incrementally rather than through an uncontrolled rewrite. Existing code that is correct and well-structured should be adapted. Existing defects, duplicated abstractions, insecure defaults, unbounded state, unsupported conclusions, and misleading certainty should not be preserved merely for upstream compatibility.

Major architecture decisions are recorded as ADRs under `docs/architecture/adr/`.

## Independence and attribution

TraceSleuth is an independent downstream project. It does not claim endorsement by Gocisse or the SD-WAN Triage project.

The original MIT license and copyright notice remain legally and historically significant and must be preserved. Historical references to SD-WAN Triage are intentional and must not be removed by blind product-name replacement.
