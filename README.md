# TraceSleuth

**Packets tell the story. TraceSleuth finds the problem.**

TraceSleuth is an open-source PCAP analysis platform that automatically detects network faults, anomalies, protocol issues, loops, redundancy failures, and other network pathologies.

> **Primary product promise:** Upload or analyze a packet capture and receive evidence-backed findings showing what appears wrong, why TraceSleuth reached that conclusion, which packets support it, how confident the diagnosis is, what alternative explanations exist, and how to validate the result independently.

[![Version](https://img.shields.io/badge/version-0.1.0-blue)](VERSION)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Maturity](https://img.shields.io/badge/maturity-bootstrap%20%2F%20pre--1.0-orange)](ROADMAP.md)

## Current maturity

**TraceSleuth 0.1.0 is a bootstrap and architecture-foundation release line. It is not yet production-ready.**

The repository was imported from the MIT-licensed [SD-WAN Triage](https://github.com/gocisse/sdwan-triage) project and already contains substantial inherited PCAP analysis, web, CLI, packet inspection, reporting, protocol analysis, timeline, voice, security, and streaming comparison functionality.

TraceSleuth is now evolving into a distinct deterministic-first network fault-analysis product. The exact baseline, architecture, detector inventory, security findings, technical debt, and migration plan are documented in the [initial baseline audit](docs/audits/INITIAL_BASELINE_AUDIT.md).

Do not interpret roadmap entries as implemented features. A detector is considered stable only after it meets the documented acceptance criteria for algorithm behavior, packet evidence, positive and negative PCAP fixtures, adversarial false-positive tests where relevant, boundary tests, confidence, limitations, Wireshark validation, JSON output, UI presentation, catalogue entry, and changelog coverage.

## Product identity

**Name:** TraceSleuth

**Tagline:** Packets tell the story. TraceSleuth finds the problem.

**Repository description:**

> TraceSleuth is an open-source PCAP analysis platform that automatically detects network faults, anomalies, protocol issues, loops, redundancy failures, and other network pathologies.

## What TraceSleuth is designed to diagnose

The target product scope includes:

- Layer-2 loops and forwarding-loop symptoms.
- Broadcast, multicast, exact-duplicate, and selected near-duplicate frame storms.
- SPAN, mirror, TAP, ERSPAN, packet-broker, and capture-duplication symptoms that could otherwise cause false loop diagnoses.
- STP, RSTP, MSTP, PVST+, and Rapid-PVST symptoms where observable.
- LACP actor/partner identity, key, synchronization, collecting/distributing, timeout, defaulted, expired, and churn conditions.
- Redundancy failures and MLAG-related symptoms without pretending MLAG is one universal wire protocol.
- ARP, IPv6 Neighbor Discovery, VRRP, HSRP, LLDP, and CDP anomalies.
- Routing-loop symptoms, TTL/hop-limit anomalies, ICMP errors, fragmentation, and PMTUD problems.
- TCP handshakes, SYN retries, retransmissions, duplicate ACKs, out-of-order segments, zero windows, receive-window exhaustion, resets, RTT, and stalls.
- DNS, DHCP, NTP, SIP, RTP, tunnel, and encapsulation anomalies.
- Multi-capture packet disappearance, duplication, modification, NAT, path changes, and delay attribution with explicit clock uncertainty.
- Capture-quality problems that may invalidate or reduce confidence in other findings.

The intended environments include campus, data-center, enterprise LAN, WAN, SD-WAN, traditional routed, Internet edge, server, voice, multi-vendor, LACP, and highly redundant network architectures.

## Engineering principles

### Deterministic analysis first

Primary findings come from protocol parsing, state machines, packet correlation, frame fingerprinting, time-series analysis, standards-based validation, explicit deterministic rules, and documented heuristics.

An LLM or other generative model is never the primary authority deciding whether a switching loop, LACP failure, STP problem, retransmission problem, or other network pathology exists.

Optional AI may later explain deterministic findings or summarize them. TraceSleuth must remain fully functional without a cloud service, external API, Internet connection, telemetry, or AI model.

### Evidence before conclusion

A major finding should answer:

1. What was observed?
2. Which packets support it?
3. During what time range?
4. Which devices, MAC addresses, IP addresses, VLANs, capture points, interfaces, flows, or protocols were involved?
5. Why does the evidence indicate a problem?
6. How confident is TraceSleuth?
7. Is the condition directly observed or inferred?
8. Which alternative explanations exist?
9. Which capture limitations could invalidate the conclusion?
10. How can an engineer validate the result independently in Wireshark?
11. What should be investigated next?

### Fact, inference, and hypothesis are different

TraceSleuth uses the target certainty model:

```text
observed
strongly_inferred
probable
possible
informational
```

Example:

- An LACP partner system ID changed during the capture: **observed**.
- The behavior is consistent with link-aggregation instability: potentially **strongly inferred**.
- An MLAG peer-link failure caused it: generally only **possible** unless direct evidence proves it.

### False-positive resistance matters more than impressive claims

Duplicate frames can come from:

- multiple SPAN source ports;
- capturing both sides of a link;
- port-channel member capture;
- packet brokers;
- ERSPAN duplication;
- TAP aggregation;
- NIC offloading;
- legitimate application retransmission;
- redundancy mechanisms;
- intentional replication.

TraceSleuth must actively consider alternatives. Duplicate packets alone are not proof of a loop.

## Detector status

The initial stable TraceSleuth detector catalogue has **not yet been declared**. The inherited code contains broad analyzers, but they are being audited and migrated into the new evidence architecture.

| Domain | Current status | Notes |
|---|---|---|
| PCAP/PCAPNG reader | Implemented in inherited baseline | Magic-value detection and `pcapgo` readers exist; first-class capture-quality preflight remains roadmap work. |
| TCP analysis | Inherited / under validation | Handshake, retransmission, RTT, zero-window, small-window, and simplified out-of-order logic exist; evidence and false-positive controls require migration. |
| DNS/DHCP/NTP | Inherited / under validation | Existing heuristics are documented in the baseline audit; categorical conclusions are being replaced with evidence-backed semantics. |
| VRRP/HSRP/STP/CDP/LLDP | Inherited / under validation | Basic combined LAN-protocol analysis exists; deeper protocol-specific state analysis remains planned. |
| LACP | Planned | Not claimed implemented in 0.1.0. |
| Capture duplication | Planned | Required before high-confidence loop/duplicate-forwarding diagnosis. |
| Layer-2 loop engine | Planned | Must include adversarial SPAN/mirror false-positive fixtures. |
| MLAG symptom inference | Planned | Will distinguish direct, strong indirect, and weak indirect evidence. |
| Normalized finding/evidence model | Architecture defined | Implementation migration remains in progress. |
| Generalized multi-capture model | Planned | Inherited LAN/WAN comparison concepts will be generalized. |

See the [roadmap](ROADMAP.md) for phase acceptance criteria and the [baseline audit](docs/audits/INITIAL_BASELINE_AUDIT.md) for the source-level detector inventory.

## Example target finding

The following illustrates the intended output contract. It is **not** a claim that the final Layer-2 loop detector is already implemented in 0.1.0.

```text
CRITICAL — Probable Layer-2 forwarding loop

Confidence: 96
Certainty: strongly_inferred

Observed:
- 287,431 repeated Ethernet frames in 8.3 seconds.
- Broadcast rate increased from 42 pps to 31,872 pps.
- One ARP request fingerprint was observed 4,721 times.
- Median recurrence interval was 630 microseconds.
- An STP topology-change event occurred 112 ms before amplification began.

Alternative explanations considered:
- Multiple-source SPAN duplication.
- Packet-broker replication.
- Port-channel member mirroring.

Why they are less likely:
- Frame multiplicity increased over time instead of remaining at a fixed factor.
- Multiple independent broadcast fingerprints amplified.
- STP instability preceded the event.

Validation:
- Inspect the referenced packet numbers.
- Apply the supplied Wireshark filters.
- Review the stated time range and topology changes.
```

## Quick start from source

### Requirements

- Go version declared by `go.mod`.
- Node.js 24 for the frontend build.
- npm with the committed lockfile.
- `make` for the unified build path.

### Build

```bash
git clone https://github.com/DanielDietz-de/TraceSleuth.git
cd TraceSleuth
make build
```

The build creates:

```text
build/tracesleuth
```

The command source directory is still `cmd/sdwan-triage` during the controlled pre-1.0 migration, but the product binary is now `tracesleuth`. Historical source paths are not treated as proof of final product identity.

### Local web mode

Before the first authenticated web start, provide an initial administrator explicitly:

```bash
export TRACESLEUTH_BOOTSTRAP_ADMIN_USERNAME='admin'
export TRACESLEUTH_BOOTSTRAP_ADMIN_PASSWORD='replace-with-a-strong-unique-password'
./build/tracesleuth -web
```

The bootstrap password is hashed with bcrypt and is not written to logs. TraceSleuth no longer creates the inherited universal `admin/admin` credential.

After an administrator exists in the database, bootstrap variables are ignored for existing-user databases.

### CLI analysis

The inherited CLI syntax remains available during migration:

```bash
./build/tracesleuth capture.pcap
./build/tracesleuth -json capture.pcap > report.json
./build/tracesleuth -compare -lan capture-lan.pcap -wan capture-wan.pcap
```

The target first-class CLI model is:

```text
tracesleuth analyze capture.pcap
tracesleuth compare capture-a.pcap capture-b.pcap
tracesleuth serve
tracesleuth detectors list
tracesleuth version
```

Those target commands must not be assumed implemented until the CLI migration is complete.

## Current runtime architecture

The inherited runtime currently follows this shape:

```text
PCAP / PCAPNG
      |
      v
pcapgo capture reader
      |
      v
packet processor + detector registry
      |                     |
      |                     +--> shared analysis state
      v
legacy monolithic TriageReport
      |
      +--> CLI / JSON / HTML / UI

React frontend <--> Gin API <--> local storage and SQLite users
```

The target TraceSleuth architecture is:

```text
capture intake
      |
      v
capture trust and capabilities
      |
      v
normalized protocol observations
      |
      +--> deterministic detectors
      +--> topology evidence
      |
      v
structured evidence and findings
      |
      v
explainable correlation
      |
      +--> CLI / JSON / API / UI / reports / evidence export
```

See:

- [Architecture](docs/architecture/ARCHITECTURE.md)
- [Analysis pipeline](docs/architecture/ANALYSIS_PIPELINE.md)
- [Finding and evidence model](docs/architecture/FINDING_AND_EVIDENCE_MODEL.md)
- [Correlation engine](docs/architecture/CORRELATION_ENGINE.md)

## Security and privacy

Packet captures are untrusted input and may contain highly sensitive enterprise data, including credentials, tokens, cookies, personal information, internal IP addresses, DNS names, file content, and application payloads.

Current bootstrap security changes include:

- removal of the universal `admin/admin` first-run account;
- explicit environment-based first-administrator bootstrap;
- no password logging;
- fail-closed JWT secret generation with no hard-coded fallback;
- CI vulnerability, secret, race, build, and CodeQL checks.

Important hardening work remains before production-ready server deployment, including full upload filename/path hardening, resource budgets, configurable retention, secure non-loopback deployment behavior, parser fuzzing, storage quotas, comprehensive secure headers/CSRF review, and WebSocket token handling.

TraceSleuth is local-first. No mandatory cloud service or telemetry is part of the product mission.

## CI and quality gates

Pull requests and pushes to `main` are intended to run:

- version-contract validation;
- Go formatting verification;
- `go vet`;
- Go tests;
- Go race detector;
- frontend typecheck/build;
- frontend linting;
- frontend unit tests;
- embedded frontend/backend build verification;
- `govulncheck`;
- Gitleaks current-tree secret scan;
- CodeQL for Go and JavaScript/TypeScript.

A green badge is not accepted as a substitute for detector fixtures, evidence, limitations, or adversarial false-positive testing.

## Platform support

The inherited project has cross-platform build targets for:

| Platform | Architecture | Planned artifact name |
|---|---|---|
| Linux | amd64 | `tracesleuth-linux-amd64` |
| macOS | amd64 | `tracesleuth-darwin-amd64` |
| macOS | arm64 | `tracesleuth-darwin-arm64` |
| Windows | amd64 | `tracesleuth-windows-amd64.exe` |

These targets must be validated by release CI before being presented as supported stable release artifacts.

## Documentation

### Project and history

- [Roadmap](ROADMAP.md)
- [Upstream provenance](UPSTREAM.md)
- [Origin and evolution](docs/history/ORIGIN.md)
- [Initial baseline audit](docs/audits/INITIAL_BASELINE_AUDIT.md)
- [Versioning](docs/project/VERSIONING.md)
- [Release process](docs/project/RELEASE_PROCESS.md)
- [Scope and limitations](docs/project/SCOPE_AND_LIMITATIONS.md)

### Architecture

- [Architecture](docs/architecture/ARCHITECTURE.md)
- [Analysis pipeline](docs/architecture/ANALYSIS_PIPELINE.md)
- [Finding and evidence model](docs/architecture/FINDING_AND_EVIDENCE_MODEL.md)
- [Correlation engine](docs/architecture/CORRELATION_ENGINE.md)
- [Architecture decision records](docs/architecture/adr/)

### Development

- [Upstream workflow](docs/development/UPSTREAM_WORKFLOW.md)

Further operational, detector, testing, security, deployment, API, and usage documentation is added only when it contains useful maintained content; TraceSleuth does not create empty documents merely to satisfy a directory checklist.

## Roadmap

The controlled roadmap progresses through:

```text
Phase 0   Baseline and provenance
Phase 1   TraceSleuth bootstrap
Phase 2   Capture trust
Phase 3   Evidence architecture
Phase 4   Layer-2 diagnostics
Phase 5   Redundancy diagnostics
Phase 6   End-to-end network pathology
Phase 7   Multi-capture intelligence
Phase 8   Diagnostic experience
Phase 9   Production hardening
Phase 10  Stable 1.0 release
```

Each phase has explicit acceptance criteria in [ROADMAP.md](ROADMAP.md).

## Contributing

Contributions are welcome, especially in:

- protocol parsing and validation;
- synthetic PCAP fixture generation;
- negative and adversarial false-positive test cases;
- capture-quality analysis;
- Layer-2 fault detection;
- STP and LACP state analysis;
- multi-capture correlation;
- evidence UX;
- parser fuzzing;
- performance measurement;
- documentation validated against actual implementation.

Do not submit private customer or production packet captures to the public repository.

Before introducing a detector, review the architecture, evidence model, scope/limitations, roadmap, and baseline audit.

## Upstream attribution

TraceSleuth originated from the MIT-licensed **SD-WAN Triage** project by **Gocisse**:

- Upstream repository: `https://github.com/gocisse/sdwan-triage`
- Exact imported upstream baseline: `43c6cd412860a5219577be6d30feca2db7f57309`
- Nearest preceding upstream tag: `v6.2.0.0`

TraceSleuth preserves attribution to the original project while pursuing an independent architecture, roadmap, product identity, release lifecycle, and network-diagnostics mission.

TraceSleuth is an independent downstream project. It is not presented as an official continuation, endorsed version, or replacement maintained by the original SD-WAN Triage author.

See [UPSTREAM.md](UPSTREAM.md) and [docs/history/ORIGIN.md](docs/history/ORIGIN.md) for the exact provenance record.

## License

TraceSleuth is distributed under the MIT License. The original upstream copyright and permission notice are preserved in [LICENSE](LICENSE).

New TraceSleuth contributions do not erase or replace upstream rights and attribution.

---

**Packets tell the story. TraceSleuth finds the problem.**
