# Initial baseline audit

**Repository:** `DanielDietz-de/TraceSleuth`  
**Audit date:** 2026-07-11  
**TraceSleuth import commit:** `da35429b7284bb6a2bc61f2049209dfff299703c`  
**Verified upstream baseline:** `gocisse/sdwan-triage@43c6cd412860a5219577be6d30feca2db7f57309`  
**Associated upstream release/tag:** `v6.2.0.0`

## 1. Executive assessment

The imported codebase is a substantial Go/React packet-analysis application, not a minimal prototype. It already contains PCAP/PCAPNG ingestion, many protocol analyzers, a CLI, an embedded React web application, JSON/HTML/CSV/PDF-oriented reporting paths, packet inspection/export features, a two-capture LAN/WAN comparator, authentication, local storage, metrics, and release automation.

It is nevertheless **not yet TraceSleuth in architecture or product behavior**. The current source tree remains consistently branded as SD-WAN Triage, uses the upstream Go module path, exposes an SD-WAN-centric two-capture model, lacks a first-class capture-quality preflight, lacks a normalized evidence model, lacks stable versioned detector metadata, lacks LACP and MLAG symptom analysis, and contains several security and operational defects that must be addressed before non-loopback or production deployment.

The most important baseline findings are:

1. **Provenance is recoverable but Git history was squashed.** The target repository contains one import commit rather than the upstream commit graph. The exact source baseline has been verified independently through matching Git blob SHAs for `README.md`, `go.mod`, and `cmd/sdwan-triage/main.go`.
2. **Version drift is already severe.** The CLI default is `6.1.0.0`, frontend package/API values include `4.3.0`, the README/release identity points to `6.2.0`, and the release workflow has its own tag-derived value.
3. **The current authentication bootstrap is unsafe.** A universal `admin` / `admin` account is created automatically and printed in logs.
4. **Upload handling needs immediate hardening.** The client-supplied filename is used directly as a filesystem path component; file-type validation is extension-based at upload time; and the 500 MB application check does not bound the incoming HTTP body before multipart parsing.
5. **The current detector framework is not sufficient for TraceSleuth's target evidence model.** Detectors have human-readable names but no stable ID, detector version, category, declared prerequisites, capture-capability contract, confidence model, or standardized packet references.
6. **Capture quality is not a first-stage analysis product.** Format magic is validated, but there is no preflight for truncation rate, timestamp resolution/monotonicity, PCAPNG interface metadata, capture loss, parser failure rate, duplicate capture, or visibility limitations.
7. **Per-packet concurrency is expensive and mostly serialized.** The registry launches a goroutine per independent analyzer for each packet, while all of those calls are enclosed by the same report mutex. This creates high goroutine churn with limited practical write parallelism.
8. **Cancellation is not true processing cancellation.** Web cancellation changes job state and stops progress updates, but the packet processor has no `context.Context` or cancellation check and continues until processing returns.
9. **The repository contains substantial hygiene debt.** Historical release binaries, archives, `.DS_Store` files, a top-level compiled binary, generated assets, and obsolete product branding are committed.

No detector behavior is changed by this audit.

---

## 2. Audit scope and method

The audit inspected the actual imported source tree and key execution paths, including:

- target and upstream commit history;
- repository file inventory;
- `README.md` and `LICENSE` provenance;
- `go.mod`;
- `Makefile`/release-workflow surfaces;
- CLI entry point and flags;
- capture format reader;
- processor and detector registry;
- report and packet-state models;
- LAN protocol implementation;
- web server/router and API registration;
- upload handler and storage implementation;
- analysis job lifecycle;
- authentication database and JWT middleware;
- React package metadata and application routing;
- test-file inventory and release automation.

The detector inventory below distinguishes between behavior directly inspected in source, behavior visible from concrete registration/output models, and items that require deeper detector-specific validation before being called stable.

---

## 3. Repository provenance and history

### 3.1 Imported state

The TraceSleuth repository currently has a single initial import commit:

```text
da35429b7284bb6a2bc61f2049209dfff299703c
```

The verified matching upstream baseline is:

```text
43c6cd412860a5219577be6d30feca2db7f57309
```

The imported state corresponds to the upstream v6.2.0-era source. The upstream README links release/tag `v6.2.0.0`.

### 3.2 Verification

The following files have identical Git blob SHAs between the TraceSleuth import and the stated upstream commit:

| File | Git blob SHA |
|---|---|
| `README.md` | `eee181477f0284276a244844b0dafe0eb6bef56c` |
| `go.mod` | `fad5e86b41491535df01d76c52682df69c8042bf` |
| `cmd/sdwan-triage/main.go` | `9d685d7a83fa0b4c681157f0fac338c5ff4376cc` |

### 3.3 Consequence

The repository is not a conventional history-preserving fork. Upstream integration must therefore be deliberate and provenance-aware. `UPSTREAM.md` and `docs/development/UPSTREAM_WORKFLOW.md` define the baseline and future workflow.

---

## 4. Current repository structure

The imported layout is approximately:

```text
/
├── .github/workflows/release.yml
├── cmd/sdwan-triage/
│   ├── main.go
│   ├── webserver.go
│   ├── auth_handlers.go
│   ├── embed.go
│   ├── embed_geoip.go
│   ├── assets/
│   ├── data/
│   └── dist/
├── data/GeoLite2-City.mmdb
├── docs/
├── pkg/
│   ├── analyzer/
│   ├── config/
│   ├── database/
│   ├── detector/
│   ├── detectors/
│   ├── integration/
│   ├── intelligence/
│   ├── metrics/
│   ├── middleware/
│   ├── models/
│   ├── output/
│   ├── safety/
│   └── web/
│       ├── handlers/
│       └── storage/
├── releases/
├── scripts/
├── templates/
├── tools/generate_samples/
├── web/frontend/
├── go.mod
├── go.sum
├── Makefile
├── README.md
├── RELEASE_NOTES.md
├── LICENSE
└── sdwan-triage
```

### Structural observations

- `pkg/detector` and `pkg/detectors` are separate source trees with overlapping conceptual responsibility.
- `pkg/analyzer` contains both analysis orchestration and substantial domain logic.
- Reporting is spread across a large `pkg/output` package with many HTML/report generators.
- The main binary is under `cmd/sdwan-triage`, and the Go module still points to `github.com/gocisse/sdwan-triage`.
- The repository contains historical release binaries and archives in `releases/` plus a top-level compiled `sdwan-triage` binary.
- `.DS_Store` files are committed under release directories.
- `pkg/output/assets/js/visualizations.js.backup` is committed and appears to be an obsolete backup artifact.

**Disposition:** retain working source during initial bootstrap, but remove committed generated binaries/archives and obsolete artifacts in a dedicated hygiene change after validating whether any are intentionally used as fixtures.

---

## 5. Build process

### Backend

- Go module: `github.com/gocisse/sdwan-triage`
- `go` directive: `1.25.0`
- Binary package: `./cmd/sdwan-triage`
- Single-binary design embeds the frontend and GeoIP data.

### Frontend

- React 18
- TypeScript
- Vite
- Vitest
- ESLint
- Tailwind CSS
- React Router
- Leaflet/react-leaflet

The frontend package is currently named `sdwan-triage-web` and declares version `4.3.0`.

### Release workflow

The only imported GitHub workflow is tag-triggered release automation. It:

- uses Node.js 20;
- uses Go 1.24;
- runs `go test ./...`;
- builds the frontend;
- copies frontend output into `cmd/sdwan-triage/dist`;
- cross-compiles Linux amd64, macOS amd64/arm64, and Windows amd64;
- generates SHA-256 checksums;
- creates a GitHub release.

Problems:

- Node.js 20 is end-of-life as of 2026-03-24 and must not remain the target CI runtime.
- The workflow's Go 1.24 differs from `go.mod`'s Go 1.25.0.
- Release artifacts are named `sdwan-triage`.
- Release title remains SD-WAN Triage.
- No independent pull-request CI workflow exists.
- No race, vet, static-analysis, vulnerability, secret, fuzz-smoke, repository-hygiene, frontend lint/test, SBOM, or container scanning workflow exists.

---

## 6. Runtime architecture

The primary flow is:

```text
PCAP/PCAPNG file
      |
      v
OpenCapture -> PacketReader
      |
      v
Processor.Process
      |
      +--> per-packet DetectorRegistry
      |      +--> independent analyzers
      |      +--> stateful analyzers
      |
      +--> finalizeReport
      |      +--> RTT/handshake summaries
      |      +--> protocol findings
      |      +--> stability findings
      |      +--> stream analysis
      |      +--> vendor DPI
      |      +--> correlation
      |      +--> bandwidth/gap summaries
      |
      v
TriageReport
      |
      +--> CLI / JSON / CSV / HTML / PDF paths
      +--> web API result files
```

The web mode adds:

```text
Gin HTTP server
  +-- SQLite user database
  +-- JWT authentication
  +-- miniredis-backed in-process job metadata
  +-- filesystem uploads/results
  +-- background analysis goroutines
  +-- WebSocket progress
  +-- packet inspection/export
  +-- optional ServiceNow/metrics/automation hooks
  +-- embedded React frontend
```

---

## 7. Current CLI

The CLI is flag-based rather than subcommand-based.

Current principal forms include:

```text
sdwan-triage [OPTIONS] <pcap_file>
sdwan-triage -web [-port PORT] [-no-browser]
sdwan-triage -compare <capture-a> <capture-b>
```

Current output/report flags include JSON, CSV, HTML, multi-page HTML, PDF, and simplified output.

Current analysis flags include filtering, QoS analysis, TCP handshakes, application identification, optional traceroute, optional external BGP lookup, two-capture comparison, debug HTML, and web mode.

### Issues

- Product name and executable are still upstream names.
- No first-class `analyze`, `compare`, `serve`, `detectors list`, or `version` command hierarchy exists.
- CLI version defaults to `6.1.0.0` and is independent of other version surfaces.
- ServiceNow password is accepted as a CLI argument, which can expose it in process listings and shell history.
- Optional BGP/traceroute behavior means offline operation is available but not the only possible execution behavior; external access must remain explicit and documented.

---

## 8. Current web interface

The React application currently gates authenticated users and defines routes for:

- home/dashboard;
- analysis progress;
- results;
- history;
- comparison;
- login.

The imported UI is useful and should be evolved rather than discarded. It does not yet implement the full target diagnostic navigation and evidence workflows required for TraceSleuth.

Target gaps include first-class pages/workflows for:

- normalized findings;
- capture quality;
- packet evidence;
- protocol catalogue;
- generalized timeline correlation;
- topology confidence;
- detector catalogue;
- explicit alternatives and limitations.

---

## 9. Current API

The API is currently unversioned under `/api`.

### Public endpoints

```text
GET  /api/health
POST /api/login
```

### Protected endpoint families

```text
/api/status
/api/upload
/api/analyze/:id
/api/results/:id
/api/history
/api/topology/:id
/api/wizard/:id
/api/compare
/api/compare-pcap
/api/trends
/api/ws/:id
/api/packets/...
/api/stream/...
/api/export-pcap/...
/api/annotations/...
/api/auth/...
```

Prometheus metrics may be exposed separately at `/metrics`.

### Gaps

- no `/api/v1/` versioning;
- no OpenAPI specification;
- no API drift validation;
- no detector-catalogue endpoint;
- hard-coded API version values already drift from CLI/README versions.

---

## 10. Storage and retention

### Current behavior

Default storage is under:

```text
~/.sdwan-triage/
├── uploads/
├── results/
├── sdwan.db
└── intelligence.json
```

Job metadata is maintained through an in-process miniredis instance and persisted by the storage layer. Original captures and generated results are retained until explicitly deleted through job deletion or manually removed.

### Gaps

- no TraceSleuth data-directory name yet;
- no configurable retention period;
- no maximum total storage policy;
- no scheduled cleanup policy;
- no documented sensitive-data retention model;
- directories are created with mode `0755` and result files with `0644`, which may be too permissive for confidential packet captures on multi-user systems;
- deletion errors are generally ignored in job cleanup;
- original capture retention is implicit rather than policy-driven.

---

## 11. Authentication and session implementation

### Current behavior

- SQLite user database;
- bcrypt password hashing;
- JWT signed with HMAC-SHA256;
- 24-hour token lifetime;
- role model: admin, analyst, viewer;
- authentication required for most API routes;
- server currently binds to `127.0.0.1` only.

### Critical findings

#### Universal default administrator

When the user table is empty, the application automatically creates:

```text
username: admin
password: admin
```

The credentials are also printed to logs. This directly violates TraceSleuth's security requirements.

#### JWT fallback secret

If cryptographic randomness fails, authentication falls back to a hard-coded secret. Security initialization must fail closed instead.

#### Token in query string

The authentication middleware accepts `?token=` for WebSocket access. Query tokens can leak through logs, browser history, reverse proxies, monitoring systems, and referrer-related surfaces. A safer WebSocket authentication design is required.

#### CORS and WebSocket origin prefix checks

Origin validation uses string-prefix checks such as `http://localhost`. A hostile origin whose hostname merely starts with that string can match. Origin parsing and exact host validation are required.

#### Session continuity

The JWT signing key is generated per application start, invalidating existing tokens after restart. This may be acceptable for local-only ephemeral use but must be explicit and configurable for self-hosted server mode.

---

## 12. Capture ingestion and parser trust boundary

### Existing positive properties

The capture reader validates the first four magic bytes and supports:

- classic PCAP;
- classic PCAP with nanosecond magic values;
- PCAPNG section-header magic;
- mixed-link-type PCAPNG through `pcapgo.NgReader`.

The processor:

- handles packet read errors without immediately terminating the whole analysis;
- recovers from panics at detector and packet-analysis boundaries;
- has a default 1 GiB heap guard;
- periodically evicts stale stream-reassembly state.

### Missing capture-trust layer

There is no first-class preflight that reports:

- file type and capture hash as a finding/report primitive;
- timestamp resolution;
- timestamp monotonicity/jumps;
- capture duration, first/last timestamp as trusted metadata;
- PCAPNG interface metadata;
- reported capture drops;
- snap length;
- truncated-packet rate;
- malformed-packet count;
- parser failure count as visible capture quality;
- file truncation confidence;
- unsupported link-layer limitations;
- control-plane observability;
- duplicate-capture prevalence;
- likely SPAN/mirror duplication;
- conclusion limitations.

This is the highest architectural priority before advanced L2/MLAG inference.

---

## 13. Upload security

### Existing checks

- accepted extensions are `.pcap`, `.pcapng`, `.cap`;
- application-level maximum is nominally 500 MB;
- UUID job IDs are generated.

### Critical gaps

1. **Client filename used as path component.** `header.Filename` is passed to storage and joined directly under a job directory. The application must generate an internal filename or sanitize with a strict basename policy and never trust client paths.
2. **Extension-only type validation at upload stage.** Capture magic should be validated before accepting the upload as a packet capture.
3. **Request body is not bounded before multipart parsing.** `router.MaxMultipartMemory` is not an HTTP-body size limit. The handler checks `header.Size` only after `FormFile` has parsed the multipart request.
4. **Key-log filename handling repeats the same trust issue.** The supplied key-log filename is concatenated into a stored path.
5. **No configurable upload limit.** The limit is hard-coded.
6. **No per-user or global analysis concurrency limit.** Upload and analysis abuse can consume CPU, memory, disk, and goroutines.

---

## 14. Current detector/analyzer framework

The `PacketAnalyzer` interface exposes only:

```text
Name()
Analyze(packet, state, report)
```

The registry divides analyzers into:

- independent analyzers, invoked through goroutines;
- stateful analyzers, invoked sequentially.

### Positive properties

- centralized registration;
- deterministic registration order in source;
- panic isolation per detector;
- explicit distinction between stateful and nominally independent analyzers;
- analyzer unit-testability is possible.

### Gaps against target detector lifecycle

Missing first-class metadata includes:

- stable detector ID;
- detector version;
- category/subcategory;
- description;
- required observations;
- required capture capabilities;
- state requirements;
- default thresholds;
- standards references;
- capture limitation hooks;
- confidence contribution model;
- enable/disable policy;
- stable machine-readable catalogue.

### Concurrency concern

For each packet, the registry creates one goroutine per independent analyzer, but each analyzer call acquires the same `report.Mu` around the entire `Analyze` call. The result is substantial goroutine churn with serialized report-locked execution. Packet-only analyzers are also invoked under that report lock even when they do not need the report.

This design should be benchmarked before modification, then replaced with bounded worker/pipeline concurrency only where measurements justify it.

---

## 15. Detector and analyzer inventory

**Legend**

- **D**: primarily deterministic protocol/state logic.
- **H**: heuristic or threshold-based.
- **Mixed**: deterministic observations feeding heuristic conclusions.
- **Dedicated test** means a directly named test file is present in the imported tree. It does not imply adequate positive/negative/false-positive PCAP fixture coverage.

| Registered analyzer/detector | Source location | Domain / actual current role | Evidence / state | Thresholds / limitations | Test status | Classification | Disposition |
|---|---|---|---|---|---|---|---|
| DNS | `pkg/detector/dns.go` | DNS query/response and anomaly analysis | packet DNS fields, query state, report slices | detector-specific; no normalized evidence references | no dedicated `dns_test.go` observed | Mixed | Refactor into normalized observations + findings |
| ARP | `pkg/detector/arp.go` | IP-to-MAC conflict detection | ARP fields + `ARPIPToMAC` map | mapping changes can be legitimate; no capture-context confidence | no dedicated `arp_test.go` observed | Mixed | Retain logic, add churn/storm/context controls |
| HTTP | `pkg/detector/http.go` | HTTP flow/error analysis | packet/application payload | encrypted traffic invisible | no dedicated test observed | Mixed | Retain where defensible |
| TLS | `pkg/detector/tls.go` | TLS flow/certificate parsing | TLS packet fields and flow state | encrypted payload limits | no direct `tls_test.go`; TLS decrypt tests exist | D/Mixed | Retain and separate observations from conclusions |
| QUIC | `pkg/detector/quic.go` | QUIC traffic detection | packet/port/protocol fields | must not overclaim app identity | no dedicated test observed | Mixed | Retain |
| QoS | `pkg/detector/qos.go` | DSCP/QoS analysis | IP DSCP/traffic stats | currently optional | no dedicated test observed | Mixed | Retain; improve multi-capture change reasoning |
| TLS-Security | `pkg/detector/tls_security.go` | TLS version/cipher security findings | handshake metadata | certainty depends on observed handshake | no dedicated test observed | Mixed | Retain with evidence model |
| ICMP | `pkg/detector/icmp.go` | ICMP anomaly/error analysis | ICMP packet fields and counters | context-sensitive | no dedicated test observed | Mixed | Retain |
| ICMPv6 | `pkg/detector/icmpv6.go` | ICMPv6 analysis | ICMPv6 packet fields | ND/RA needs dedicated normalized model | no dedicated test observed | Mixed | Refactor/expand |
| GeoIP | `pkg/detector/geoip.go` | geolocation enrichment | IP addresses + embedded DB | enrichment, not pathology evidence | no dedicated test observed | D enrichment | Retain as optional enrichment |
| SDWAN-Vendor | `pkg/detector/sdwan_vendor.go` | SD-WAN vendor identification | packet patterns/ports/signatures | vendor inference risks need explicit confidence | payload test exists | H/Mixed | Isolate as vendor enrichment |
| SIP | `pkg/detector/sip.go` | SIP signaling analysis | SIP payload/flow | encrypted SIP not observable | no dedicated test observed | D/Mixed | Retain/expand |
| RTP | `pkg/detector/rtp.go` | RTP quality analysis | RTP sequence/timing | valid only where sequence context exists | no dedicated test observed | Mixed | Retain, add explicit observability limits |
| Tunnel | `pkg/detector/tunnel.go` | tunnel/encapsulation detection | EtherType/IP protocol/ports/headers | detection does not imply pathology | dedicated test present | D/Mixed | Retain as observations |
| BGP | `pkg/detector/bgp.go` | BGP analysis | BGP packet fields/state | separate from optional external BGP lookup | dedicated test present | Mixed | Retain/validate |
| LAN-Protocols | `pkg/detector/lan_protocols.go` | VRRP, CDP, LLDP, HSRP, basic STP/RSTP-like BPDU parsing | protocol payloads, session maps, timeline | monolithic; lacks MST/PVST depth, packet references, normalized observations | no dedicated test observed | Mixed | Split into protocol packages and detectors |
| DHCP | `pkg/detector/dhcp.go` | DHCP failure/rogue-server style analysis | DHCP messages/state | multiple servers are not inherently rogue | dedicated test present | Mixed | Retain with neutral competing-server terminology |
| NTP | `pkg/detector/ntp.go` | NTP anomaly/amplification analysis | NTP packet fields/counters | needs context and documented thresholds | dedicated test present | Mixed | Retain |
| DNS-Tunneling | `pkg/detector/dns_tunneling.go` | DNS tunneling heuristic | query characteristics/statistics | high false-positive sensitivity | no dedicated test observed | H | Keep experimental until adversarial tests exist |
| IOC-IP | `pkg/detector/ioc.go` | IOC matching on IPs | exact threat-intel matches | feed quality governs meaning | no dedicated test observed | D enrichment | Retain separately from fault diagnosis |
| IOC-DNS | `pkg/detector/ioc.go` | IOC matching on DNS | exact threat-intel matches | feed quality governs meaning | no dedicated test observed | D enrichment | Retain separately from fault diagnosis |
| TCP-Advanced | `pkg/detector/tcp_advanced.go` | TCP window/out-of-order analysis | sequence/window state | duplicate capture/reordering can confound | no dedicated test observed | Mixed | Major refactor into TCP pathology engine |
| Stability | `pkg/detector/stability_monitor.go` | BFD/IKE/STP-TCN stability signals | protocol events + sliding windows | conclusions need evidence and confidence | no dedicated test observed | H/Mixed | Retain signals; refactor outputs |
| PacketLoss | `pkg/detectors/packet_loss.go` | packet-loss-oriented metrics | protocol state/sequence context | generic loss cannot be invented for arbitrary UDP | no dedicated test observed | Mixed | Validate strictly; likely refactor |
| SMB | `pkg/detectors/smb.go` | SMB protocol detection | packet payload/ports | not a fault detector by itself | no dedicated test observed | D/Mixed | Retain as protocol observation |
| LDAP | `pkg/detectors/ldap.go` | LDAP protocol detection | packet payload/ports | encrypted LDAP limits | no dedicated test observed | D/Mixed | Retain as protocol observation |
| Kerberos | `pkg/detectors/kerberos.go` | Kerberos protocol detection | packet payload/ports | encryption/context limits | no dedicated test observed | D/Mixed | Retain as protocol observation |
| StreamReassembly | `pkg/analyzer/stream_reassembly.go` | TCP/UDP stream reconstruction | bounded/reaped stream state | payload sensitivity; memory cost | no dedicated test observed | D infrastructure | Retain, benchmark, harden |
| Bandwidth | `pkg/analyzer/bandwidth_timeseries.go` | time-series throughput and gaps | packet timestamps/lengths | capture gaps may not equal network outage | no dedicated test observed | Mixed | Retain as observation infrastructure |
| TCP | `pkg/detector/tcp.go` | TCP flow/retransmission/RTT analysis | sequence, ACK, timestamps, flow state | duplicate capture and timestamp quality can confound | no dedicated `tcp_test.go` observed; related TCP tests exist | Mixed | Refactor into TCP pathology engine |
| TCP-Handshake | `pkg/detector/tcp_handshake.go` | SYN/SYN-ACK/ACK tracking and failures | per-flow handshake state | timeout semantics depend on capture start/end | dedicated test present | Mixed | Retain, add capture-window limitations |
| Traffic | `pkg/detector/traffic.go` | generic flow/app traffic statistics | flow state/counters | not itself a pathology detector | no dedicated test observed | D/Mixed | Retain as normalized observation source |
| DDoS-TCP | `pkg/detector/ddos.go` | SYN flood heuristic | counters/time windows/targets | threshold/context-sensitive | dedicated test present | H | Keep separate from core fault pathologies |
| DDoS-UDP | `pkg/detector/ddos.go` | UDP flood heuristic | counters/time windows/targets | threshold/context-sensitive | dedicated test present | H | Keep separate from core fault pathologies |
| DDoS-ICMP | `pkg/detector/ddos.go` | ICMP flood heuristic | counters/time windows/targets | threshold/context-sensitive | dedicated test present | H | Keep separate from core fault pathologies |
| PortScan | `pkg/detector/portscan.go` | horizontal/vertical scan heuristic | source/destination/port maps | legitimate scanners/monitoring possible | no dedicated test observed | H | Retain as security module, not core fault diagnosis |
| C2-TCP | `pkg/detector/c2_beaconing.go` | TCP beaconing heuristic | interval tracking | high false-positive sensitivity | dedicated test present | H | Experimental/security module |
| C2-UDP | `pkg/detector/c2_beaconing.go` | UDP beaconing heuristic | interval tracking | high false-positive sensitivity | dedicated test present | H | Experimental/security module |
| Aruba DPI | `pkg/analyzer/vendor_aruba.go` | post-reassembly Aruba issue heuristics | reassembled stream data | vendor-specific, payload-dependent | dedicated test present | H/Mixed | Move behind vendor enrichment interface |
| Cisco Viptela DPI | `pkg/analyzer/vendor_cisco_viptela.go` | post-reassembly Viptela issue heuristics | reassembled stream data | vendor-specific, payload-dependent | dedicated test present | H/Mixed | Move behind vendor enrichment interface |
| VeloCloud DPI | `pkg/analyzer/vendor_velocloud.go` | post-reassembly VeloCloud issue heuristics | reassembled stream data | vendor-specific, payload-dependent | dedicated test present | H/Mixed | Move behind vendor enrichment interface |
| Underlay/overlay correlator | `pkg/analyzer/correlator.go` | BGP-to-TCP/RTT correlation | recorded protocol events and time gaps | current confidence is not the target explainable contribution model | dedicated test present | H/Mixed | Retain concept; replace output model |

### Missing target detector domains

The imported registry does **not** contain first-class implementations for the following TraceSleuth priorities:

- capture-quality preflight;
- capture duplication / probable SPAN duplication;
- exact frame duplicate storm;
- normalized near-duplicate frame analysis;
- broadcast storm baseline/growth analysis;
- multicast storm analysis;
- correlation-based probable Layer-2 loop detection;
- LACP parsing/state tracking;
- MLAG symptom inference framework;
- generalized duplicate forwarding across multiple capture points;
- full STP/RSTP/MSTP/PVST+/Rapid-PVST observation model;
- normalized evidence packet references;
- detector catalogue with stable IDs and versions.

---

## 16. Current LAN/WAN comparison logic

The imported comparator is a significant reusable asset. The CLI currently accepts two captures and treats them explicitly as LAN-side capture A and WAN-side capture B.

Current concepts include:

- packet matching;
- missing-from-A / missing-from-B classifications;
- TTL/DSCP/NAT modification signals;
- tunnel awareness;
- path-integrity score;
- per-flow summaries;
- one-way latency estimates;
- retransmission and failed-handshake summaries.

### Required evolution

The model must become capture-point-neutral:

```text
Capture A — client access
Capture B — server access
Capture C — firewall ingress
Capture D — firewall egress
Capture E — WAN edge
```

The current implementation also uses language such as "dropped by device" for missing packets. That conclusion can be stronger than the evidence permits when clocks, visibility, filters, asymmetric paths, capture loss, or unsynchronized capture points are not accounted for. TraceSleuth must distinguish observed disappearance from inferred device drop.

---

## 17. Current report model

`TriageReport` is a large aggregate containing protocol-specific slices and structures such as DNS anomalies, TCP retransmissions, failed handshakes, ARP conflicts, TLS data, traffic analysis, RTT analysis, timeline events, security findings, ICMP, VoIP, tunnel data, packet-loss metrics, LAN protocols, vendor DPI issues, DHCP/NTP findings, TCP window/out-of-order findings, correlation chains, and stability findings.

### Positive properties

- broad current output coverage;
- JSON serialization already exists;
- timeline support exists;
- report mutex exists for concurrent writes.

### Gaps

There is no universal `Finding` schema containing:

- stable finding ID;
- detector ID/version;
- certainty classification;
- numerical confidence with documented calculation;
- affected entities;
- packet references;
- structured evidence;
- thresholds;
- alternative explanations;
- capture limitations;
- Wireshark filters;
- recommended validation;
- correlated finding references;
- risk warnings and standards references.

The current report should be adapted incrementally through compatibility layers rather than replaced in one uncontrolled rewrite.

---

## 18. Current state and memory behavior

### Bounded components

The analysis state uses LRU caches for:

- TCP flows: default 100,000;
- UDP flows: default 100,000;
- pending SYN entries: default 50,000;
- TLS SNI cache: default 10,000;
- device fingerprints: default 5,000.

The processor also has:

- default 1 GiB heap ceiling;
- periodic stream cleanup;
- top-50 stream reporting.

### Unbounded or potentially large components

The analysis state explicitly contains unbounded maps for:

- ARP IP-to-MAC mappings;
- DNS query transaction tracking;
- HTTP requests;
- TLS flow seen-state;
- HTTP/2 flow seen-state;
- application statistics.

Additional detector-specific maps and report slices may also grow with capture cardinality. A systematic memory-complexity review is required.

---

## 19. Concurrency and cancellation

### Current behavior

- packets are read sequentially;
- each packet dispatches independent analyzers through goroutines;
- the registry waits for all independent analyzers before stateful analyzers;
- detector panic recovery exists;
- web analysis starts in a background goroutine.

### Risks

- high per-packet goroutine churn;
- shared report mutex serializes nominally independent analysis calls;
- no `context.Context` in `Processor.Process`;
- web cancellation does not interrupt packet processing;
- no global maximum concurrent analysis count;
- no analysis timeout;
- no explicit worker shutdown model;
- `go test -race ./...` is not part of normal CI.

---

## 20. Existing tests

The imported tree contains meaningful Go unit tests across analyzers, detectors, models, middleware, output, and web handlers.

Observed dedicated tests include, among others:

- analyzer correlator;
- detector registry;
- filters;
- processor;
- TCP analysis flags;
- TCP graphing;
- TLS decryption;
- Aruba/Viptela/VeloCloud issue detectors;
- BGP;
- C2 beaconing;
- detector common helpers;
- DDoS;
- DHCP;
- NTP;
- SD-WAN payloads;
- TCP handshake;
- tunnels;
- rate limiting;
- model helpers and packet state;
- HTML report generation;
- split reports;
- web handler integration;
- packet search.

### Test gaps

No imported evidence was found for a systematic public PCAP corpus with:

- positive expected findings;
- negative forbidden findings;
- adversarial false-positive cases;
- fixture provenance/license metadata;
- threshold-minus-one/exact/plus-one boundary cases;
- finding golden outputs;
- malformed-capture corpus organization.

No Go fuzz tests were identified in the imported file inventory. Some benchmark functions exist in tests, but there is no documented baseline performance matrix or CI regression gate.

Required next artifacts include:

```text
testdata/pcaps/MANIFEST.yaml
docs/testing/TEST_STRATEGY.md
docs/testing/PCAP_CORPUS.md
docs/testing/GOLDEN_TESTS.md
docs/performance/BASELINE.md
```

---

## 21. GitHub workflows and release automation

### Present

- one tag-triggered `release.yml` workflow;
- frontend build;
- `go test ./...`;
- cross-platform binary builds;
- checksums;
- GitHub release publication.

### Missing

- pull-request CI;
- `gofmt` verification;
- `go vet`;
- race tests;
- `staticcheck` or controlled `golangci-lint`;
- frontend lint;
- frontend tests;
- explicit TypeScript checking separate from build;
- `govulncheck`;
- CodeQL;
- secret scanning;
- dependency review;
- bounded fuzz smoke tests;
- SBOM generation;
- container scanning;
- version-alignment checks;
- generated-file checks;
- branding-hygiene checks;
- unintended-binary checks.

---

## 22. Dependency management

The repository uses standard Go modules and an npm lockfile-based frontend build.

Notable dependency categories include:

- gopacket/pcapgo;
- Gin;
- JWT;
- bcrypt via `x/crypto`;
- modernc SQLite;
- miniredis and go-redis;
- MaxMind DB support;
- QUIC;
- PDF generation;
- React/Vite/TypeScript/Leaflet.

A full dependency policy is not present. Runtime dependencies should be classified as essential, optional, removable, or development-only, with `govulncheck`, frontend dependency audit, and update policy in CI.

---

## 23. Security findings summary

| Severity | Finding | Evidence in implementation | Required direction |
|---|---|---|---|
| Critical | Universal `admin/admin` bootstrap | database seed function | remove; first-run or explicit secure bootstrap |
| Critical | Default credentials printed to logs | database seed log banner | never log secrets |
| High | Client filename used as storage path component | upload handler + `SaveUploadedFile` | internal generated names; sanitized display name only |
| High | Request body not bounded before multipart parsing | Gin multipart configuration + post-parse size check | `MaxBytesReader`/equivalent boundary limit |
| High | Hard-coded JWT fallback secret | auth middleware fallback path | fail closed if CSPRNG fails |
| High | Query-string JWT support | auth middleware | safer WebSocket auth/token exchange |
| High | Prefix-based CORS/WebSocket origin validation | `strings.HasPrefix` | parse origin; exact allowlist |
| High | No analysis concurrency limit or timeout | background `go h.runAnalysis` + processor API | bounded queue/workers/context cancellation |
| Medium | ServiceNow password CLI flag | main CLI | environment/secret file/interactive mechanism |
| Medium | Confidential files created with broad default modes | storage/results directories | restrictive modes and documented policy |
| Medium | `/metrics` may be unauthenticated | router registration | document/protect when non-loopback |
| Medium | Retention indefinite unless manually deleted | storage lifecycle | configurable retention and cleanup |
| Medium | Upload validation relies on extension before analysis | upload handler | validate magic and parser preflight |

The current loopback-only bind materially reduces remote exposure, but it does not make unsafe defaults acceptable and does not protect against malicious local/browser-origin interactions.

---

## 24. Version drift

At least the following independent values exist:

| Surface | Current value |
|---|---|
| `cmd/sdwan-triage/main.go` default | `6.1.0.0` |
| `web/frontend/package.json` | `4.3.0` |
| health/status API | `4.3.0` |
| README/release identity | `6.2.0` / `v6.2.0.0` |
| release workflow | derived from Git tag |
| Makefile default | separate legacy value |

TraceSleuth establishes `VERSION` as the authoritative product version, beginning at `0.1.0`, and must add automated exact-alignment validation before stable releases.

---

## 25. Licensing and attribution

The imported `LICENSE` contains the MIT license and upstream copyright:

```text
Copyright (c) 2025-2026 Gocisse
```

This notice must be preserved. TraceSleuth may add its own copyright notices for new contributions without removing upstream rights.

Historical and attribution references to SD-WAN Triage are valid and must not be removed by blind branding automation.

---

## 26. Technical debt and obsolete artifacts

High-confidence hygiene candidates include:

- top-level compiled `sdwan-triage` binary;
- many historical binaries/archives under `releases/`;
- `.DS_Store` files;
- backup JavaScript asset;
- old release notes tied exclusively to upstream versioning;
- upstream product logo/assets in current product-facing locations;
- duplicated or overlapping `pkg/detector` and `pkg/detectors` namespaces;
- hard-coded version values;
- product branding embedded throughout code, UI, metrics, paths, release tooling, and reports.

These should be removed or migrated through controlled, build-tested changes rather than a destructive global replacement.

---

## 27. Immediate implementation priorities

### P0 — provenance and release identity

- keep MIT license intact;
- add `UPSTREAM.md`;
- add origin and upstream-workflow documentation;
- establish `VERSION=0.1.0`;
- create independent changelog/versioning policy;
- replace product-facing README identity while retaining attribution.

### P0 — critical security

- eliminate universal default credentials;
- fail closed on JWT-secret generation failure;
- generate internal upload filenames;
- enforce request-body limits at the HTTP boundary;
- validate capture magic before job acceptance;
- use restrictive file permissions;
- fix exact origin validation.

### P0 — build and CI truth

- create PR CI;
- move frontend CI away from EOL Node 20;
- align Go toolchain with `go.mod`;
- run backend/frontend tests and lint;
- add race/static/vulnerability/secret checks;
- add version-alignment and repository-hygiene tests.

### P1 — capture trust

- capture metadata/preflight;
- truncation and timestamp analysis;
- PCAPNG interface metadata;
- parser/malformed counters;
- capture duplication detection;
- visible capture confidence and limitations.

### P1 — evidence architecture

- normalized observations;
- stable `Finding` schema;
- packet references;
- detector metadata/lifecycle;
- confidence model;
- correlation primitives.

### P2 — L2 and redundancy differentiation

- exact and normalized frame fingerprints;
- SPAN/capture duplication safeguards;
- broadcast/multicast storms;
- probable L2 loop correlation;
- ARP/ND expansion;
- STP/RSTP/MSTP/PVST reasoning;
- LACP parser/state machine;
- MLAG symptom inference;
- FHRP evidence improvements.

---

## 28. Baseline audit conclusion

The imported application provides valuable engineering foundations worth preserving: Go-based packet processing, PCAP/PCAPNG support, a web UI, CLI/JSON/report outputs, multi-capture comparison concepts, protocol analyzers, timeline support, packet inspection/export, bounded caches in several critical paths, panic isolation, and an existing test suite.

The transformation should therefore be incremental, not a rewrite.

However, TraceSleuth must not merely rebrand this codebase. The defining architectural work remains capture trust, normalized observations, structured evidence, stable detector contracts, false-positive control, L2 pathology analysis, full LACP analysis, honest MLAG symptom inference, generalized multi-capture correlation, production security, and a troubleshooting-first UI.

This audit is the initial baseline for those changes. No unimplemented detector is presented here as complete or stable.