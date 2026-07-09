# Initial baseline audit

**Audit date:** 2026-07-09  
**TraceSleuth import commit:** `da35429b7284bb6a2bc61f2049209dfff299703c`  
**Exact upstream source baseline:** `43c6cd412860a5219577be6d30feca2db7f57309`  
**Nearest preceding upstream tag:** `v6.2.0.0` at `2855ef6d1cd26909e70e60b893c13341efab9767`

## 1. Executive assessment

The imported repository is a substantial Go and React PCAP-analysis application, not an empty shell. It contains useful protocol analyzers, streaming comparison logic, packet inspection, reporting, a local web UI, CLI operation, authentication, and tests. It is a viable technical foundation for TraceSleuth.

It is **not yet TraceSleuth as defined by the product specification**. The current architecture is centered on a monolithic `TriageReport` containing protocol-specific arrays, a packet-by-packet analyzer registry, direct heuristic findings, and an SD-WAN-oriented product identity. It lacks a normalized observation layer, a first-class evidence model, capture-quality preflight, detector metadata/versioning, packet references on findings, explicit certainty semantics, explainable confidence scoring, a dedicated capture-duplication detector, generalized multi-capture capture-point metadata, a versioned API, and the proposed Layer-2/LACP/MLAG architecture.

The most important immediate risks are:

1. **Universal default credentials are created in code.** `pkg/database/database.go` seeds `admin` / `admin` when the user table is empty and prints the credential pair to logs.
2. **JWT fallback secret is hard-coded.** `pkg/middleware/auth.go` normally uses `crypto/rand`, but falls back to a known string if random generation fails.
3. **Uploaded filenames are used in filesystem paths.** The upload handler validates extensions and an advertised size, then storage joins the job directory with the original filename. This must be replaced with generated internal names and strict path containment.
4. **No automatic retention policy exists.** Original PCAPs and generated reports remain until manual deletion.
5. **Version drift is extensive.** The repository simultaneously exposes `6.2.0`, `6.1.0.0`, `4.3.0`, frontend package version `4.3.0`, and differing Go versions.
6. **There is no general CI workflow.** Only a tag-triggered release workflow exists.
7. **The current finding model is not evidence-backed enough for the TraceSleuth mission.** Findings generally lack packet number, capture interface, certainty, structured alternatives, capture limitations, detector version and normalized evidence.
8. **Several heuristics are too categorical.** Examples include treating any second observed DHCP server as a critical rogue-server condition and classifying certain TLDs as suspicious without enough context.
9. **Repository hygiene is poor.** Historical release binaries, archives, a root binary, generated frontend assets, `.DS_Store` files and a JavaScript backup file are committed.
10. **The detector architecture has duplicated namespaces.** Both `pkg/detector` and `pkg/detectors` exist.

The correct path is incremental refactoring, not an uncontrolled rewrite.

## 2. Audit methodology and boundaries

This audit was performed against the actual source imported into `DanielDietz-de/TraceSleuth`. Representative file identities were compared against upstream. Source files for runtime entry points, build metadata, authentication, storage, upload handling, packet capture handling, detector registration, report models and key detectors were inspected directly.

The current execution environment provided repository/API access but not a local source checkout capable of running the full Go/frontend test suites. Therefore this audit distinguishes **source-inspected facts** from **runtime validation still required**. No test, race, fuzz, coverage or benchmark result is claimed unless actually executed later by CI or a local build environment.

## 3. Provenance

The TraceSleuth repository currently contains a single import commit rather than the full upstream Git history.

The exact imported source baseline is upstream SD-WAN Triage commit:

```text
43c6cd412860a5219577be6d30feca2db7f57309
```

The nearest preceding tag is:

```text
v6.2.0.0 -> 2855ef6d1cd26909e70e60b893c13341efab9767
```

The imported baseline is one upstream commit ahead of that tag. That one additional commit adds the upstream `README.md` and `LICENSE`.

TraceSleuth import commit:

```text
da35429b7284bb6a2bc61f2049209dfff299703c
```

Full provenance policy is recorded in `UPSTREAM.md`.

## 4. Repository structure

The inherited top-level structure is approximately:

```text
.github/workflows/       tag-triggered release workflow
build/                   build-related content
cmd/sdwan-triage/        main Go executable, web server and embedded UI assets
data/                    GeoIP database content

docs/                    limited inherited documentation
pkg/analyzer/            packet pipeline, registry, TCP/comparison/correlation logic
pkg/config/              report and threshold configuration
pkg/database/            SQLite-backed user database
pkg/detector/            primary detector implementations
pkg/detectors/           second detector namespace
pkg/integration/         automation and ticketing integration
pkg/intelligence/        local customer-intelligence data
pkg/metrics/             Prometheus metrics
pkg/middleware/          JWT auth and rate limiting
pkg/models/              report/state/domain models
pkg/output/              console, HTML, CSV, PDF and Wireshark-oriented output
pkg/safety/              guidance and training helpers
pkg/web/handlers/        API, analysis, comparison, packet and export handlers
pkg/web/storage/         job metadata and file storage
releases/                committed historical binaries and archives
scripts/                 release/GeoIP scripts
templates/               report template content
tools/generate_samples/  sample generator
web/backend/             inherited web backend area
web/frontend/            React/Vite frontend and committed dist
web/releases/            frozen historical frontend release tree
```

### Structural debt

- `pkg/detector` and `pkg/detectors` are overlapping namespaces.
- Analyzer, detector, correlation and reporting responsibilities are intermingled.
- `cmd/sdwan-triage` remains the executable source path.
- `web/frontend/dist` is committed.
- Historical frozen release trees are committed.
- Root and historical platform binaries/archives are committed.
- A JavaScript `.backup` file and `.DS_Store` artifacts are committed.

**Disposition:** retain useful code, remove generated/release artifacts through a dedicated repository-hygiene change, and refactor toward `internal/analysis`, `internal/capture`, `internal/protocols`, `internal/detectors`, `internal/evidence`, `internal/findings`, `internal/topology`, `internal/reporting`, `internal/storage`, `internal/api`, `internal/auth`, and `internal/config` incrementally.

## 5. Go package structure

### `pkg/analyzer`

Contains the current execution pipeline and higher-order analysis. Important files include:

- `pcap_reader.go`: PCAP/PCAPNG magic detection and `pcapgo` readers.
- `detector_registry.go`: common packet-analyzer interface and registration.
- `processor.go`, `streaming.go`, `streaming_advanced.go`: analysis execution.
- `comparator.go`, `comparator_streaming.go`: multi-file/LAN-WAN comparison.
- `correlator.go`: root-cause/event correlation.
- `tcp_analysis.go`, `tcp_graph.go`, `stream_reassembly.go`: TCP/stream analysis.
- `issue_detector_*`: higher-level issue generation.
- `security_detector.go`: security-specific higher-order detection.
- vendor-specific analyzers for Aruba, Cisco Viptela and VMware VeloCloud.
- `worker_pool.go`: worker execution support.

### Current analyzer interface

The common interface is:

```go
type PacketAnalyzer interface {
    Name() string
    Analyze(packet gopacket.Packet, state *models.AnalysisState, report *models.TriageReport)
}
```

The registry separates `IndependentAnalyzers` and `StatefulAnalyzers`. For every packet, independent analyzers are launched as goroutines, while a global report mutex is held around each analyzer call. Stateful analyzers execute sequentially.

Strengths:

- common registration point;
- panic recovery per detector;
- explicit distinction between parallel-safe and stateful analyzers;
- existing registry tests;
- bounded caches exist for parts of TCP/state processing.

Weaknesses:

- no stable detector ID;
- no detector version;
- no category metadata;
- no declared observation prerequisites;
- no capture-capability prerequisites;
- no default-threshold metadata;
- no standards-reference metadata;
- no `Initialize`, `Finalize`, `Findings`, `Reset` lifecycle contract;
- registration does not reject duplicate IDs because IDs do not exist;
- goroutine-per-independent-detector-per-packet creates avoidable scheduling overhead;
- report locking around complete analyzer calls limits the expected benefit of concurrent execution;
- detectors directly mutate a large shared report rather than emitting normalized findings;
- capture limitations cannot systematically reduce detector confidence.

**Disposition:** retain the concept, replace the contract incrementally after the normalized observation/evidence foundation exists.

## 6. Frontend structure

The frontend is React 18, TypeScript, Vite and Tailwind-based. It has scripts for:

```text
npm run build
npm run lint
npm run test
```

The package is still named `sdwan-triage-web` and declares version `4.3.0`.

Current useful capabilities include dashboard views, findings, timeline, packet inspection, stream views, comparison, exports, global filtering and troubleshooting workflows.

The committed `dist` directory and a frozen historical release tree should not remain authoritative source.

**Disposition:** preserve useful UX components, establish TraceSleuth navigation and evidence workflows incrementally, and make frontend version/product identity derive from authoritative project metadata.

## 7. Build process

The inherited `Makefile`:

- builds the frontend;
- copies frontend distribution files into `cmd/sdwan-triage/dist`;
- optionally stages GeoIP data for embedding;
- builds a single Go binary;
- cross-compiles Linux amd64, macOS amd64/arm64 and Windows amd64;
- provides Go test, coverage, race, format and vet targets.

Current problems:

- binary name is `sdwan-triage`;
- build source path is `./cmd/sdwan-triage`;
- default version is `6.1.0.0`;
- release titles still name SD-WAN Triage;
- release links point to upstream;
- version is duplicated rather than sourced from one authoritative file;
- frontend build uses `npm install` rather than deterministic `npm ci` in the Makefile;
- release behavior assumes local platform tooling such as `codesign`.

## 8. Runtime architecture

Current runtime shape:

```text
PCAP/PCAPNG
   |
   v
pcapgo reader
   |
   v
packet processor / detector registry
   |                     |
   |                     +--> shared AnalysisState
   v
monolithic TriageReport
   |
   +--> CLI output
   +--> JSON
   +--> HTML/CSV/PDF-related output
   +--> web job storage and API

React frontend <--> Gin HTTP API <--> local job/file storage
                                 +--> SQLite users
                                 +--> in-process miniredis metadata
```

The architecture is local-first and mostly self-contained, which is valuable. However, the analysis contract is report-centric rather than evidence-centric.

## 9. CLI

The current CLI is implemented in `cmd/sdwan-triage/main.go` using Go's `flag` package. Existing capabilities include:

- direct capture analysis;
- JSON, CSV, HTML, multi-page HTML and PDF-related output;
- source/destination/service/protocol filtering;
- QoS analysis;
- handshake reporting;
- application identification;
- optional traceroute and BGP checks;
- comparison mode;
- web mode;
- ServiceNow options;
- verbose/debug options.

Problems:

- product identity is SD-WAN Triage throughout;
- executable syntax is legacy `sdwan-triage`;
- some help text describes external-network features even though TraceSleuth's core must work offline;
- some examples use an `analyze` positional command while the implementation is primarily legacy flag-based;
- the proposed first-class command hierarchy does not exist;
- version output is not derived from a single source.

**Disposition:** preserve backward-compatible aliases temporarily where low-cost, introduce `tracesleuth analyze`, `compare`, `serve`, `detectors list`, and `version` through a deliberate CLI refactor.

## 10. Web interface and API

The current Gin server binds to `127.0.0.1` only. This is a positive local-only default.

Current public endpoints:

```text
GET  /api/health
POST /api/login
```

Protected endpoints include:

```text
GET    /api/status
POST   /api/upload
POST   /api/analyze/:id
GET    /api/analyze/:id/status
POST   /api/analyze/:id/cancel
GET    /api/results/:id
GET    /api/results/:id/json
GET    /api/results/:id/html
GET    /api/results/:id/pdf
GET    /api/history
DELETE /api/history/:id
GET    /api/topology/:id
POST   /api/wizard/:id
POST   /api/compare
POST   /api/compare-pcap
GET    /api/trends
GET    /api/ws/:id
```

Packet, stream, PCAP export, annotation and user-management endpoints also exist.

Problems:

- API is unversioned (`/api`, not `/api/v1`);
- no OpenAPI specification exists;
- health/status endpoints hard-code version `4.3.0`;
- WebSocket bearer tokens may be accepted through a query parameter, increasing token leakage risk in logs/history/proxies;
- no explicit API drift check exists;
- secure response headers and CSRF posture need dedicated review;
- server mode is not yet configurable for supported non-loopback self-hosting.

## 11. Storage and retention

Current storage defaults to:

```text
~/.sdwan-triage/
├── uploads/
└── results/
```

The SQLite user database is stored as `sdwan.db` within the data directory.

Job metadata is maintained through an in-process `miniredis` instance and persisted by storage code. Uploaded PCAPs and generated results are deleted when the user explicitly deletes a job.

Problems:

- old product path/name;
- no configurable retention period;
- no automatic cleanup policy;
- no maximum aggregate storage quota;
- no default privacy-aware expiration;
- no documented backup/retention behavior;
- current directory permissions are created as `0755`, which is too permissive for potentially confidential packet captures on multi-user systems;
- persistence occurs on close and needs crash-consistency review.

## 12. Authentication and session security

### Confirmed behavior

- user records are stored in SQLite;
- passwords are hashed with bcrypt;
- JWTs use HMAC-SHA256;
- normal JWT secret generation uses `crypto/rand`;
- tokens expire after 24 hours;
- role checks exist for admin-only user operations;
- the server is loopback-only by default;
- a per-IP rate limiter is installed.

### Critical findings

#### Universal default administrator credential

`seedDefaultAdmin()` creates:

```text
username: admin
password: admin
```

when the users table is empty. The credentials are also printed to logs.

**Risk:** unacceptable for any future non-loopback or container/server deployment.

**Required remediation:** explicit first-run admin bootstrap, secure environment/CLI bootstrap options, no universal password, no secret logging, and startup refusal or safe local-only behavior when non-loopback binding lacks secure bootstrap.

#### Hard-coded JWT fallback secret

If `crypto/rand` fails, the middleware uses a known fallback literal.

**Risk:** catastrophic token forgery under the failure condition.

**Required remediation:** fail closed. Do not start authenticated server mode without a cryptographically secure secret.

## 13. Upload and untrusted-PCAP handling

Current positive controls:

- accepted extensions are limited to `.pcap`, `.pcapng`, and `.cap`;
- an upload size limit of 500 MiB exists;
- a UUID job ID is generated;
- capture format detection validates PCAP/PCAPNG magic values before creating readers;
- parser creation errors are propagated.

Current problems:

1. **Filename trust:** original upload names are joined into the job directory path.
2. **Extension validation is not content validation:** file extension is checked before capture magic validation.
3. **Header size trust:** `multipart.FileHeader.Size` is checked, but the actual streamed byte count should also be bounded.
4. **Memory pressure:** `MaxMultipartMemory` is set to 500 MiB, which is an aggressive default.
5. **No configurable resource budget:** no global concurrent-analysis cap, per-analysis memory budget or explicit analysis timeout was identified.
6. **Cancellation is status-oriented:** a cancel endpoint updates job state, but the running analysis goroutine requires context cancellation propagation to actually stop work reliably.
7. **No dedicated capture-integrity report:** malformed counts, truncation rate, timestamp quality, interface metadata, capture gaps and capture duplication are not first-class preflight results.
8. **No parser fuzzing workflow was identified.**

## 14. Capture processing

`pkg/analyzer/pcap_reader.go` supports:

- classic PCAP big-endian/little-endian magic;
- nanosecond-resolution PCAP magic;
- PCAPNG Section Header Block magic;
- `pcapgo.Reader`;
- `pcapgo.NgReader` with mixed link types enabled.

This is a useful foundation.

Missing for TraceSleuth capture trust:

- normalized capture metadata model;
- PCAPNG interface metadata surfaced to detectors/findings;
- snap length and truncation-rate reporting;
- timestamp resolution and monotonicity analysis;
- timestamp jumps and gap analysis;
- parser failure/malformed packet metrics;
- reported drop metadata where available;
- explicit L2-capability determination;
- control-plane observability assessment;
- unsupported encapsulation summary;
- file-truncation classification;
- capture-duplication preflight.

## 15. Current report and evidence model

The central `models.TriageReport` is a large struct with protocol-specific fields such as:

- DNS anomalies/details;
- TCP retransmissions, handshakes, window and out-of-order findings;
- ARP conflicts;
- HTTP/TLS/QUIC traffic;
- RTT, bandwidth and timeline data;
- security analysis;
- ICMP, VoIP, tunnel and SD-WAN vendor results;
- packet-loss metrics;
- SMB/LDAP/Kerberos flows;
- LAN protocols;
- DHCP/NTP/DNS-tunneling/C2 findings;
- root-cause chains;
- stability findings.

Strengths:

- broad existing domain coverage;
- JSON serialization;
- timeline data;
- some existing severity/confidence concepts;
- correlation hooks exist.

TraceSleuth gaps:

- no normalized `Finding` object across all detectors;
- no stable detector IDs and versions;
- no required certainty classification;
- confidence is inconsistent and not generally explainable;
- no common structured evidence records;
- no required packet number references;
- no common capture/interface references;
- no standard alternative-explanation field;
- no standard capture-limitations field;
- no standard Wireshark validation filter set;
- no standard recommended-validation/actions/risk-warning fields;
- no detector threshold snapshot attached to findings.

**Disposition:** introduce the new model alongside legacy reports, adapt detectors progressively, and provide compatibility translation during migration.

## 16. Detector inventory

The following inventory records every detector or detector-adjacent source unit identified in the inherited detector namespaces. `Tests` means a directly corresponding test file was present in the imported repository listing; it does not claim successful execution.

### Primary detector namespace: `pkg/detector`

| Detector / source | Domain | Actual evidence and behavior | Threshold / state | Tests | Nature | Disposition |
|---|---|---|---|---|---|---|
| `arp.go` | ARP | Observes ARP replies and reports an IP when a later reply maps it to a different source MAC. | Stateful `ARPIPToMAC`; no threshold. | No direct test file identified. | Deterministic observation, heuristic diagnosis. | Retain parser concept; replace conclusion with mapping-churn evidence, alternatives and packet refs. |
| `bgp.go` | BGP/security | BGP-related indicator logic. | Implementation-specific. | `bgp_test.go` | Mixed. | Review standards correctness; keep only evidence-backed behavior. |
| `c2_beaconing.go` | Security/traffic timing | Detects periodic communication patterns interpreted as possible beaconing. | Time-series state. | `c2_beaconing_test.go` | Heuristic. | Retain as optional security signal, not core fault authority. |
| `common.go` | Shared parsing | IP extraction and common detector helpers. | Shared helpers. | `common_test.go` | Deterministic. | Move toward normalized observations/protocol packages. |
| `ddos.go` | Traffic storms/security | Counts SYN-without-ACK, UDP and ICMP packets per source. | 100 SYN, 200 UDP, 100 ICMP; nominal 10-second window. Shared security state. | `ddos_test.go` | Threshold heuristic. | Refactor rate calculations and baseline awareness; avoid attack attribution without context. |
| `dhcp.go` | DHCP | Tracks DISCOVER volume, OFFER sources and NAK volume. | 50 DISCOVER/MAC; 10 NAKs; 60s reset; any second observed server triggers `Critical` rogue-server finding. | `dhcp_test.go` | Deterministic observations, overly categorical heuristic conclusions. | Major refactor. Multiple servers must not equal malicious/rogue by itself. |
| `dns.go` | DNS | Tracks queries/responses and flags non-listed public resolvers, public-domain/private-IP responses, selected TLDs, deep labels and long names. | Hard-coded resolver/TLD/name heuristics. | No direct test file identified. | Heuristic. | Split deterministic transaction/latency/error analysis from optional threat heuristics. |
| `dns_tunneling.go` | DNS/security | DNS tunneling heuristics. | Stateful heuristic thresholds. | No direct test file identified. | Heuristic. | Optional security detector; require explicit FP documentation. |
| `geoip.go` | Metadata | Geolocates IP-related traffic. | GeoIP DB state. | No direct test file identified. | Informational. | Preserve as optional enrichment; never required for offline core diagnosis. |
| `http.go` | HTTP | Extracts HTTP/error behavior. | Protocol state. | No direct test file identified. | Mostly deterministic. | Preserve useful parsing; emit normalized service observations. |
| `icmp.go` | ICMPv4 | ICMP anomaly/error processing. | Protocol-specific. | No direct test file identified. | Mostly deterministic. | Preserve and expand error correlation. |
| `icmpv6.go` | ICMPv6 | ICMPv6 analysis. | Protocol-specific. | No direct test file identified. | Mostly deterministic. | Preserve and integrate with ND/IPv6 path analysis. |
| `ioc.go` | Threat intelligence | IOC lookup. | External/local feed maps. | No direct test file identified. | Deterministic lookup if feed is known. | Keep optional; not part of network-fault authority. |
| `ipv6.go` | IPv6 | IPv6-related analysis. | Protocol state. | No direct test file identified. | Mixed. | Preserve parsing; expand ND and hop-limit evidence. |
| `lan_protocols.go` | VRRP/CDP/LLDP/HSRP/STP | One large analyzer parses and tracks several LAN protocols. Tracks VRRP priority changes, discovery neighbors, HSRP groups and basic STP bridge/root data. | Multiple unbounded maps keyed by sessions/devices/groups/bridges. | No direct matching test file identified. | Deterministic parsing plus heuristic state interpretation. | Split into normalized protocol packages and independent detectors. High priority. |
| `ntp.go` | NTP | Tracks large responses, private/monlist mode and stratum changes. | 468-byte large response; 10 large responses; 3 stratum changes. | `ntp_test.go` | Deterministic observations plus attack/instability heuristics. | Preserve facts; soften attack attribution and add transaction/timing analysis. |
| `portscan.go` | Security | Port-scan heuristics. | Stateful thresholds. | No direct test file identified. | Heuristic. | Optional security detector. |
| `qos.go` | QoS/DSCP | DSCP/QoS analysis. | Aggregation state. | No direct test file identified. | Mostly deterministic with policy assumptions. | Preserve facts; require explicit policy context before fault conclusions. |
| `quic.go` | QUIC | Identifies/analyzes QUIC traffic. | Protocol state. | No direct test file identified. | Mixed. | Preserve where parsing is correct. |
| `rtp.go` | RTP/voice | Heuristically identifies RTP, tracks SSRC/sequence, estimated loss, reordering and jitter. | Minimum 5 packets; excludes many service ports and public DNS resolver IPs; assumes 8 kHz for simplified jitter calculation. | No direct `rtp_test.go`; historical bug fix exists upstream. | Heuristic identification and metrics. | Retain after codec/clock-rate-aware redesign and fixture coverage. |
| `sdwan_vendor.go` | SD-WAN vendor inference | Vendor heuristics. | Signature/OUI/traffic patterns. | `sdwan_payload_test.go` partly covers SD-WAN payload logic. | Heuristic. | Preserve useful vendor enrichment, isolate from generic diagnosis. |
| `sip.go` | SIP/voice | SIP call/signaling analysis. | Call/session state. | No direct test file identified. | Mostly deterministic parsing. | Preserve and connect to RTP evidence. |
| `stability_monitor.go` | BFD/IKE/STP | Tracks BFD state transitions, IKE SA-init repetition and STP TCNs. | BFD >3 transitions/60s; IKE >3 init events/60s; STP >5 TCN BPDUs. | No direct matching test file identified. | Deterministic observations with threshold inference. | Split by protocol; add packet refs, time-window rigor and capture limitations. |
| `tcp.go` | TCP | Tracks handshakes, same-sequence payload retransmission heuristic, RTT samples and device fingerprints. | 200 ms RTT callback default; state maps/caches. | TCP coverage mainly elsewhere in analyzer tests. | Mixed deterministic/heuristic. | Preserve concepts, redesign retransmission/RTT evidence and capture-duplication awareness. |
| `tcp_advanced.go` | TCP | Detects zero/small windows and simplified out-of-order behavior. | 3 zero windows; 5 windows <=1024; OOO >=10, >=2%, >=20 packets; >10% critical. | No direct matching test file identified. | Threshold heuristic. | Refactor substantially; account for scaling, retransmission, capture duplication and reordering. |
| `tcp_handshake.go` | TCP | Dedicated handshake analysis. | Handshake state/timeouts. | `tcp_handshake_test.go` | Mostly deterministic. | Preserve and normalize evidence. |
| `tls.go` | TLS | TLS parsing/analysis. | Protocol state. | No direct test file identified. | Mixed. | Preserve correctly parsed facts. |
| `tls_ja3.go` | TLS fingerprinting | JA3/JA3S-style fingerprints. | Fingerprint maps. | No direct test file identified. | Deterministic derivation if implementation is correct. | Optional enrichment; verify canonicalization. |
| `tls_security.go` | TLS/security | TLS security heuristics. | Policy/signature thresholds. | No direct test file identified. | Heuristic. | Keep optional and distinguish policy from protocol fault. |
| `traffic.go` | Traffic classification | General traffic classification. | Aggregation state. | No direct test file identified. | Mixed. | Preserve useful stats; do not conflate with fault findings. |
| `tunnel.go` | Tunnels | Identifies several encapsulations/tunnel protocols. | Protocol-specific. | `tunnel_test.go` | Mostly deterministic. | Preserve; move to protocol observations and multi-capture transformations. |

### Secondary detector namespace: `pkg/detectors`

| Detector / source | Domain | Current concern | Tests | Disposition |
|---|---|---|---|---|
| `kerberos.go` | Kerberos | Separate namespace from main detector framework. | No direct test file identified. | Consolidate architecture; preserve correct parsing. |
| `ldap.go` | LDAP | Separate namespace. | No direct test file identified. | Consolidate architecture. |
| `packet_loss.go` | Packet loss | Packet-loss inference is high risk without protocol sequence numbers or synchronized capture points. | No direct test file identified. | Re-audit algorithm before any stable TraceSleuth claim. |
| `smb.go` | SMB | Separate namespace. | No direct test file identified. | Consolidate architecture; retain useful facts. |

### Detector-adjacent analyzer units

| Source | Purpose | Concern | Disposition |
|---|---|---|---|
| `pkg/analyzer/security_detector.go` | Higher-level security findings. | Must not become authority for network-pathology conclusions without normalized evidence. | Keep optional, refactor. |
| `pkg/analyzer/issue_detector_core.go` | Core issue generation. | Findings are not based on a common evidence schema. | Migrate to normalized findings. |
| `pkg/analyzer/issue_detector_infra.go` | Infrastructure issue generation. | Same. | Migrate. |
| `pkg/analyzer/issue_detector_m365.go` | Microsoft 365-specific issue generation. | Product-specific assumptions may not belong in core. | Move to optional rules/profile. |
| `pkg/analyzer/issue_detector_transport.go` | Transport issue generation. | Needs packet refs, capture-quality penalties and detector IDs. | Migrate. |
| `pkg/analyzer/correlator.go` | Correlates events/root-cause chains. | Existing confidence is string-based and not a documented contribution model. | Reuse concepts, redesign contract. |

## 17. Existing protocol support

Source inspection confirms inherited support or detection logic for substantial protocol families, including:

- Ethernet/IP/IPv6/ARP/ICMP/ICMPv6;
- TCP/UDP/SCTP-related traffic processing;
- DNS, DHCP, NTP;
- HTTP/TLS/QUIC;
- SIP/RTP/RTCP-oriented voice analysis;
- VRRP, HSRP, STP, CDP, LLDP;
- BFD and IKE stability signals;
- BGP-related analysis;
- VXLAN, GRE/NVGRE/ERSPAN, MPLS, IPsec, GTP, L2TP and VPN/tunnel identification;
- SMB, LDAP and Kerberos-related analysis;
- SD-WAN vendor heuristics.

Notably absent as first-class TraceSleuth-quality implementations at baseline:

- LACP parser/state machine;
- dedicated capture duplication detector;
- exact/normalized frame-storm engine;
- robust L2 loop correlation;
- comprehensive STP/RSTP/MSTP state analysis;
- MLAG symptom inference framework;
- normalized IPv6 ND pathology engine;
- generalized capture-point-aware multi-capture topology model.

## 18. LAN/WAN comparison

The inherited comparator includes a streaming implementation and forensic summary concepts. This is one of the strongest architectural assets for future multi-capture correlation.

Current limitation: the product model remains primarily LAN-versus-WAN rather than arbitrary named capture points with metadata, clock uncertainty, interface identity, device/location, direction and optional offset.

**Disposition:** preserve streaming packet-correlation concepts; generalize after the capture identity, fingerprint and evidence models exist.

## 19. Tests

Existing Go tests were identified across analyzer, detector, middleware, model, output and web-handler packages. Examples include:

- streaming comparator;
- correlator;
- detector registry;
- filter;
- processor;
- TCP analysis/graphs/TLS decryption;
- vendor analyzers;
- BGP/C2/common/DDoS/DHCP/NTP/TCP-handshake/tunnel detectors;
- rate limiting;
- packet state/store helpers;
- HTML/split-report generation;
- web integration and packet search.

Gaps:

- no repository-wide PCAP corpus manifest as specified for TraceSleuth;
- no systematic positive/negative/false-positive fixture requirement;
- no stable golden finding schema tests;
- no dedicated malformed-PCAP corpus identified;
- no Go fuzz tests identified in the initial source inventory;
- many detectors have no corresponding direct test file;
- no evidence that every high-risk heuristic has adversarial false-positive tests;
- frontend test script exists, but coverage and E2E posture require validation.

No pass/fail or coverage result is asserted by this audit because the full suite was not executed in the connector-only audit environment.

## 20. Fuzz tests

No Go fuzz test files were identified in the initial repository inventory. High-priority future fuzz targets are:

- PCAP/PCAPNG format boundaries;
- custom STP/CDP/LLDP parsing;
- DHCP option parsing;
- LACP parser when introduced;
- tunnel parsers;
- SIP/RTP custom parsing;
- uploaded filename/path handling;
- malformed protocol TLVs.

## 21. Performance and benchmarks

The repository contains streaming processing and bounded-cache work in some areas, including the streaming comparator and TCP-flow state. This is positive.

No authoritative TraceSleuth performance baseline document or benchmark corpus exists. No runtime, peak RSS, CPU, file-size and packet-count matrix exists.

Potential scalability issues requiring measurement:

- detector goroutines created per packet;
- large shared report arrays and timeline accumulation;
- unbounded per-detector maps in several analyzers;
- full DNS details and timeline retention;
- RTP stream maps;
- LAN protocol maps;
- upload memory settings;
- background analyses without a global concurrency limit.

## 22. Concurrency

Positive properties:

- detector registry distinguishes independent from stateful analyzers;
- shared report has a mutex;
- panic recovery prevents one detector panic from immediately killing the entire pipeline;
- some state uses bounded LRU caches;
- storage has mutexes for shared data and subscriptions.

Risks:

- goroutine-per-detector-per-packet overhead;
- serialization caused by locking the report around entire analyzer calls;
- individual detector state is not uniformly bounded;
- cancellation is not visibly propagated through `context.Context` to all analysis work;
- no global maximum concurrent analyses was identified;
- goroutine leak and deterministic ordering require explicit tests;
- race results have not yet been executed for this branch.

## 23. CI/CD

Only `.github/workflows/release.yml` was identified.

It:

- runs on `v*` tags;
- builds frontend and backend;
- runs Go tests;
- cross-compiles artifacts;
- generates SHA-256 checksums;
- publishes a GitHub release.

Problems:

- no PR/push CI workflow;
- no explicit `gofmt` verification;
- no `go vet` step;
- no race job;
- no staticcheck/golangci-lint policy;
- no frontend lint/test step in release workflow;
- no `govulncheck`;
- no CodeQL workflow;
- no secret scanning workflow;
- no dependency review;
- no fuzz smoke tests;
- no repository-hygiene gate;
- no version-alignment check;
- no SBOM;
- no artifact signing/provenance;
- workflow declares Go `1.24` while `go.mod` declares `1.25.0`;
- workflow declares Node `20`;
- release artifacts and titles still use SD-WAN Triage identity.

## 24. Version drift

At baseline:

| Location | Version/product value |
|---|---|
| Upstream README badge/link | `6.2.0` / tag `v6.2.0.0` |
| `Makefile` | `6.1.0.0` |
| `cmd/sdwan-triage/main.go` | `6.1.0.0` |
| web health/status handlers | `4.3.0` |
| `web/frontend/package.json` | `4.3.0` |
| release workflow Go | `1.24` |
| `go.mod` Go | `1.25.0` |

This violates the required single-authoritative-version policy.

**Required baseline change:** create `VERSION` containing `0.1.0`, then progressively make CLI, API, frontend, build metadata, archive names and release workflow derive from or validate against it.

## 25. Dependency management

Positive:

- Go modules and lock-style checksums are present;
- frontend has `package-lock.json`;
- core capture processing uses established Go packet libraries.

Concerns:

- direct versus indirect dependency classification in `go.mod` needs `go mod tidy` validation;
- frontend dependencies include older major versions that require current support review;
- no dependency policy document;
- no vulnerability scan in normal CI;
- embedded GeoIP database provenance/update behavior needs explicit privacy/licensing/update documentation;
- miniredis as runtime job metadata store is unconventional and should be justified or replaced.

## 26. Documentation

Inherited documentation is limited relative to the requested product scope. Existing documents include LAN protocol detection/reference material and an SD-WAN gap-analysis HTML document, plus README content and screenshots.

Missing at baseline:

- provenance document;
- origin history;
- upstream workflow;
- initial baseline audit;
- versioning/release process;
- complete architecture/pipeline/evidence/correlation docs;
- detector catalogue;
- confidence model;
- testing strategy and corpus manifest;
- threat model and PCAP data sensitivity docs;
- configuration, deployment, retention and hardening docs;
- OpenAPI specification;
- explicit scope/limitations;
- TraceSleuth roadmap.

## 27. Obsolete/generated artifacts and repository hygiene

Confirmed hygiene problems include:

- committed root `sdwan-triage` binary;
- numerous historical release binaries and archives under `releases/`;
- committed frontend `dist`;
- frozen `web/releases/v4.3.0` source tree;
- `.DS_Store` files;
- `pkg/output/assets/js/visualizations.js.backup`;
- historic product assets and naming.

These make clones larger, complicate secret/binary scanning and blur source-of-truth boundaries.

**Disposition:** remove through a dedicated, reviewed hygiene change after confirming no runtime dependency on committed generated assets.

## 28. Naming inconsistencies

The baseline contains:

- repository name `TraceSleuth`;
- Go module path `github.com/gocisse/sdwan-triage`;
- command source directory `cmd/sdwan-triage`;
- binary `sdwan-triage`;
- storage path `~/.sdwan-triage`;
- database filename `sdwan.db`;
- JWT issuer `sdwan-triage`;
- metrics instance label `sdwan-triage`;
- frontend package `sdwan-triage-web`;
- UI/README/release titles for SD-WAN Triage.

Historical references must remain where appropriate; runtime/product-facing references require controlled migration.

## 29. Technical debt summary

### Critical

- universal `admin/admin` bootstrap;
- hard-coded JWT fallback secret;
- untrusted uploaded filename path handling;
- no capture-retention policy.

### High

- no normalized evidence/finding contract;
- no capture-quality preflight;
- no packet references for major findings;
- categorical heuristics with weak false-positive controls;
- no general CI/security pipeline;
- version drift;
- no global analysis concurrency/resource policy.

### Medium

- duplicate detector namespaces;
- large monolithic report model;
- large combined LAN-protocol analyzer;
- goroutine-per-detector-per-packet execution pattern;
- unversioned API;
- hard-coded data paths and product names;
- committed build/release artifacts.

## 30. Baseline capabilities to preserve

Unless correctness/security analysis later proves otherwise, preserve:

- local-first operation;
- no mandatory cloud dependency;
- PCAP and PCAPNG processing;
- web and CLI interfaces;
- JSON output;
- single-capture analysis;
- streaming comparison concepts;
- embedded frontend and single-binary distribution where practical;
- existing correct protocol parsers;
- timeline functionality;
- Wireshark-oriented workflows;
- packet inspection and export concepts;
- existing useful tests and fixtures.

## 31. Recommended controlled implementation sequence

1. Preserve provenance and legal attribution.
2. Establish TraceSleuth `0.1.0` version lineage.
3. Add CI and repository quality gates without changing detector behavior.
4. Complete controlled product-identity migration while keeping builds green.
5. Introduce capture identity, metadata and capability models.
6. Implement capture-quality preflight and capture-duplication detection.
7. Introduce normalized observations and evidence-backed findings alongside legacy reports.
8. Create detector metadata/lifecycle contracts.
9. Build L2 duplicate/storm/loop engine with adversarial false-positive fixtures.
10. Split and deepen STP/LACP/FHRP/redundancy analysis.
11. Add MLAG symptom inference only after generic evidence primitives exist.
12. Generalize multi-capture correlation.
13. Migrate UI/API/reporting to evidence workflows.
14. Remove insecure auth defaults and complete production hardening before supported non-loopback deployments.

## 32. Audit conclusion

The inherited project is valuable and should not be discarded. It provides a broad implementation base and several mature-looking features. The core transformation challenge is credibility: TraceSleuth must convert protocol-specific arrays and direct heuristics into normalized, traceable, capture-aware evidence and honest findings.

The initial baseline is now sufficiently understood to begin controlled bootstrap work. Advanced detector behavior must not be advertised as complete until each detector satisfies TraceSleuth's acceptance criteria for evidence, positive/negative/false-positive fixtures, confidence, limitations, packet references and UI/JSON presentation.
