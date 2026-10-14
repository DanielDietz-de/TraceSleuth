# Test strategy

## Purpose

TraceSleuth makes technical claims about network behavior from untrusted packet captures. A detector is not complete because it compiles or fires on one sample. Tests must prove what a detector detects, what it must not detect, where its thresholds lie, how it handles malformed input, and whether its evidence remains stable.

## Test layers

```text
unit tests
protocol parser tests
detector state-machine tests
positive PCAP fixtures
negative PCAP fixtures
adversarial false-positive fixtures
boundary tests
malformed-input tests
fuzz tests
golden finding tests
multi-capture correlation tests
API/integration tests
frontend component tests
end-to-end tests
race tests
benchmarks and performance regressions
```

Not every feature requires every layer, but every stable detector must meet the detector definition of done.

## Unit tests

Unit tests should cover:

- protocol field parsing;
- state transitions;
- fingerprint generation;
- rate calculations;
- threshold evaluation;
- confidence contributions and penalties;
- certainty ceilings;
- correlation joins;
- clock-offset uncertainty;
- packet-reference creation;
- path and filename safety;
- retention decisions.

Tests should avoid arbitrary sleeps and wall-clock dependence. Inject clocks where time behavior is material.

## Positive PCAP fixtures

A positive fixture proves that a detector fires when the intended condition exists.

Each fixture should specify:

- fixture ID;
- file path;
- origin;
- license;
- synthetic generator when applicable;
- expected finding IDs;
- allowed findings where necessary;
- forbidden findings;
- expected severity/certainty/confidence range when stable;
- required packet references.

## Negative PCAP fixtures

A negative fixture proves that healthy or irrelevant traffic does not trigger the detector.

Examples:

- healthy LACP periodic exchange;
- stable STP root;
- ordinary ARP resolution;
- successful DHCP DORA sequence;
- successful TCP handshake;
- normal DNS response latency;
- ordinary multicast service discovery.

## Adversarial false-positive fixtures

High-risk heuristic detectors require purpose-built alternatives.

### Loop and duplicate forwarding

Required examples include:

- stable factor-of-two dual-source SPAN duplication;
- same traffic captured on both sides of a link;
- port-channel member mirroring;
- packet-broker replication;
- ERSPAN duplication;
- TAP aggregation;
- sender retransmission;
- intentional multicast/broadcast-heavy applications;
- duplicate capture with no traffic amplification.

### MLAG and redundancy

Required examples include:

- valid LACP failover;
- device reboot/failover;
- two unrelated links captured together;
- intentional FHRP transition;
- capture duplication creating apparent dual forwarding;
- LACP timeout-mode difference without service impact where legitimate.

### Transport

Required examples include:

- TCP reordering without loss;
- capture duplication that resembles retransmission;
- one-sided capture;
- timestamp disorder;
- capture starting mid-flow;
- segmentation/offloading effects where represented in captures.

## Boundary tests

Every numeric threshold should test:

```text
threshold - 1
threshold
threshold + 1
```

Time-window detectors should additionally test events immediately inside and outside the window boundary.

## Malformed-input tests

Minimum malformed capture cases:

- invalid magic;
- truncated global header;
- truncated PCAP packet record;
- invalid PCAPNG block length;
- mismatched PCAPNG total block length;
- impossible captured/original lengths;
- unsupported link type;
- truncated protocol header;
- malformed TLV length;
- oversized declared length;
- integer-overflow boundary where applicable.

Expected behavior:

- no uncontrolled panic;
- bounded allocation;
- useful error or malformed metric;
- partial results clearly labeled when allowed;
- cleanup performed.

## Fuzz testing

Priority fuzz targets:

- PCAP/PCAPNG trust boundaries;
- LACP parser;
- STP/RSTP/MSTP parser;
- LLDP TLVs;
- CDP TLVs;
- DHCP options;
- ARP and IPv6 ND custom handling;
- SIP/RTP custom parsing;
- tunnel parsers;
- frame fingerprint normalization;
- evidence export selection.

Fuzz tests should preserve minimal crashing inputs as regression fixtures.

CI may run bounded smoke fuzzing. Longer fuzz campaigns may run separately.

## Golden finding tests

Golden tests protect semantically important output:

- stable detector IDs;
- detector versions where expected;
- severity;
- certainty;
- confidence;
- affected entities;
- evidence schema;
- packet references;
- Wireshark filters;
- correlation links;
- limitations.

Normalize only truly dynamic fields such as analysis UUIDs or wall-clock build timestamps. Do not normalize away detector regressions.

## PCAP corpus layout

Target layout:

```text
testdata/pcaps/
├── capture_quality/
├── l2/
├── loops/
├── stp/
├── lacp/
├── mlag-symptoms/
├── arp/
├── nd/
├── fhrp/
├── tcp/
├── dns/
├── dhcp/
├── voice/
├── multi-capture/
└── malformed/
```

The corpus manifest is:

```text
testdata/pcaps/MANIFEST.yaml
```

Example schema:

```yaml
id: l2-loop-basic-001
file: loops/l2-loop-basic-001.pcap
source: synthetic
license: project-test-data
expected_findings:
  - l2.probable_forwarding_loop
  - l2.broadcast_storm
forbidden_findings:
  - capture.duplication.fixed_factor
```

Do not commit private customer or production captures.

## Fixture provenance

Every fixture records:

- origin;
- redistribution license;
- synthetic status;
- generator/tool version;
- generation parameters;
- expected findings;
- forbidden findings.

Third-party fixtures require verified redistribution rights.

## Integration tests

Core flow:

```text
upload -> validate -> store -> analyze -> findings -> evidence -> export -> delete
```

Integration tests should verify:

- upload byte limits;
- safe internal filename/path behavior;
- authentication and roles;
- analysis lifecycle;
- cancellation;
- result retrieval;
- evidence export;
- deletion and retention;
- API schema behavior.

## Multi-capture tests

Test:

- exact packet matches;
- payload/header modifications;
- NAT;
- TTL decrement;
- DSCP change;
- disappearance;
- fixed duplication;
- duplicate forwarding;
- asymmetric visibility;
- known clock offset;
- estimated clock offset;
- unknown offset;
- collision resistance.

Timing assertions must respect clock uncertainty.

## Frontend tests

Use appropriate unit/component/end-to-end coverage for:

- finding cards;
- certainty/confidence display;
- evidence lists;
- packet references;
- copyable Wireshark filters;
- capture-quality limitations;
- timeline interactions;
- topology evidence classes;
- authentication bootstrap state;
- deletion confirmations;
- detector maturity labels.

The inherited frontend already has a test script; its actual coverage must be measured rather than assumed.

## Race tests

Run:

```text
go test -race ./...
```

where supported.

Priority concurrency targets:

- detector state;
- analysis state;
- subscriptions/WebSockets;
- job updates;
- multi-capture correlation;
- cancellation;
- worker shutdown.

## Determinism tests

The same capture, version, detector configuration, and thresholds should produce semantically identical findings independent of:

- Go map iteration order;
- goroutine scheduling;
- unrelated analysis concurrency.

Sort output using stable keys where order is user-visible or serialized.

## Performance tests

Baseline measurements include:

- fixture/file size;
- packet count;
- protocol mix;
- detector set;
- runtime;
- peak RSS;
- CPU;
- allocations where useful.

Do not claim multi-terabyte scale or production capacity without measured evidence.

Regression thresholds should be introduced only after stable representative baselines exist.

## Security tests

Security regression tests should cover:

- no universal credentials;
- bootstrap password not logged;
- CSPRNG failure is fail-closed where testable;
- filename/path traversal;
- oversized streaming upload;
- malformed capture panic boundaries;
- symlink/temp-file behavior;
- auth role enforcement;
- token validation;
- CORS/CSRF/headers according to supported deployment mode;
- retention deletion failures;
- subscriber/connection limits.

## CI matrix

Bootstrap CI currently targets:

- Go formatting;
- `go vet`;
- Go tests;
- race tests;
- frontend build/typecheck;
- frontend lint;
- frontend tests;
- embedded application build;
- version contract;
- `govulncheck`;
- Gitleaks;
- CodeQL.

Future gates add:

- fuzz smoke tests;
- golden finding tests;
- corpus manifest validation;
- OpenAPI drift checks;
- repository hygiene;
- SBOM validation;
- container scan when a production container exists;
- benchmark reporting.

## Detector definition of done

A stable detector requires:

- unique stable ID;
- detector version;
- description;
- implemented algorithm;
- positive PCAP fixture;
- negative PCAP fixture;
- false-positive fixture where relevant;
- unit tests;
- boundary tests;
- confidence documentation;
- limitations documentation;
- Wireshark validation filter;
- UI presentation;
- JSON output;
- detector catalogue entry;
- evidence packet references;
- changelog entry.

High-risk loop and MLAG symptom detectors require multiple adversarial false-positive fixtures.

## Bug regression policy

Every confirmed detector bug should receive a regression test or fixture when technically feasible.

Do not delete tests, weaken assertions, hard-code expected success, or lower meaningful coverage merely to make CI green.

## Current bootstrap status

The inherited repository contains useful Go and frontend tests, but the complete TraceSleuth corpus, golden, malformed, fuzz, and detector-acceptance framework is not yet implemented. The initial audit documents current coverage and gaps.
