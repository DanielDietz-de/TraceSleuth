# Development guide

## Purpose

This guide covers the current TraceSleuth `0.1.0` bootstrap development workflow. The project is migrating incrementally from an imported SD-WAN Triage baseline; some source paths and module names remain intentionally legacy until their replacement is implemented and tested.

## Prerequisites

Use the toolchain versions declared by the repository:

- Go: read from `go.mod`.
- Node.js: Node 24 is used by current CI and release workflows.
- npm: use the committed `web/frontend/package-lock.json` with `npm ci`.
- `make`: optional but recommended for the unified build.
- Git.

Optional tools depend on the task, for example Wireshark/tshark for filter and packet validation.

## Clone and remotes

```bash
git clone https://github.com/DanielDietz-de/TraceSleuth.git
cd TraceSleuth
```

To review future upstream SD-WAN Triage changes deliberately:

```bash
git remote add upstream https://github.com/gocisse/sdwan-triage.git
git fetch upstream --tags
```

Never push TraceSleuth branches or tags to `upstream`.

See `docs/development/UPSTREAM_WORKFLOW.md`.

## Current source-layout migration note

The product binary is `tracesleuth`, but the inherited Go command source directory remains:

```text
cmd/sdwan-triage/
```

The Go module path also remains inherited during the bootstrap phase.

Do not interpret those legacy source paths as final product identity. Do not rename them in an isolated blind change without updating imports, build, embedded assets, tests, release metadata, documentation, and compatibility behavior together.

## Build

Unified build:

```bash
make build
```

Expected product artifact:

```text
build/tracesleuth
```

The build:

1. installs frontend dependencies with `npm ci`;
2. builds the React frontend;
3. stages the frontend in the inherited Go embed directory;
4. optionally stages the GeoIP database if present;
5. builds the Go binary with version/build metadata.

## Run CLI analysis

The inherited flag syntax remains available while the new CLI command hierarchy is deferred:

```bash
./build/tracesleuth capture.pcap
./build/tracesleuth -json capture.pcap > report.json
./build/tracesleuth -compare -lan capture-lan.pcap -wan capture-wan.pcap
```

The target commands such as `tracesleuth analyze`, `serve`, and `detectors list` are not yet claimed implemented.

## Run local web mode

For a new user database, explicitly bootstrap the first administrator:

```bash
export TRACESLEUTH_BOOTSTRAP_ADMIN_USERNAME='admin'
export TRACESLEUTH_BOOTSTRAP_ADMIN_PASSWORD='replace-with-a-strong-unique-password'
./build/tracesleuth -web
```

Requirements:

- both variables must be set together;
- the bootstrap password must contain at least 12 characters;
- no universal default account is created;
- the password is bcrypt-hashed;
- the password is not written to logs;
- bootstrap variables do not create another user when the database already contains users.

The inherited web server binds to loopback by default. Non-loopback production deployment is not yet declared production-ready.

## Go checks

```bash
make fmt-check
make vet
make test
make test-race
```

Equivalent commands:

```bash
go vet ./...
go test ./... -timeout 120s
go test -race ./... -timeout 240s
```

Do not delete or weaken tests merely to make CI green.

## Frontend checks

```bash
cd web/frontend
npm ci
npm run build
npm run lint
npm run test
```

The Vite build performs TypeScript compilation through the inherited build script.

## Repository contract checks

```bash
bash scripts/check-version-contract.sh
bash scripts/check-repository-hygiene.sh
```

For pull-request-equivalent changed-file hygiene:

```bash
git fetch origin main
bash scripts/check-repository-hygiene.sh origin/main
```

The hygiene check rejects new:

- packet captures outside `testdata/pcaps/`;
- release/generated artifact paths;
- common binary/archive types;
- `.DS_Store`, `.backup`, and coverage output;
- changed files larger than 10 MiB.

The repository still contains inherited historical hygiene debt documented in the baseline audit. The changed-file gate prevents additional debt while cleanup is performed in a dedicated reviewed change.

## Versioning

Root `VERSION` is authoritative.

```bash
cat VERSION
```

Do not independently hard-code another release version.

The bootstrap contract currently validates:

- Semantic Version syntax;
- changelog release section;
- roadmap current-version declaration;
- versioning policy;
- Makefile product artifact identity;
- Makefile use of root `VERSION`;
- release workflow artifact identity;
- README version badge.

Legacy runtime surfaces are added to exact alignment only when their migration is implemented.

## Branch workflow

Use focused branches:

```text
feat/capture-quality
feat/lacp-parser
fix/tcp-retransmission-span-duplication
security/upload-path-containment
docs/stp-detector-guide
```

Recommended flow:

1. branch from current `main`;
2. inspect actual implementation;
3. document existing behavior when changing detector semantics;
4. define acceptance criteria;
5. add tests/fixtures;
6. implement;
7. run applicable quality/security checks;
8. update docs and changelog;
9. open a focused pull request;
10. keep failed checks and deferred work visible.

## Adding protocol parsing

Do not let each detector reinvent the same binary parsing.

Target direction:

```text
capture decoder
    -> normalized protocol observation
    -> one or more detectors
    -> evidence/findings
```

Protocol parsing should:

- validate lengths before reading;
- handle malformed input without routine panic;
- retain packet source context;
- avoid unnecessary full-payload copies;
- expose malformed/parser metrics;
- have positive, negative, truncated, and malformed tests;
- receive fuzz coverage when it crosses a custom binary trust boundary.

## Adding a detector

Read:

- `docs/detectors/DETECTOR_AUTHORING_GUIDE.md` when available/current;
- `docs/detectors/DETECTOR_CATALOG.md`;
- `docs/detectors/CONFIDENCE_MODEL.md`;
- `docs/architecture/FINDING_AND_EVIDENCE_MODEL.md`;
- `docs/testing/TEST_STRATEGY.md`.

Never mark a detector stable before its acceptance criteria are complete.

## Test captures

Do not commit private customer or production captures.

Allowed public corpus location:

```text
testdata/pcaps/
```

Every fixture will require provenance and expected/forbidden finding metadata in the corpus manifest once that framework is implemented.

Prefer synthetic minimal fixtures.

## Security-sensitive changes

Treat the following as security boundaries:

- PCAP/PCAPNG parsing;
- TLVs and length-prefixed protocol fields;
- uploaded filenames and paths;
- temporary files;
- capture/report retention;
- evidence export;
- authentication and roles;
- JWT/session behavior;
- WebSocket authentication/connections;
- resource limits and cancellation;
- external integrations;
- dependencies and GitHub Actions.

Read `SECURITY.md`, `docs/security/THREAT_MODEL.md`, and `docs/security/DEPENDENCY_POLICY.md`.

## CI workflows

### CI

Runs:

- version contract;
- changed-file hygiene;
- Go formatting;
- `go vet`;
- Go tests;
- race tests;
- frontend build/typecheck;
- frontend lint;
- frontend tests;
- embedded application build.

### Security

Runs:

- `govulncheck`;
- Gitleaks;
- CodeQL for Go;
- CodeQL for JavaScript/TypeScript.

Passing automation does not replace detector fixtures, capture-limit reasoning, or independent packet validation.

## Commit and PR quality

A useful implementation report records:

```text
what changed
why
source locations
algorithm changes
security impact
tests executed
pass/fail results
coverage when measured
race results
fuzz results
known failures
deferred items
```

Never claim a test passed when it was not executed.

## Current migration priorities

The controlled sequence is:

1. bootstrap/provenance/CI/security foundation;
2. capture trust;
3. normalized evidence architecture;
4. Layer-2 pathology engine;
5. STP/LACP/FHRP/MLAG symptoms;
6. broader routing/transport/services;
7. generalized multi-capture intelligence;
8. evidence-focused UI;
9. production hardening;
10. stable 1.0 validation.

See `ROADMAP.md` for acceptance criteria.
