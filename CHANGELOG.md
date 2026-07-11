# Changelog

All notable TraceSleuth changes are documented here.

TraceSleuth uses Semantic Versioning. The project has an independent version lineage and does not inherit SD-WAN Triage 6.x version numbers.

## [Unreleased]

### Planned

- Complete remaining product-identity migration for inherited runtime source paths, frontend strings, API metadata, and configuration/storage names.
- Capture-quality preflight and capture-duplication analysis.
- Normalized observation, finding, and evidence architecture implementation.
- Layer-2 duplicate/storm/loop analysis.
- STP, LACP, FHRP, and MLAG symptom analysis.
- Generalized multi-capture correlation.
- Retention, storage quotas, analysis resource limits, and comprehensive self-hosting hardening.

## [0.1.0] - 2026-07-09

### Added

- Established the independent TraceSleuth product and version lineage.
- Recorded exact upstream provenance in `UPSTREAM.md`:
  - SD-WAN Triage upstream repository.
  - Exact imported baseline commit `43c6cd412860a5219577be6d30feca2db7f57309`.
  - Nearest preceding upstream tag `v6.2.0.0` at `2855ef6d1cd26909e70e60b893c13341efab9767`.
  - TraceSleuth import commit `da35429b7284bb6a2bc61f2049209dfff299703c`.
- Added `docs/history/ORIGIN.md` describing the evolution from SD-WAN Triage to TraceSleuth.
- Added `docs/development/UPSTREAM_WORKFLOW.md` defining deliberate upstream review and attribution policy.
- Added `docs/audits/INITIAL_BASELINE_AUDIT.md` with source-grounded review of architecture, detectors, security, storage, API, CLI, tests, concurrency, versioning, CI, and technical debt.
- Added authoritative root `VERSION` file with TraceSleuth version `0.1.0`.
- Added semantic-versioning and release-process documentation.
- Added target architecture, analysis pipeline, finding/evidence, correlation, scope/limitations, and architecture-decision records.
- Added a phased roadmap with acceptance criteria and detector definition of done.
- Added pull-request CI for:
  - repository/version contract validation;
  - Go formatting, vet, unit/integration tests, and race tests;
  - frontend typecheck/build, lint, and tests;
  - embedded frontend/backend build validation.
- Added security CI for:
  - `govulncheck`;
  - Gitleaks current-tree scanning;
  - CodeQL for Go and JavaScript/TypeScript.

### Security

- Removed the inherited universal `admin` / `admin` first-run account.
- Added explicit first-administrator bootstrap through:
  - `TRACESLEUTH_BOOTSTRAP_ADMIN_USERNAME`;
  - `TRACESLEUTH_BOOTSTRAP_ADMIN_PASSWORD`.
- Bootstrap passwords are bcrypt-hashed and never written to logs.
- Removed the inherited hard-coded JWT fallback signing secret; authentication now fails closed if the operating-system CSPRNG cannot provide key material.
- Hardened role-context type handling to avoid unsafe type assertions.
- Fixed an inherited nested-lock deadlock path in `CreateUser` by avoiding a second lock acquisition while the write lock is held.
- Fixed ignored `last_login` update errors during authentication.
- Documented remaining known hardening items, including uploaded filename path construction, indefinite capture/report retention, missing global analysis resource limits, and inherited WebSocket query-token behavior.

### Changed

- Replaced the upstream README with a TraceSleuth product README containing the tagline, product promise, honest maturity status, detector-status matrix, architecture summary, quick start, security posture, documentation links, roadmap, attribution, and license information.
- Changed build artifact identity from `sdwan-triage` to `tracesleuth`.
- Changed the Makefile to derive the application version from root `VERSION`.
- Changed frontend installation in the reproducible build path from `npm install` to `npm ci`.
- Made macOS ad-hoc signing conditional on `codesign` availability rather than causing non-macOS release builds to fail solely because `codesign` is unavailable.
- Project status is explicitly pre-1.0 and not production-ready.
- TraceSleuth is documented as an independent downstream project without any claim of upstream endorsement.

### Remaining inherited risks

The initial audit records inherited risks that are not yet claimed fixed in `0.1.0`, including:

- uploaded filenames being used in filesystem path construction;
- indefinite PCAP/report retention unless manually deleted;
- missing global analysis concurrency/resource limits;
- inherited query-parameter bearer-token support for browser WebSockets;
- incomplete secure-header, CSRF, and non-loopback self-hosting posture;
- no completed capture-quality preflight or parser-fuzzing framework yet.

### Not yet implemented

Version `0.1.0` does **not** claim completion of the target detector architecture, capture-quality layer, normalized evidence implementation, L2 loop detector, LACP analysis, MLAG symptom inference, production hardening, or TraceSleuth 1.0 acceptance criteria. Those remain roadmap work and must not be represented as implemented.

[Unreleased]: https://github.com/DanielDietz-de/TraceSleuth/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/DanielDietz-de/TraceSleuth/releases/tag/v0.1.0
