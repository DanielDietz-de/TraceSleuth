# Changelog

All notable TraceSleuth changes are documented here.

TraceSleuth uses Semantic Versioning. The project has an independent version lineage and does not inherit SD-WAN Triage 6.x version numbers.

## [Unreleased]

### Added (unreleased)

- Add a signed-in About view with upstream MIT attribution, non-endorsement disclosure, provenance/license links and explicit pre-1.0 status.
- Inject the browser-visible product version from the authoritative root VERSION during Vite builds, replacing inherited frontend version labels.
- Replace inherited application shell title and HTML metadata with TraceSleuth while preserving historical upstream attribution.

### Planned

- Complete remaining product-identity migration for inherited runtime source paths, frontend strings, API metadata, and configuration/storage names.
- Capture-duplication/SPAN/packet-broker differentiation and full capture capability propagation.
- Normalized observation, finding, and evidence architecture implementation.
- Layer-2 duplicate/storm/loop analysis.
- STP, LACP, FHRP, and MLAG symptom analysis.
- Generalized multi-capture correlation.
- Retention, storage quotas, analysis resource limits, and comprehensive self-hosting hardening.

## [0.2.0] - 2026-10-14

### Added

- Capture-integrity preflight executes before inherited fault detectors in
  both the CLI and the authenticated web analysis path.
- Report capture SHA-256, PCAP/PCAPNG format, per-interface metadata where
  available, link types, packet totals and duration, truncation, observed
  timestamp anomalies, and capture-reported packet drops.
- Export a structured `capture_quality` result in the existing JSON report;
  display capture observations and limitations in the React results UI.
- Reject malformed/truncated/empty capture files during preflight; bound the
  parser's recovery from repeated record-read errors.
- Add synthetic PCAP/PCAPNG positive/negative tests, malformed-input tests,
  result integration assertions and UI regression tests.

### Review hardening

- Pin preflight and detector processing to one open capture descriptor,
  verifying the SHA-256 identity before and after packet analysis to reject
  captures modified in place or replaced between passes.
- Preserve per-section PCAPNG interfaces and packet counts instead of
  incorrectly assigning earlier sections to the final section's interfaces.
- Record interface capture filters, surface them in the UI, and suppress
  unsupported STP/LACP visibility claims for filtered captures.
- Prevent cancellation during the preflight scan from being overwritten by
  late progress or result updates; add concurrent cancellation regression tests.
- Keep single-capture and comparison JSON-mode output parseable as exactly
  one document and reject conflicting export flags, with an executable
  smoke gate in both CI and the release workflow.
- Make analysis claims atomic: reject starting cancelled/failed jobs,
  prevent duplicate starts, and keep failed status terminal against late
  progress updates.
- Propagate cancellation through report-generation checkpoints and finalize
  the job before any external integration hooks (tickets/webhooks/metrics).
- Treat absent PCAPNG interface-statistics blocks as unknown drop counts,
  not falsely reported zero; add absent/zero/nonzero ISB regression fixtures.
- Keep CLI usage and invalid-argument diagnostics on stderr for JSON mode,
  including missing capture and unrecognized option failures.

- Remove uncommitted JSON/HTML reports if cancellation or an analysis
  failure wins during report generation; never recursively delete unrelated
  files in the results directory.
- Report completed/failed cancellation races as HTTP 409 conflicts instead
  of incorrect HTTP 500 errors.
- Reject malformed packet records in both sides of PCAP comparison rather
  than treating parser errors as EOF and reporting misleading partial output.
- Advertise Ethernet/VLAN/STP/LACP capture capabilities only when the usable
  captured frame depth can accommodate the required headers; test shallow
  snap-length PCAP fixtures.
- Reject unsupported comparison export options rather than exit successfully
  while silently ignoring requested CSV, HTML, PDF or simplified output.
- Declare 0.2.x as the current supported prerelease security line and enforce
  consistency between the support matrix and the root version contract.
- Derive classic PCAP microsecond/nanosecond timestamp resolution from magic
  bytes instead of the inverted value in the pinned gopacket reader.
- Return sanitized comparison API errors with packet index and parser cause
  but never expose randomized host-side temporary paths.

- Apply Ethernet, VLAN, STP and LACP capability-depth checks to every
  active PCAPNG interface, never use another interface's deeper capture
  as evidence that a shallow mirror/tap can observe those protocols.
- Reject comparison-only invocations that supply analysis filters or
  flags the comparator would ignore; correct the built-in CLI examples
  and use the TraceSleuth command name in help output.
- Return the actual terminal job state in cancellation conflicts so
  a failure cannot be misrepresented as a successful completion.
- Derive the release-process current-status text from the authoritative
  root VERSION and validate that contract rather than leaving a stale
  0.1.1 claim in the 0.2.0 release documentation.

- Reject header-only PCAP and PCAPNG comparisons rather than reporting
  misleading zero-packet path integrity; include both-side CLI and Go tests.
- Attribute capture-reported packet loss to the exact PCAPNG section,
  interface index, and interface name so engineers can locate the
  unreliable SPAN/TAP source.
- Document the accepted -no-external-lookup flag in built-in help and
  remove legacy nonexistent analysis subcommand examples.

### Remaining limitations

- This is an **initial Phase 2 checkpoint**, not completed capture trust:
  capture duplication/SPAN differentiation, downstream confidence penalties,
  per-packet evidence references, and full capability-aware detector logic
  remain planned. The product is still pre-production.

## [0.1.1] - 2026-10-14

### Review-driven hardening

- Remove disk-backed multipart temporary files even on parsing failures.
- Route every results accessor through the same containment validation.
- Align Vite development WebSocket proxy with strict browser same-origin checks,
  and restore polling fallback after a failed initial WebSocket connection.
- Restrict progress WebSocket identifiers to server-issued UUIDs and use a
  same-origin relative endpoint in the browser.
- Disable the unauthenticated, duplicated historical web/backend executable.
  The legacy web/build.sh script now invokes the canonical authenticated build.



### Security

- Enforce per-request multipart byte ceilings before parsing, plus independent
  stream-copy limits for captures (500 MiB), comparison captures (200 MiB each)
  and optional TLS key logs (8 MiB).
- Replace user-controlled upload path components with UUID-isolated, random,
  private internal filenames; clean incomplete uploads.
- Restrict sensitive local data directories to owner access and prevent
  unmanaged result paths from being read or removed through persisted jobs.
- Remove JWT authentication through URL query parameters and migrate browser
  WebSockets to a dedicated handshake subprotocol; enforce exact-origin checks.
- Persist and delete TLS key-log files correctly; sanitize display/download
  filenames to prevent header injection.
- Raise the minimum Go toolchain to supported Go 1.26.9 (October 2026
  security release); update x/net to 0.60.0 and Gorilla WebSocket to 1.5.3,
  with the necessary x/crypto, x/sys and x/text dependency changes.
- Add focused Go regression tests for upload limits, traversal prevention,
  storage containment, WebSocket origin/token handling and key-log lifecycle.

### Release validation

- Remove inherited frontend ESLint violations, including conditional React
  hooks and stale fetch callbacks, so the full frontend lint gate passes.
- Upgrade pull-request CI from changed-file-only lint validation to a
  repository-wide blocking frontend lint gate, preventing debt regressions.
- Stage the embedded GeoIP database in release CI before Go tests and all
  cross-platform builds; previously the release workflow lacked this input.

### Compatibility

- The backend and frontend must be upgraded together: pre-0.1.1 browsers
  still send WebSocket query tokens, which the hardened backend rejects.
- The application remains loopback-only by default and is **not yet
  production-ready**; resource budgets, retention, capture preflight, and
  parser fuzzing remain outstanding.

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
