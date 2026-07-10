# Changelog

All notable changes to TraceSleuth are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project follows Semantic Versioning.

TraceSleuth has an independent release lineage and does not continue the SD-WAN Triage 6.x version sequence. Historical upstream provenance is documented in `UPSTREAM.md` and `docs/history/ORIGIN.md`.

## [Unreleased]

### Added

- Initial baseline audit in `docs/audits/INITIAL_BASELINE_AUDIT.md`.
- Exact upstream provenance record in `UPSTREAM.md`.
- Project-origin history in `docs/history/ORIGIN.md`.
- Deliberate upstream-review process in `docs/development/UPSTREAM_WORKFLOW.md`.
- Independent authoritative `VERSION` file.
- TraceSleuth versioning policy.
- Initial product roadmap and architecture documentation.
- Pull-request CI covering Go formatting, vet, tests, embedded build verification, race testing, Staticcheck, frontend lint/tests/type-check/build, `govulncheck`, Gitleaks, version policy, and repository hygiene.
- Short-lived CI diagnostic artifacts for failed backend, frontend, race, Staticcheck, and vulnerability checks so inherited baseline debt remains inspectable rather than hidden.
- Explicit TypeScript/React ESLint configuration for the imported frontend.

### Changed

- Began product-facing transformation from SD-WAN Triage to TraceSleuth.
- Established the independent `0.1.0` semantic-version lineage.
- Updated CI from the inherited Node.js 20 runtime to Node.js 24.
- Pinned CI to Go 1.25.12 after the vulnerability baseline identified a standard-library issue in Go 1.25.11.
- Reworked CI to build the real React frontend first and restore it into `cmd/sdwan-triage/dist` for Go tests, static analysis, race tests, vulnerability analysis, and embedded-binary verification.

### Security

- Documented critical inherited risks requiring immediate remediation, including universal default administrator credentials, client-controlled upload filenames, unbounded multipart request bodies before application-level size checks, hard-coded JWT fallback secret behavior, query-string JWT transport, and prefix-based origin validation.
- Upgraded `github.com/quic-go/quic-go` from `v0.59.0` to `v0.59.1` to address reachable `GO-2026-5676`.
- Upgraded `github.com/redis/go-redis/v9` from `v9.4.0` to `v9.6.3` to address reachable `GO-2025-3540`.
- Upgraded `github.com/gin-contrib/cors` from `v1.5.0` to `v1.6.0` to address reachable `GO-2024-2955`.
- Pinned CI to Go `1.25.12` to address reachable standard-library vulnerability `GO-2026-5856` found under Go `1.25.11`.

### Known limitations

- The executable, Go module path, API version surfaces, frontend package metadata, runtime banners, filesystem paths, metrics labels, release workflow, and other product-facing code still contain inherited SD-WAN Triage identity and version values. These are intentionally not changed through a blind global replacement; they will be migrated in build-tested increments.
- The normalized observation model, capture-quality preflight, first-class evidence schema, detector metadata lifecycle, L2 pathology engine, LACP analysis, MLAG symptom inference, and generalized multi-capture model are not yet implemented.
- The initial imported source contains formatting and Staticcheck debt. CI keeps these failures visible while the bootstrap branch fixes correctness defects and establishes an explicit baseline policy for deferred style/dead-code cleanup.

## [0.1.0] - Unreleased

### Added

- TraceSleuth product bootstrap.
- Independent project identity and semantic-version lineage.
- Historical attribution to the MIT-licensed SD-WAN Triage project by Gocisse.
- Baseline architecture, security, detector, test, build, storage, API, and repository-hygiene audit.

[Unreleased]: https://github.com/DanielDietz-de/TraceSleuth/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/DanielDietz-de/TraceSleuth/releases/tag/v0.1.0
