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

### Changed

- Began product-facing transformation from SD-WAN Triage to TraceSleuth.
- Established the independent `0.1.0` semantic-version lineage.

### Security

- Documented critical inherited risks requiring immediate remediation, including universal default administrator credentials, client-controlled upload filenames, unbounded multipart request bodies before application-level size checks, hard-coded JWT fallback secret behavior, query-string JWT transport, and prefix-based origin validation.

### Known limitations

- The executable, Go module path, API version surfaces, frontend package metadata, runtime banners, filesystem paths, metrics labels, release workflow, and other product-facing code still contain inherited SD-WAN Triage identity and version values. These are intentionally not changed through a blind global replacement; they will be migrated in build-tested increments.
- The normalized observation model, capture-quality preflight, first-class evidence schema, detector metadata lifecycle, L2 pathology engine, LACP analysis, MLAG symptom inference, and generalized multi-capture model are not yet implemented.

## [0.1.0] - Unreleased

### Added

- TraceSleuth product bootstrap.
- Independent project identity and semantic-version lineage.
- Historical attribution to the MIT-licensed SD-WAN Triage project by Gocisse.
- Baseline architecture, security, detector, test, build, storage, API, and repository-hygiene audit.

[Unreleased]: https://github.com/DanielDietz-de/TraceSleuth/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/DanielDietz-de/TraceSleuth/releases/tag/v0.1.0
