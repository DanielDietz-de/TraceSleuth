# Changelog

All notable TraceSleuth changes are documented here.

TraceSleuth uses Semantic Versioning. The project has an independent version lineage and does not inherit SD-WAN Triage 6.x version numbers.

## [Unreleased]

### Planned

- Controlled product-identity migration from inherited SD-WAN Triage runtime names to TraceSleuth.
- General CI, static-analysis, security and repository-hygiene gates.
- Capture-quality preflight and capture-duplication analysis.
- Normalized observation, finding and evidence architecture.
- Layer-2 duplicate/storm/loop analysis.
- STP, LACP, FHRP and MLAG symptom analysis.
- Generalized multi-capture correlation.

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
- Added `docs/audits/INITIAL_BASELINE_AUDIT.md` with source-grounded review of architecture, detectors, security, storage, API, CLI, tests, concurrency, versioning, CI and technical debt.
- Added authoritative `VERSION` file.

### Security findings documented

The initial audit records inherited risks that are not yet claimed fixed in `0.1.0`:

- universal `admin` / `admin` first-run credentials;
- a hard-coded JWT fallback secret;
- uploaded filenames being used in filesystem path construction;
- indefinite PCAP/report retention unless manually deleted;
- missing global analysis concurrency/resource limits.

### Changed

- Project status is explicitly pre-1.0 and not production-ready.
- TraceSleuth is documented as an independent downstream project without any claim of upstream endorsement.

### Not yet implemented

Version `0.1.0` does **not** claim completion of the target detector architecture, capture-quality layer, evidence model, L2 loop detector, LACP analysis, MLAG symptom inference, production hardening or TraceSleuth 1.0 acceptance criteria. Those remain roadmap work and must not be represented as implemented.

[Unreleased]: https://github.com/DanielDietz-de/TraceSleuth/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/DanielDietz-de/TraceSleuth/releases/tag/v0.1.0
