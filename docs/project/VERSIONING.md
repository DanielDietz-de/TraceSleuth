# Versioning policy

TraceSleuth follows [Semantic Versioning](https://semver.org/) and has an independent release history.

## Authoritative version source

The repository-root `VERSION` file is the authoritative source for the TraceSleuth product version.

Example:

```text
0.1.0
```

Build scripts, CLI version output, API version output, frontend metadata, release artifacts, container image tags, release notes and documentation must either derive from `VERSION` or be checked against it in CI.

Version drift is a release blocker.

## Independent lineage

TraceSleuth does not inherit the SD-WAN Triage 6.x version lineage. The first TraceSleuth release line begins at `0.1.0`.

Historical references to upstream version numbers remain valid when they describe the source project's history or the imported baseline.

## Semantic version rules

Before `1.0.0`:

- `0.MINOR.0` may introduce substantial architecture, API or detector changes.
- `0.MINOR.PATCH` should be used for backward-compatible corrections and hardening within that development phase.
- Breaking changes are permitted during pre-1.0 development but must be documented explicitly.

At and after `1.0.0`:

- **MAJOR**: incompatible public API, CLI, configuration or stable finding-schema changes.
- **MINOR**: backward-compatible capabilities, detectors and API additions.
- **PATCH**: backward-compatible fixes, documentation corrections and hardening.

## Planned development progression

```text
0.1.0  Product bootstrap, provenance, baseline audit, identity foundation
0.2.0  Capture integrity and normalized evidence model foundation
0.3.0  Detector framework and correlation engine
0.4.0  Layer-2 pathology engine
0.5.0  STP, LACP, redundancy and MLAG symptom analysis
0.6.0  Multi-capture correlation and topology reasoning
0.7.0  Diagnostic UI and evidence workflows
0.8.0  Production hardening, security and deployment
0.9.0  Release candidate and detector validation
1.0.0  First stable public TraceSleuth release
```

The roadmap may adjust phase boundaries when the implementation proves a different sequence safer. A version number must never be used to imply features that are not implemented and tested.

## Detector versions

The application version and detector versions are distinct concepts.

Every detector in the target architecture must expose a stable detector ID and detector version. A detector version changes when behavior that can affect its findings changes materially, including:

- algorithm changes;
- threshold-default changes;
- confidence-model changes;
- protocol parsing changes that alter evidence;
- false-positive/false-negative behavior changes;
- finding-schema interpretation changes.

A general application patch does not automatically require every detector version to change.

## Finding schema versions

Stable serialized finding schemas require explicit versioning. Before `1.0.0`, schema evolution must still be documented. After `1.0.0`, incompatible stable schema changes require the appropriate API/schema versioning and may require a major product version.

## Tag format

Release tags use:

```text
v<MAJOR>.<MINOR>.<PATCH>
```

Examples:

```text
v0.1.0
v0.4.2
v1.0.0
```

Do not create four-component TraceSleuth versions.

## Pre-release identifiers

Use SemVer pre-release forms when necessary:

```text
0.9.0-rc.1
1.0.0-rc.1
```

A release candidate must not be described as stable or production-ready without satisfying its documented acceptance criteria.

## Version transaction

A version change is complete only when all authoritative/validated surfaces align. The expected transaction includes, as applicable:

1. update `VERSION`;
2. update `CHANGELOG.md`;
3. update build/release metadata that cannot directly consume `VERSION`;
4. update frontend metadata or generated version constants where required;
5. update documentation that declares the current release;
6. run the version-alignment CI check;
7. run build/test/security gates;
8. create the release tag only from a green commit.

## Release integrity

Do not tag or publish a release from a commit with failing required CI.

Do not change tests merely to hide a version inconsistency.

Do not manually override artifact versions independently of `VERSION`.

## Current maturity

`0.1.0` is a bootstrap release line. It records provenance, baseline architecture and project contracts. It does not imply that the target capture-quality, evidence, L2, LACP, MLAG, multi-capture or production-hardening roadmap is complete.
