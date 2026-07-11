# Release process

TraceSleuth releases are evidence-based engineering milestones. A tag is not proof that a roadmap item exists; the repository, tests and release report must prove what is implemented.

## Release prerequisites

A release candidate must satisfy all applicable gates:

- `VERSION` and all validated version surfaces align exactly;
- `CHANGELOG.md` contains an honest release section;
- Go formatting verification passes;
- `go vet` passes;
- Go unit/integration tests pass;
- race tests pass where supported;
- frontend type checking/build passes;
- frontend linting and tests pass;
- static analysis passes under the adopted policy;
- `govulncheck` completes successfully or findings are explicitly assessed;
- repository-hygiene checks pass;
- secret scanning passes;
- generated assets required by the build are reproducible and current;
- release artifacts build for supported targets;
- checksums are generated;
- SBOM/provenance requirements for the release phase are met;
- documentation matches implemented behavior;
- no known release-blocking security issue is silently ignored.

Before `1.0.0`, unfinished roadmap items are allowed, but the release notes must describe them as unfinished.

## Branch and pull-request workflow

TraceSleuth development uses reviewed feature branches and pull requests. Do not rewrite `main` for normal feature work.

A typical release-affecting change:

```text
main
  \
   feat/<scope>-<version>
      \
       pull request -> required CI -> review -> merge
```

The release tag is created only after the release commit is present on the intended release branch and required CI is green.

## Version preparation

1. Select the SemVer version from `docs/project/VERSIONING.md`.
2. Update the root `VERSION` file.
3. Move completed changelog items from `Unreleased` into the release section.
4. Validate every version-bearing file or generated surface.
5. Run the repository version-alignment check.
6. Do not tag while alignment is red.

## Detector release requirements

A detector may be advertised as stable only when it has:

- unique stable ID;
- detector version;
- documented purpose and required capture context;
- positive PCAP fixture;
- negative PCAP fixture;
- false-positive fixture where relevant;
- unit tests;
- boundary tests;
- documented thresholds;
- documented confidence model;
- documented limitations;
- packet evidence references;
- Wireshark validation guidance;
- JSON output;
- UI presentation;
- detector-catalogue entry;
- changelog entry.

High-risk heuristic detectors such as probable loops and MLAG symptoms require multiple adversarial false-positive fixtures.

## Build metadata

Release artifacts should record:

- TraceSleuth version;
- Git commit;
- UTC build timestamp;
- target OS/architecture;
- Go version;
- frontend build metadata where practical.

Runtime version output must never report a stale hard-coded legacy version.

## Release artifacts

The planned supported release artifact set includes:

- Linux amd64 binary/archive;
- Windows amd64 archive;
- macOS amd64 and arm64 archives when supported by the build and signing policy;
- SHA-256 checksums;
- SBOM;
- build metadata;
- release notes.

Container images are released only after the container build, non-root runtime, writable paths, health check, vulnerability scan and data-retention behavior are validated.

## Release notes

Release notes must include:

1. product version and date;
2. major capabilities actually implemented;
3. detector additions/behavior changes;
4. security changes;
5. API/schema changes;
6. configuration changes;
7. migration instructions;
8. known limitations;
9. outstanding risks;
10. test/validation summary;
11. upstream-derived changes and attribution when relevant.

Do not use release notes to imply completion of unimplemented roadmap items.

## Release validation report

For significant milestones, especially `0.9.0` and `1.0.0`, create or attach a validation report that records:

```text
Version:
Commit:
Build targets:
Go test:
Race test:
Frontend tests:
Static analysis:
Vulnerability scan:
Fuzz smoke tests:
Golden tests:
Integration tests:
Coverage:
Performance baseline:
Known failures:
Waivers:
```

A blank field is not equivalent to success.

## Tagging

After merge and green required CI:

```bash
VERSION="$(tr -d '\r\n' < VERSION)"
git tag -s "v${VERSION}" -m "TraceSleuth v${VERSION}"
git push origin "v${VERSION}"
```

Signed tags are preferred where maintainer signing infrastructure is available. Never invent or embed maintainer credentials in automation.

## Rollback and withdrawn releases

Do not silently move an existing public release tag.

When a release is materially broken:

- document the defect;
- mark the release appropriately in GitHub if necessary;
- publish a corrected patch release;
- preserve historical traceability.

## Current release status

TraceSleuth `0.1.0` is a bootstrap milestone, not a production-ready release. It establishes provenance, audit, architecture contracts, roadmap and repository foundations while advanced detector and production-hardening work remains explicitly deferred.
