# Release process

## Objective

TraceSleuth releases must be reproducible as practical, version-consistent, tested, attributable, and explicit about detector maturity and limitations.

The authoritative product version is the repository-root `VERSION` file.

## Release prerequisites

Before creating a release:

1. The intended version is present in `VERSION`.
2. `CHANGELOG.md` contains the release section and no misleading completion claims.
3. All required CI jobs pass.
4. Backend tests pass.
5. Frontend lint, type checking, tests, and build pass.
6. Race tests pass where supported.
7. Static analysis and vulnerability checks pass or documented exceptions are approved.
8. Detector fixtures/golden tests pass for detectors affected by the release.
9. Documentation reflects actual behavior.
10. No experimental detector is advertised as stable.
11. Security-sensitive changes receive explicit review.
12. `UPSTREAM.md` is updated if the baseline/provenance relationship changed.

## Pre-release validation

Expected commands will evolve with the repository, but the intended minimum validation set is:

```bash
gofmt -w <changed-go-files>
go test ./...
go test -race ./...
go vet ./...

govulncheck ./...

cd web/frontend
npm ci
npm run lint
npm test
npm run build
```

Where a command is unsupported on a platform, the CI matrix should provide coverage rather than silently omitting it.

## Version alignment

Before tagging:

```text
VERSION             -> 0.1.0
release tag         -> v0.1.0
CLI version         -> 0.1.0
API version         -> 0.1.0
frontend version    -> 0.1.0 or generated at build time
artifact names      -> tracesleuth-v0.1.0-...
```

A release workflow must fail on mismatch.

## Tagging

Use annotated semantic-version tags:

```bash
git tag -a v0.1.0 -m "TraceSleuth v0.1.0"
git push origin v0.1.0
```

Do not create a release from a tag whose version differs from `VERSION`.

## Release artifacts

Target artifacts should eventually include supported combinations of:

- Linux amd64;
- Linux arm64 where validated;
- Windows amd64;
- macOS amd64 where still supported by the project;
- macOS arm64;
- container image where the container deployment is production-ready.

Each release should include:

- checksums;
- build metadata;
- release notes;
- SBOM;
- provenance/attestation where implemented;
- signatures where implemented.

Do not claim reproducible builds until reproducibility is measured and documented.

## Release notes

Release notes should state:

- product version;
- release maturity (`experimental`, `alpha`, `beta`, `release candidate`, or `stable` as applicable);
- major changes;
- detector changes;
- security fixes;
- compatibility changes;
- known limitations;
- upgrade notes;
- attribution where upstream changes were imported.

## Detector release requirements

A detector must not be called stable solely because source code exists.

Stable-detector acceptance requires:

- unique stable ID;
- detector version;
- algorithm documentation;
- positive fixture;
- negative fixture;
- false-positive fixture where relevant;
- unit tests;
- threshold-boundary tests;
- confidence documentation;
- limitations documentation;
- Wireshark validation filter;
- JSON output;
- UI presentation;
- detector catalogue entry;
- packet evidence references;
- changelog entry.

High-risk heuristic detectors such as probable L2 loops and MLAG symptom inference require multiple adversarial false-positive fixtures.

## Release rollback

If a release is found to be defective:

1. Do not rewrite or silently replace published artifacts.
2. Document the defect.
3. Publish a patch release when feasible.
4. Mark a GitHub release as pre-release or otherwise warn users when appropriate.
5. Revoke or supersede compromised artifacts if a security issue requires it.

## 1.0 gate

TraceSleuth `1.0.0` must satisfy the project definition of done in `ROADMAP.md`, including capture trust, evidence-backed findings, mature L2/redundancy/transport functionality, security hardening, automated tests, documentation, and validated deployment paths.