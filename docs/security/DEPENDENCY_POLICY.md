# Dependency policy

## Purpose

TraceSleuth parses untrusted binary input and is intended for local and self-hosted use. Dependencies therefore affect correctness, attack surface, offline operation, reproducibility, supply-chain trust, binary size, portability, and long-term maintainability.

## Principles

1. Prefer the standard library when it is correct and maintainable.
2. Keep runtime dependencies minimal.
3. Do not add a dependency merely to avoid a small amount of straightforward project code.
4. Prefer actively maintained packages with clear ownership and release history.
5. Avoid abandoned packages unless no practical alternative exists and the justification is documented.
6. Avoid unnecessary CGO dependencies so cross-platform single-binary distribution remains practical.
7. Preserve offline core analysis.
8. Pin dependency versions through standard Go module and frontend lockfiles.
9. Treat parser and cryptography dependencies as security-sensitive.
10. Remove unused dependencies.

## Go dependencies

Go dependencies are declared through:

```text
go.mod
go.sum
```

Requirements:

- use explicit module versions;
- run `go mod tidy` only as a reviewed change;
- inspect unexpected transitive changes;
- use `govulncheck` in CI;
- review license implications for new runtime dependencies;
- prefer pure Go unless CGO provides a documented material benefit;
- avoid `replace` directives pointing to unreviewed forks or mutable local paths in releases.

## Frontend dependencies

Frontend dependencies are declared through:

```text
web/frontend/package.json
web/frontend/package-lock.json
```

Requirements:

- use `npm ci` in CI and reproducible builds;
- commit the lockfile;
- avoid lifecycle scripts from untrusted packages where practical;
- remove unused packages;
- review major-version upgrades;
- keep the Node.js runtime on a supported line;
- do not retain Node 20-only GitHub Actions solely for historical compatibility.

## GitHub Actions

Third-party actions are executable supply-chain dependencies.

Policy:

- prefer official GitHub or language-owner actions;
- use current supported major versions;
- use least-privilege `permissions`;
- set `persist-credentials: false` for checkout when later authenticated pushes are not required;
- avoid unnecessary write permissions;
- document third-party actions with elevated access or external-service behavior;
- consider commit-SHA pinning for mature release/security workflows once an update mechanism exists.

The bootstrap workflows use Node 24-generation action lines and explicit permissions.

## Parser dependencies

Packet and protocol parsers are high-risk because captures are untrusted input.

Before adding a parser dependency, evaluate:

- malformed-input handling;
- length validation;
- panic behavior;
- integer-overflow risks;
- allocation behavior;
- fuzzing history;
- project maintenance;
- standards compliance;
- license;
- whether unsupported packet types fail safely.

A dependency does not remove TraceSleuth's responsibility to fuzz and bound its own trust boundaries.

## Cryptography and authentication

Do not implement custom cryptographic primitives.

Use established standard-library or well-maintained security packages. Fail closed when secure randomness is unavailable. Never add public fallback secrets or universal default credentials.

## External data files

Databases such as GeoIP or threat-intelligence feeds require separate review for:

- provider and source URL;
- license and redistribution rights;
- version/update cadence;
- integrity verification;
- whether they are embedded, downloaded, or supplied by the user;
- whether analysis makes network requests;
- privacy implications.

Core network-fault diagnosis must not require such optional data.

## Adding a dependency

A pull request adding a direct runtime dependency should answer:

1. What capability requires it?
2. Why is existing code or the standard library insufficient?
3. Is the project maintained?
4. What is the license?
5. Does it require CGO?
6. Does it make network requests?
7. Does it process untrusted input?
8. What transitive dependencies are added?
9. What tests cover the integration?
10. What happens when it fails?

## Vulnerability handling

When `govulncheck`, CodeQL, dependency review, or another source identifies a vulnerability:

1. verify whether the affected code path is reachable;
2. identify affected TraceSleuth versions;
3. upgrade, replace, patch, or remove the dependency;
4. add regression coverage where appropriate;
5. document user mitigation when immediate upgrade is impossible;
6. do not suppress findings merely to make CI green.

A scanner finding may be unreachable; that requires documented assessment, not silent dismissal.

## Dependency updates

Updates should be controlled and reviewable.

Preferred approach:

- small dependency-focused pull requests;
- changelog entry when runtime behavior/security changes;
- full relevant CI;
- compatibility testing for major upgrades;
- no unreviewed mass upgrades mixed with detector changes.

Dependabot or an equivalent controlled updater may be configured for Go modules, npm, and GitHub Actions.

## Removal policy

Remove dependencies that are:

- unused;
- duplicated without justification;
- abandoned and replaceable;
- incompatible with target platforms;
- unnecessary for offline core analysis;
- responsible for unacceptable unresolved vulnerabilities.

## SBOM and release provenance

The target release process should generate an SBOM and build metadata for release artifacts. Artifact signing and provenance should be adopted when maintainable signing infrastructure exists.

Do not claim reproducibility, signing, or provenance guarantees before they are implemented and tested.

## Current bootstrap status

TraceSleuth `0.1.0` has:

- Go modules and checksums;
- npm lockfile;
- `npm ci` in CI/release build paths;
- `govulncheck` workflow;
- CodeQL workflow;
- Gitleaks workflow.

Outstanding dependency work includes:

- complete direct/transitive dependency audit;
- automated dependency-update configuration;
- SBOM generation;
- container scanning when a production container image exists;
- explicit GeoIP data provenance/update documentation;
- review of the inherited runtime use of embedded `miniredis` as job metadata storage.
