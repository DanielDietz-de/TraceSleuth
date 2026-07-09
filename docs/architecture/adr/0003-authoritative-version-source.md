# ADR 0003: Repository-root VERSION is authoritative

- **Status:** Accepted
- **Date:** 2026-07-09

## Context

The imported baseline contains version drift across the README, Makefile, CLI, web API, frontend package metadata, Go toolchain configuration and release workflow. Different surfaces report `6.2.0`, `6.1.0.0`, and `4.3.0`.

TraceSleuth is a distinct product and must not inherit SD-WAN Triage's 6.x lineage.

## Decision

The repository-root `VERSION` file is the authoritative TraceSleuth product version.

Release tooling, CLI output, API output, frontend metadata, archive names, container tags, documentation and build metadata must either derive from `VERSION` or be checked against it in CI.

TraceSleuth starts at `0.1.0` and uses three-component Semantic Versioning.

During the bootstrap migration, legacy runtime surfaces are inventoried explicitly. The version contract check will expand as each surface is migrated; the temporary presence of inherited values must never be misrepresented as final alignment.

## Consequences

### Positive

- One release version has one source of truth.
- CI can detect drift.
- The independent product lifecycle is explicit.
- Four-component inherited versions are not perpetuated.

### Negative

- Some tooling requires adapters or generated metadata.
- The bootstrap phase needs a controlled migration from hard-coded legacy values.

## Guardrails

- Never manually override an artifact version independently of `VERSION`.
- Never change tests merely to hide version drift.
- Do not tag a release while required version checks fail.
- Detector versions remain independent from the application version.
