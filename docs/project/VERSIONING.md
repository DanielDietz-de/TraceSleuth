# Versioning policy

## Independent lineage

TraceSleuth is an independent downstream project and does not continue the SD-WAN Triage 6.x version sequence.

The TraceSleuth lineage begins at:

```text
0.1.0
```

The repository-root `VERSION` file is the authoritative product version source.

## Semantic Versioning

TraceSleuth follows Semantic Versioning:

```text
MAJOR.MINOR.PATCH
```

Before `1.0.0`, the project is explicitly pre-stable. Breaking changes may occur between minor releases, but they must still be documented and intentional.

### MAJOR

Increment for incompatible changes after stable `1.0.0`, including incompatible API, CLI, configuration, finding-schema, detector-ID, persisted-data, or supported-deployment contract changes.

### MINOR

Increment for backward-compatible capabilities or, before `1.0.0`, substantial milestone releases. Examples include a new capture-quality subsystem, evidence model, major detector family, generalized multi-capture capability, or major UI workflow.

### PATCH

Increment for backward-compatible bug fixes, false-positive/false-negative fixes, security patches that do not require a breaking interface change, documentation corrections tied to a release, dependency updates, and other narrowly scoped maintenance changes.

## Planned pre-1.0 progression

The roadmap uses the following intended progression. Exact release contents remain governed by tested acceptance criteria rather than calendar dates.

```text
0.1.0  Product bootstrap, provenance, rebranding foundation, repository hardening
0.2.0  Capture integrity and normalized evidence foundation
0.3.0  Detector framework and correlation engine
0.4.0  Layer-2 pathology engine
0.5.0  STP, LACP, redundancy and MLAG symptom analysis
0.6.0  Multi-capture correlation and topology reasoning
0.7.0  Complete diagnostic UI and evidence workflows
0.8.0  Production hardening, security and deployment
0.9.0  Release candidate and detector validation
1.0.0  First stable public TraceSleuth release
```

## Authoritative version source

The authoritative version is:

```text
VERSION
```

All of the following must derive from that file or be tested for exact alignment:

- CLI version output;
- runtime banner;
- API `/version` response;
- health/status metadata where version is returned;
- frontend application metadata;
- About page;
- release tags;
- release archive names;
- container image tags;
- generated reports;
- build metadata;
- documentation release references.

Hard-coded independent version values are prohibited once the 0.1.0 bootstrap migration is complete.

## Release tags

Release tags use:

```text
vMAJOR.MINOR.PATCH
```

Example:

```text
v0.1.0
```

The release workflow must fail if the tag version does not exactly match `VERSION`.

## Detector versioning

Product version and detector version are separate concepts.

Each detector will eventually expose a stable detector ID and detector version. A detector version should change when semantics change in a way that may affect findings, including:

- algorithm changes;
- threshold-default changes;
- confidence-model changes;
- evidence-selection changes;
- material parser behavior changes.

A detector bug fix that changes output should be reflected in its detector version and changelog entry once detector versioning is implemented.

## Finding-schema compatibility

Before `1.0.0`, the normalized finding/evidence schema may evolve, but changes must be documented.

After `1.0.0`:

- compatible additive fields may be introduced in minor releases;
- removals, semantic reinterpretations, or incompatible type changes require a major-version decision unless a versioned API/schema mechanism isolates the change.

## Version alignment CI

CI must validate at minimum:

1. `VERSION` contains a valid semantic version;
2. release tag equals `v` + `VERSION`;
3. CLI/API/frontend/build metadata do not drift;
4. changelog contains the released version;
5. generated artifacts use the expected product/version name.

## Upstream versions

Upstream SD-WAN Triage version numbers remain historical provenance only. They must not be reused as TraceSleuth release numbers.

The imported baseline is recorded in `UPSTREAM.md`.