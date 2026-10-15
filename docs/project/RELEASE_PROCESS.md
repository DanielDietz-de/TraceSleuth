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
- the release workflow stages both the built frontend and the GeoIP database
  before Go validation and cross-platform builds;
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

**Never publish by pushing a version tag.** A tag push checks out the tagged
commit, which can contain an obsolete or unreviewed release workflow.
The validated workflow runs only from the current trusted `main` commit.
Its gated release job creates or validates the version tag itself, after all
release checks. A maintainer-signed tag may be prepared only for that exact
approved commit and is **not** a release trigger.

Historical commits in this repository contained a tag-triggered release
workflow. Merely removing the trigger from current `main` does **not**
retroactively rewrite those commits. Before accepting version tags from
outside the guarded release job, administrators must independently verify
that historical tag-push workflows cannot publish, e.g. by disabling that
legacy workflow at repository level or enforcing an approved tag-creation
policy. This residual historical trigger is a documented release blocker;
do not claim it is solved solely by the revised YAML. Never invent or embed
maintainer credentials in automation.

## Controlled automated prerelease publication

The Release workflow accepts **only** two trusted-default-branch events:

- a GitHub Actions manual dispatch on current `main` supplying the exact
  `VERSION`; dispatch targeting a tag or other branch is rejected;
- a reviewed merge pushed to `main` whose commit subject begins
  `release: vX.Y.Z`, with X.Y.Z exactly matching `VERSION`.

Tag-push release events are deliberately **not** accepted. No workflow loaded
from a tagged or historical commit is trusted as a release authority.

The per-PR `scripts/test-release-context.sh` matrix validates authorized and
rejected event, ref and version combinations against the **same shell helper**
used by the release workflow; the workflow job condition independently enforces
the event/ref restriction. In particular, a tag selected in the manual Actions
UI is not equivalent to a pushed tag.

The release job dispatches **fresh, attempt-specific CI and Security** runs
using `workflow_dispatch` on the exact current `main` commit. Their unique
release-run/attempt ID must match the returned workflow runs, and **both must
complete successfully on the exact release commit SHA**. Stale push runs
cannot satisfy the release gate; later scheduled, pushed or manually requested
failed/incomplete CI or Security checks invalidate earlier green results.
The gate is rechecked before tag creation and immediately before publication;
a moved `main` fails closed. This requires `actions:write` scoped to the
release workflow's `GITHUB_TOKEN` and supported Actions dispatch permissions.
The 120-minute wait remains bounded; missing, cancelled or timed-out runs are
not treated as success.

It then repeats frontend build/full lint/tests, Go vet/tests/race tests,
builds the four supported binaries, exercises CLI JSON regression checks,
verifies all archive SHA-256 checksums, and only then creates the release.
For pre-1.0 versions the release is explicitly marked as a **prerelease** and
its notes include the remaining limitations. Existing releases cannot be
silently replaced.

Signed maintainer tags are preferred. When publication is initiated on
`main` without a signed tag, GitHub's release API creates a lightweight
version tag at the exact validated release SHA, using the scoped
GitHub Actions token. The release job atomically creates the tag if absent
and validates that its resolved commit equals the exact green release SHA.
For signed annotated tags, it resolves the tag object to the underlying
commit; any mismatch fails before publication. A repeated run may reuse an
existing tag only when it identifies that same green commit. This is an
explicitly documented pre-1.0 alternative, not a claim that the tag is
GPG-signed.

## Protected version-tag prerequisite

The prerelease workflow **fails closed** unless GitHub reports an active tag
ruleset covering the exact `refs/tags/vX.Y.Z` with both **Restrict updates**
and **Restrict deletions**, and an **explicitly present, empty** `bypass_actors`
array. A redacted or absent bypass field is not evidence of safety.
The release token must have sufficient ruleset-visibility permission to
obtain authoritative details; if GitHub withholds the field, publication is
blocked until an auditable privileged validation is designed and tested.
Patterns are deliberately restricted to exact or single-component
`refs/tags/*` forms and `~ALL`, not ambiguous recursive globs. This protection
must apply **before** the tag is created: GitHub immutable releases lock the tag
only *after* release publication and do not cover the validation-to-publication
interval. The workflow independently revalidates the ruleset and the exact
annotated/lightweight tag target immediately before publishing.

A repository administrator must configure this once in **Settings → Rules →
Rulesets → New tag ruleset**:

1. Include 'refs/tags/v*' in the target tag pattern.
2. Activate **Restrict updates** and **Restrict deletions**.
3. **Do not restrict creations**: the scoped release workflow must be able to
   create a new tag only after exact-SHA CI, Security and release validation.
4. Configure **no bypass actors** for the version-tag ruleset. A
   GitHub-token response without `bypass_actors: []` is now **rejected**;
   maintainer assurances alone never cause automated validation to pass.
   Grant only an appropriately scoped ruleset-read validation capability,
   or leave automatic publishing intentionally disabled.
5. Also enable **release immutability** under repository Settings → Releases to
   lock assets and tags following publication; tag rulesets protect the
   interval *before* release immutability takes effect.

The workflow runs `scripts/check-release-tag-protection.py` and its negative
fixture tests are part of normal CI. No qualifying and completely visible
tag ruleset means **no automated release**, even when other CI checks are
green. The documented historical tag-trigger risk must also be addressed;
a safe new workflow alone does not make unsafe old tag flows disappear.
This is an explicit supply-chain authorization gate, not a reason to skip
review or publish by hand.

The fresh, release-specific gate tolerates **up to 120 minutes** of
CI/Security runtime (with a further 60-minute budget for build/package/
validation), while rejecting failed, cancelled, pending, or missing runs.
A later failed Security rerun or weekly scan on the same commit supersedes
a formerly green run. Tags remain bound to the validated commit, including
annotated tags; never force-move version tags as a workaround.

## Rollback and withdrawn releases

Do not silently move an existing public release tag.

When a release is materially broken:

- document the defect;
- mark the release appropriately in GitHub if necessary;
- publish a corrected patch release;
- preserve historical traceability.

## Current release status

The current version is declared by the repository-root `VERSION` file,
with the corresponding scope and unfinished milestones recorded in
`CHANGELOG.md` and `ROADMAP.md`. All pre-1.0 releases remain
prereleases and must not be represented as production-ready or as having
implemented detectors that remain planned.
