# Upstream review workflow

## Purpose

TraceSleuth originated from `gocisse/sdwan-triage` but is an independent downstream project. Upstream integration is therefore deliberate, selective, reviewable, and attribution-preserving.

The exact imported baseline is recorded in `UPSTREAM.md`.

## Recommended remotes

For a local clone, use distinct remotes:

```bash
git remote -v
git remote add upstream https://github.com/gocisse/sdwan-triage.git
git fetch upstream --tags --prune
```

The intended roles are:

```text
origin    -> https://github.com/DanielDietz-de/TraceSleuth
upstream  -> https://github.com/gocisse/sdwan-triage
```

Before pushing, verify the destination:

```bash
git remote -v
git push --dry-run origin HEAD
```

Do not push TraceSleuth changes to the upstream repository.

## Imported baseline

The initial TraceSleuth repository was created as a single import commit rather than as a history-preserving fork.

```text
Upstream baseline commit:
43c6cd412860a5219577be6d30feca2db7f57309

TraceSleuth import commit:
da35429b7284bb6a2bc61f2049209dfff299703c
```

Because the upstream commit graph is not part of the current TraceSleuth history, normal merge-base operations between the two repositories may not work as they would for a conventional fork. Treat upstream integration as explicit code provenance work, not routine branch synchronization.

## Reviewing upstream changes

1. Fetch the upstream repository and tags.
2. Identify the exact upstream commits or release range under consideration.
3. Read the upstream diff and understand the behavior being imported.
4. Decide whether the change is compatible with TraceSleuth's architecture, security requirements, product identity, evidence model, and deterministic-first mission.
5. Create a dedicated TraceSleuth branch.
6. Import only the relevant change. A clean reimplementation may be preferable when the TraceSleuth architecture has diverged substantially.
7. Preserve applicable attribution and license notices.
8. Add or update tests, including regression fixtures for detector bugs.
9. Update documentation and `CHANGELOG.md` for user-visible behavior.
10. Record the upstream commit(s) in the pull request description.

## Deliberate, not automatic

TraceSleuth does not automatically merge every upstream release or commit. Upstream changes are candidates for review, not mandatory dependencies.

A change should normally be declined or reworked when it:

- conflicts with TraceSleuth's evidence model;
- introduces unsupported diagnostic certainty;
- weakens capture-quality safeguards;
- reintroduces SD-WAN-specific product assumptions into generic components;
- creates insecure default behavior;
- introduces unbounded resource usage without justification;
- relies on cloud services for core operation;
- compromises testability or deterministic behavior.

## Conflict policy

When upstream behavior and TraceSleuth architecture conflict:

1. preserve the useful underlying idea or bug fix where appropriate;
2. adapt it to TraceSleuth's current interfaces and models;
3. do not retain obsolete structure solely to make future rebases easier;
4. document material divergence in an ADR when it represents a durable architectural decision.

TraceSleuth is not required to remain merge-compatible with SD-WAN Triage indefinitely.

## Attribution of imported code

The repository-level MIT license remains in place. Do not remove upstream copyright or permission notices.

When a later upstream change is imported substantially, the pull request should identify:

- upstream repository;
- source commit SHA or tag;
- files or behavior imported;
- local adaptations;
- associated tests.

Where source files contain specific upstream copyright headers, retain them unless legal review establishes a reason to do otherwise.

## Example pull request note

```text
Upstream provenance
-------------------
Source: https://github.com/gocisse/sdwan-triage
Commit: <full SHA>
Imported behavior: <concise description>
TraceSleuth adaptations: <concise description>
Tests: <tests/fixtures added or updated>
```

## Historical references and product branding

Automated branding checks must allow historical and attribution documents to contain the name `SD-WAN Triage`. Product-facing code, UI, binaries, new documentation, runtime banners, configuration names, and release artifacts should use `TraceSleuth` except where a compatibility alias is intentionally documented.

Never perform a blind repository-wide replacement that damages provenance records or historical references.