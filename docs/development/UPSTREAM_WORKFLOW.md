# Upstream workflow

This document defines how TraceSleuth tracks its origin in SD-WAN Triage without sacrificing TraceSleuth's independent architecture or accidentally pushing changes to the upstream project.

## Baseline

The authoritative imported source baseline is:

```text
upstream repository: https://github.com/gocisse/sdwan-triage
upstream commit:     43c6cd412860a5219577be6d30feca2db7f57309
nearest prior tag:   v6.2.0.0
TraceSleuth import:  da35429b7284bb6a2bc61f2049209dfff299703c
import date:         2026-07-09
```

The imported commit is one commit ahead of the `v6.2.0.0` tag and adds the upstream README and MIT license.

## Important repository-history limitation

The current TraceSleuth Git repository was initialized with a single import commit rather than by preserving the full upstream Git history. Therefore the source baseline is documented explicitly in `UPSTREAM.md` and `docs/history/ORIGIN.md`.

Future maintainers must not pretend that the local Git ancestry itself proves upstream provenance. The provenance record, exact SHAs, file identity checks, and upstream comparison establish that relationship.

Reconstructing or grafting full upstream history later is a separate repository-administration decision and must not rewrite public history casually after releases or external contributions exist.

## Recommended remotes

For a normal developer clone:

```bash
git remote -v

git remote add upstream https://github.com/gocisse/sdwan-triage.git
git fetch upstream --tags
```

The intended model is:

```text
origin   -> https://github.com/DanielDietz-de/TraceSleuth
upstream -> https://github.com/gocisse/sdwan-triage
```

Before pushing, verify the destination explicitly:

```bash
git remote get-url origin
git remote get-url upstream
```

Never push TraceSleuth branches or tags to `upstream`.

## Reviewing an upstream change

Upstream integration is deliberate, not automatic.

1. Fetch the upstream remote and tags.
2. Identify the exact upstream commit or range under review.
3. Read the upstream diff and tests.
4. Determine whether the change overlaps TraceSleuth code that has diverged.
5. Evaluate correctness, security, licensing, evidence semantics, memory behavior, concurrency, API compatibility, UI impact, and test coverage.
6. Add TraceSleuth-specific regression tests when the change addresses a relevant defect.
7. Port or cherry-pick only when technically appropriate.
8. Preserve original copyright and attribution for upstream-derived code.
9. Record the source commit in the TraceSleuth commit message or pull request.
10. Run the complete applicable quality gate before merge.

## Merge, cherry-pick, or independent port

Use the least misleading method:

- **Merge** only when histories and architecture are sufficiently compatible and the resulting ancestry remains understandable.
- **Cherry-pick** when a self-contained upstream commit remains directly applicable.
- **Independent port** when TraceSleuth architecture has diverged. The pull request should still identify the upstream source and explain what was adapted.
- **Do not import** when a change conflicts with TraceSleuth's deterministic-first evidence model, security requirements, public API contract, or architecture.

TraceSleuth is not required to remain merge-compatible with SD-WAN Triage indefinitely.

## Conflict policy

When upstream and TraceSleuth goals conflict, prefer:

1. protocol correctness;
2. evidence traceability;
3. false-positive resistance;
4. capture-integrity awareness;
5. secure handling of untrusted PCAP input;
6. bounded resource use;
7. testability and deterministic output;
8. maintainability; and only then
9. ease of future upstream rebasing.

## Attribution when code is reused

Do not remove upstream notices from files or substantial portions of code where required by the MIT License. Do not replace the upstream copyright notice with a TraceSleuth-only notice.

New TraceSleuth contributions may add additional notices where appropriate.

## Historical names

Automated branding checks must allow intentional references to `SD-WAN Triage` and `sdwan-triage` in:

- `UPSTREAM.md`;
- `LICENSE`;
- `docs/history/`;
- this upstream workflow document;
- audit records describing the inherited baseline;
- changelog entries that explain upstream-derived history; and
- source comments or compatibility documentation where the legacy name is technically relevant.

A blind global replacement is prohibited.

## Release independence

TraceSleuth does not inherit upstream 6.x version numbers. TraceSleuth starts at `0.1.0` and follows its own release process and roadmap.
