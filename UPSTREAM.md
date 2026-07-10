# Upstream provenance

TraceSleuth originated from the MIT-licensed **SD-WAN Triage** project.

## Baseline record

| Field | Value |
|---|---|
| Original project | SD-WAN Triage |
| Original repository | `https://github.com/gocisse/sdwan-triage` |
| Original author/copyright holder | Gocisse, as stated in the imported MIT license |
| Original license | MIT License |
| Exact upstream baseline commit | `43c6cd412860a5219577be6d30feca2db7f57309` |
| Upstream release/tag associated with the imported state | `v6.2.0.0` |
| TraceSleuth import commit | `da35429b7284bb6a2bc61f2049209dfff299703c` |
| Baseline import date | 2026-07-09 |

The baseline mapping was verified by comparing repository content at the TraceSleuth import with the stated upstream commit. At minimum, `README.md`, `go.mod`, and `cmd/sdwan-triage/main.go` have identical Git blob SHAs in both repositories at that baseline.

## Relationship between the projects

TraceSleuth is an independent downstream project. It preserves attribution to SD-WAN Triage and the original MIT copyright and permission notice while pursuing a different primary mission, architecture, release lifecycle, roadmap, documentation set, and network-diagnostics scope.

TraceSleuth is **not** represented as an official continuation of SD-WAN Triage, an endorsed build, or a replacement maintained by the original SD-WAN Triage author. No endorsement by the upstream author is claimed.

A concise acknowledgement used by the project is:

> TraceSleuth originated from the MIT-licensed SD-WAN Triage project by Gocisse. TraceSleuth preserves attribution to the original project while pursuing an independent architecture, roadmap, product identity, and network-diagnostics mission.

## History preservation status

The current TraceSleuth repository was imported as a single initial commit rather than as a history-preserving fork. The TraceSleuth import commit is:

```text
da35429b7284bb6a2bc61f2049209dfff299703c
```

This means the original upstream commit graph is not currently present in the TraceSleuth repository. This file records the exact source baseline explicitly so provenance remains auditable even though the initial import was squashed.

Rewriting the public repository history solely to graft the upstream commit graph onto the repository is not performed automatically. Such a rewrite would be disruptive for existing clones and references and must be an explicit maintainer decision.

## Future upstream review policy

Upstream changes may be reviewed deliberately when they provide relevant bug fixes, security improvements, protocol support, test improvements, or other value compatible with TraceSleuth's architecture and product mission.

TraceSleuth does not automatically merge or backport every upstream change. Each imported change should:

1. be reviewed for architectural compatibility;
2. retain applicable upstream attribution;
3. receive TraceSleuth-specific tests where behavior changes;
4. avoid reintroducing product identity, security behavior, or architectural assumptions that conflict with TraceSleuth;
5. be documented in the changelog when user-visible.

See `docs/development/UPSTREAM_WORKFLOW.md` for the operational workflow and `docs/history/ORIGIN.md` for the project history.