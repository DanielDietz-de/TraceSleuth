# Upstream provenance

TraceSleuth originated from the MIT-licensed **SD-WAN Triage** project by Gocisse. TraceSleuth preserves attribution to the original project while pursuing an independent architecture, roadmap, product identity, release lifecycle, and network-diagnostics mission.

## Baseline record

| Field | Value |
|---|---|
| Original project | SD-WAN Triage |
| Original repository | https://github.com/gocisse/sdwan-triage |
| Upstream author / copyright holder | Gocisse, as represented by the upstream MIT license |
| Upstream license | MIT License |
| Exact imported upstream commit | `43c6cd412860a5219577be6d30feca2db7f57309` |
| Nearest preceding upstream release tag | `v6.2.0.0` |
| Commit represented by that release tag | `2855ef6d1cd26909e70e60b893c13341efab9767` |
| Relationship of baseline to tag | The imported baseline is one upstream commit after `v6.2.0.0`; that additional commit added the upstream `README.md` and `LICENSE`. |
| TraceSleuth import commit | `da35429b7284bb6a2bc61f2049209dfff299703c` |
| Baseline import date | 2026-07-09 |

The baseline identity was verified by comparing representative file blob hashes between the TraceSleuth import and the upstream repository and by comparing the upstream release tag with the exact upstream baseline commit.

## Relationship between the projects

TraceSleuth is an **independent downstream project**. It is not presented as an official continuation, endorsed version, successor maintained by the original author, or official replacement for SD-WAN Triage.

The project intentionally retains useful upstream capabilities, including local-first PCAP analysis, the Go backend, React web interface, CLI operation, JSON/report output, protocol analysis, timeline functionality, packet inspection, and multi-capture comparison concepts. TraceSleuth's primary mission is broader: deterministic, evidence-backed diagnosis of network faults and pathologies across enterprise LAN, data-center, WAN, SD-WAN, server, voice, Internet-edge, and highly redundant environments.

TraceSleuth is not intended to remain a rebranding exercise or a downstream patch collection. Architectural divergence is expected where needed to support normalized packet observations, capture-integrity analysis, structured evidence, detector lifecycle contracts, correlation, topology reasoning, multi-capture analysis, L2 fault analysis, STP/LACP/redundancy diagnosis, MLAG symptom inference, transport pathology analysis, and production-conscious self-hosting.

## Attribution and copyright

The upstream MIT copyright and permission notice are preserved in `LICENSE` and must not be removed from copies or substantial portions of upstream-derived software.

TraceSleuth contributions may add separate copyright notices where appropriate, but such additions do not replace, erase, or narrow upstream rights and attribution.

Historical documents may and should refer to **SD-WAN Triage** by its original name. Product-facing TraceSleuth documentation must not rewrite history or imply upstream endorsement.

## Reviewing future upstream changes

Upstream changes may be reviewed deliberately. TraceSleuth does not automatically backport or merge every upstream change. Each candidate change must be evaluated for:

- correctness and tests;
- security impact;
- compatibility with TraceSleuth's deterministic-first evidence model;
- architectural fit;
- licensing and attribution;
- overlap with independent TraceSleuth work;
- regression risk; and
- whether preserving easy upstream rebasing would compromise TraceSleuth's target architecture.

The detailed workflow is documented in `docs/development/UPSTREAM_WORKFLOW.md`.

## No endorsement claim

No statement in this repository should be interpreted as a claim that Gocisse or the SD-WAN Triage project endorses TraceSleuth. Any future endorsement or formal relationship must be documented only when explicit evidence exists.
