# Origin and project evolution

## Summary

TraceSleuth began from the source code of the MIT-licensed **SD-WAN Triage** project by Gocisse. The imported baseline is recorded precisely in the repository-level `UPSTREAM.md` file.

TraceSleuth preserves that origin visibly and respectfully. It does not erase historical references, remove upstream copyright rights, or imply that the original author endorses the downstream project.

## Why TraceSleuth exists

SD-WAN Triage provides a substantial Go-based PCAP analysis application with an embedded web frontend, CLI reporting, packet-capture processing, protocol analyzers, timeline data, packet comparison, export capabilities, and a local-first deployment model.

TraceSleuth retains useful foundations from that work but changes the product's primary question from an SD-WAN-centric forensic workflow to a broader network-engineering problem:

> What looks wrong in this capture, what evidence supports that conclusion, how confident are we, what else could explain it, and which packets should the engineer inspect?

The intended scope includes campus, data-center, enterprise LAN, WAN, routed, Internet-edge, server, highly redundant, LACP/MLAG, voice, and multi-vendor environments.

## Architectural evolution

The imported implementation uses a central processor with many protocol-specific analyzers, a shared report structure, per-packet detector registration, protocol-specific state, a two-capture LAN/WAN comparator, a Go HTTP API, an embedded React frontend, SQLite-based user management, and local filesystem storage.

TraceSleuth will evolve that foundation incrementally rather than through a disruptive rewrite. The planned architectural changes include:

1. **Capture trust before diagnosis** — capture format, truncation, timestamp quality, malformed input, interface metadata, duplication, and visibility limitations are assessed before network-pathology findings are trusted.
2. **Normalized observations** — protocol facts become reusable observations rather than being independently reinterpreted by each detector.
3. **First-class evidence** — findings carry packet references, time ranges, affected entities, metrics, thresholds, alternatives, capture limitations, Wireshark filters, and recommended validation steps.
4. **Stable detector lifecycle** — detectors receive IDs, versions, categories, prerequisites, declared state requirements, explicit thresholds, and documented confidence limitations.
5. **Correlation instead of isolated alarms** — related STP, LACP, FHRP, duplicate-frame, storm, TCP, and service events can contribute explainably to higher-level findings.
6. **Generalized multi-capture reasoning** — the imported two-sided LAN/WAN comparison concept becomes a flexible capture-point model with explicit timing uncertainty.
7. **Troubleshooting-first UI** — findings, evidence, packet references, capture quality, timeline, topology, conversations, protocols, and reports become first-class diagnostic workflows.
8. **Secure self-hosting** — unsafe universal credentials, weak bootstrap behavior, untrusted filename handling, parser attack surfaces, uncontrolled concurrency, retention ambiguity, and supply-chain gaps are addressed explicitly.

## Deterministic-first product principle

TraceSleuth's primary findings are intended to come from protocol parsing, state machines, time-series analysis, packet correlation, frame fingerprinting, statistical analysis, standards-based validation, deterministic rules, and documented heuristics.

Optional AI functionality may later explain or summarize deterministic findings. AI is not intended to be the primary authority deciding whether a loop, LACP fault, STP failure, retransmission problem, MLAG inconsistency, or other network pathology exists.

## Evidence and epistemic discipline

TraceSleuth distinguishes among directly observed facts, strong inference, probability, possibility, and informational context. A packet capture often exposes symptoms without exposing the physical root cause. Therefore the project avoids statements such as "the MLAG peer link is down" unless the capture directly supports that fact.

The product model is intended to express categories such as:

- `observed`
- `strongly_inferred`
- `probable`
- `possible`
- `informational`

This distinction is central to the project's credibility and false-positive resistance.

## Independent project identity

TraceSleuth has its own:

- product name and mission;
- semantic version lineage beginning at `0.1.0`;
- repository and release lifecycle;
- architecture roadmap;
- documentation structure;
- detector validation requirements;
- security and deployment model.

The project may still review useful upstream changes. It is not required to remain permanently merge-compatible with SD-WAN Triage, and architectural quality takes precedence over easy rebasing.

## Attribution

The imported `LICENSE` retains the upstream MIT license and copyright statement. Additional TraceSleuth contribution notices may be added without deleting upstream rights.

The standard acknowledgement is:

> TraceSleuth originated from the MIT-licensed SD-WAN Triage project by Gocisse. TraceSleuth preserves attribution to the original project while pursuing an independent architecture, roadmap, product identity, and network-diagnostics mission.

For the exact baseline commit and import details, see `UPSTREAM.md`.