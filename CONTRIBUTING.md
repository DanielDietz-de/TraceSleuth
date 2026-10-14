# Contributing to TraceSleuth

Thank you for helping build TraceSleuth.

TraceSleuth is a deterministic-first packet-capture analysis platform. Contributions are evaluated for protocol correctness, evidence traceability, false-positive resistance, capture limitations, bounded resource use, security, tests, and documentation—not merely whether a feature produces an interesting result.

## Read first

Before a substantial change, review:

- `README.md`
- `ROADMAP.md`
- `UPSTREAM.md`
- `docs/audits/INITIAL_BASELINE_AUDIT.md`
- `docs/architecture/ARCHITECTURE.md`
- `docs/architecture/ANALYSIS_PIPELINE.md`
- `docs/architecture/FINDING_AND_EVIDENCE_MODEL.md`
- `docs/architecture/CORRELATION_ENGINE.md`
- `docs/project/SCOPE_AND_LIMITATIONS.md`
- `docs/testing/TEST_STRATEGY.md`
- `SECURITY.md`

## Core contribution principles

### Do not invent observations

Do not invent:

- packet fields;
- standards citations;
- Wireshark display fields;
- vendor behavior;
- protocol semantics;
- packet references;
- detector status;
- test results.

When behavior is uncertain, verify it against authoritative standards, public vendor documentation, Wireshark behavior, or actual packet fixtures.

### Evidence before conclusion

A major detector should explain:

- what was observed;
- which packets support it;
- time range;
- affected entities;
- reasoning;
- confidence and certainty;
- alternative explanations;
- capture limitations;
- independent validation steps.

### False-positive resistance

For high-risk heuristic detectors, healthy alternative explanations are first-class test cases.

Examples:

- dual-source SPAN duplication;
- packet brokers;
- capturing both sides of a link;
- port-channel member mirroring;
- valid LACP failover;
- legitimate FHRP transitions;
- normal multicast;
- TCP reordering without loss.

### Preserve provenance

Do not erase upstream attribution. Historical references to SD-WAN Triage are intentional in `UPSTREAM.md`, `LICENSE`, `NOTICE`, `docs/history/`, audits, upstream workflow documentation, and compatibility notes.

Do not use blind global replacement.

## Development workflow

1. Create a focused branch from current `main`.
2. Keep unrelated changes separate.
3. Add or update tests before or with behavior changes.
4. Update documentation and changelog when behavior changes.
5. Run applicable quality gates.
6. Open a pull request with explicit implemented/deferred scope.
7. Do not hide failing tests or known limitations.

Example branch names:

```text
feat/capture-quality
feat/lacp-parser
fix/tcp-retransmission-span-duplication
security/upload-path-containment
docs/stp-detector-guide
```

## Building

```bash
make build
```

The product artifact is:

```text
build/tracesleuth
```

## Quality checks

Useful local commands:

```bash
make check-version
make fmt-check
make vet
make test
make test-race
```

Frontend:

```bash
cd web/frontend
npm ci
npm run build
npm run lint
npm run test
```

## Detector contributions

A stable detector requires:

- unique stable ID;
- detector version;
- description and purpose;
- implemented algorithm;
- declared capture prerequisites;
- positive PCAP fixture;
- negative PCAP fixture;
- false-positive fixture where relevant;
- unit tests;
- boundary tests;
- confidence documentation;
- limitations documentation;
- Wireshark validation filter;
- UI presentation;
- JSON output;
- detector catalogue entry;
- evidence packet references;
- changelog entry.

High-risk probable-loop and MLAG-symptom detectors require multiple adversarial false-positive fixtures.

Do not mark an unvalidated detector stable.

## PCAP fixtures

Do not commit private customer or production captures.

Prefer:

- synthetic minimal captures;
- documented generators;
- expected and forbidden findings;
- explicit origin/license metadata.

Third-party captures require verified redistribution rights.

## Go style and architecture

- Run `gofmt`.
- Keep detector-local state bounded where practical.
- Propagate `context.Context` for cancellation/deadlines where relevant.
- Avoid global mutable detector state.
- Avoid panic for routine malformed input.
- Recover only at appropriate trust boundaries.
- Do not swallow parser errors without metrics or evidence.
- Keep serialized output deterministic.
- Avoid map-order-dependent findings.
- Prefer immutable normalized observations where practical.
- Avoid duplicating payload bytes into every evidence object.

## Frontend contributions

The UI is a troubleshooting interface, not merely a metrics dashboard.

Findings should make it easy to answer:

1. What happened?
2. Why does TraceSleuth think this?
3. What evidence supports it?
4. Which packets matter?
5. Which alternatives exist?
6. What limits confidence?
7. How can I validate this in Wireshark?
8. What should I investigate next?

Experimental detectors must be labeled honestly.

## Security contributions

PCAPs are untrusted input. Treat parsers, upload handling, filenames, temporary files, exports, WebSockets, authentication, and resource limits as security-sensitive.

For vulnerabilities, follow `SECURITY.md` rather than opening a public exploit report.

## Dependencies

Review `docs/security/DEPENDENCY_POLICY.md` before adding a dependency.

A direct runtime dependency should have a clear necessity, active maintenance, acceptable license, understood transitive impact, and tests.

## Upstream-derived changes

Follow `docs/development/UPSTREAM_WORKFLOW.md`.

When adapting upstream code:

- identify the exact source commit;
- preserve attribution;
- explain whether the change was merged, cherry-picked, or independently ported;
- do not sacrifice TraceSleuth architecture quality merely for easy rebasing.

## Pull request expectations

A useful PR description includes:

- problem statement;
- implemented scope;
- explicitly deferred scope;
- architecture impact;
- security impact;
- tests added/run;
- failures or waivers;
- detector acceptance status;
- docs changed;
- migration impact;
- upstream provenance when relevant.

## Documentation quality

Do not create empty placeholder documents. Every committed document should contain useful maintained content.

Documentation must distinguish:

```text
implemented
experimental
beta
stable
planned
deferred
not supported
```

## License

By contributing, you agree that your contribution may be distributed under the repository's MIT License.

Your contribution does not erase or replace upstream copyright and license notices.
