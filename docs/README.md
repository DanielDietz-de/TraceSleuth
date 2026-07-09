# TraceSleuth documentation

**Packets tell the story. TraceSleuth finds the problem.**

This documentation set supports the controlled transformation of the imported SD-WAN Triage baseline into the independent TraceSleuth network fault-analysis platform.

TraceSleuth `0.1.0` is a bootstrap line and is not production-ready. Documents clearly distinguish implemented, inherited-unclassified, experimental, beta, stable, planned, deferred, and unsupported capabilities.

## Start here

- [Project README](../README.md)
- [Roadmap](../ROADMAP.md)
- [Scope and limitations](project/SCOPE_AND_LIMITATIONS.md)
- [Initial baseline audit](audits/INITIAL_BASELINE_AUDIT.md)
- [Upstream provenance](../UPSTREAM.md)
- [Origin and evolution](history/ORIGIN.md)

## Architecture

- [Architecture](architecture/ARCHITECTURE.md)
- [Analysis pipeline](architecture/ANALYSIS_PIPELINE.md)
- [Finding and evidence model](architecture/FINDING_AND_EVIDENCE_MODEL.md)
- [Correlation engine](architecture/CORRELATION_ENGINE.md)

### Architecture decision records

- [ADR 0001 — Deterministic-first diagnosis](architecture/adr/0001-deterministic-first-diagnosis.md)
- [ADR 0002 — Incremental migration over a one-shot rewrite](architecture/adr/0002-incremental-migration-over-rewrite.md)
- [ADR 0003 — Repository-root VERSION is authoritative](architecture/adr/0003-authoritative-version-source.md)
- [ADR 0004 — Capture trust precedes fault diagnosis](architecture/adr/0004-capture-trust-before-fault-diagnosis.md)

## Detectors

- [Detector catalogue](detectors/DETECTOR_CATALOG.md)
- [Detector authoring guide](detectors/DETECTOR_AUTHORING_GUIDE.md)
- [Confidence model](detectors/CONFIDENCE_MODEL.md)

The stable TraceSleuth detector catalogue is intentionally empty in `0.1.0`. The imported code contains broad analyzers, but stable status requires the full detector acceptance criteria: stable ID/version, algorithm, positive and negative fixtures, adversarial false-positive fixtures where relevant, boundary tests, confidence/limitations, packet evidence, Wireshark validation, JSON/UI presentation, catalogue entry, and changelog coverage.

## Security and privacy

- [Security policy](../SECURITY.md)
- [Threat model](security/THREAT_MODEL.md)
- [PCAP data sensitivity](security/PCAP_DATA_SENSITIVITY.md)
- [Dependency policy](security/DEPENDENCY_POLICY.md)

Packet captures can contain credentials, tokens, cookies, personal data, internal addressing, DNS names, files, application payloads, and voice/media traffic. Do not commit private customer or production captures to the public repository.

## Testing and quality

- [Test strategy](testing/TEST_STRATEGY.md)
- [Baseline audit: tests, fuzzing, performance, and concurrency](audits/INITIAL_BASELINE_AUDIT.md)

The target test model includes unit tests, protocol parser tests, detector state-machine tests, positive/negative/adversarial PCAP fixtures, boundary tests, malformed-input tests, fuzzing, golden findings, integration tests, frontend tests, race tests, and benchmarks.

## Development

- [Development guide](development/DEVELOPMENT.md)
- [Upstream workflow](development/UPSTREAM_WORKFLOW.md)
- [Contributing](../CONTRIBUTING.md)
- [Pull request template](../.github/PULL_REQUEST_TEMPLATE.md)

## Project management

- [Versioning](project/VERSIONING.md)
- [Release process](project/RELEASE_PROCESS.md)
- [Scope and limitations](project/SCOPE_AND_LIMITATIONS.md)
- [Roadmap](../ROADMAP.md)
- [Changelog](../CHANGELOG.md)
- [Support](../SUPPORT.md)
- [Code of conduct](../CODE_OF_CONDUCT.md)

## Provenance

- [Upstream provenance](../UPSTREAM.md)
- [Notice](../NOTICE)
- [Origin and evolution](history/ORIGIN.md)
- [Upstream workflow](development/UPSTREAM_WORKFLOW.md)
- [License](../LICENSE)

TraceSleuth originated from the MIT-licensed SD-WAN Triage project by Gocisse. TraceSleuth preserves attribution while pursuing an independent architecture, roadmap, version lifecycle, product identity, and network-diagnostics mission. No upstream endorsement is claimed.

## Documentation still intentionally deferred

The project does not create empty documents simply to satisfy a directory checklist. The following subjects receive dedicated documents when implementation exists or enough source-grounded operational detail is available:

- installation and first-analysis guides after the CLI/runtime identity migration stabilizes;
- complete capture-quality detector guide after Phase 2 implementation;
- L2/STP/LACP/MLAG detector guides with tested algorithms and filters;
- API/OpenAPI documentation after versioned `/api/v1` implementation;
- Docker/systemd deployment after production-conscious artifacts exist;
- retention/backup operations after policy and cleanup implementation;
- performance baseline after actual benchmark measurements;
- golden-test and PCAP-corpus guides after the corpus is implemented.

This avoids documentation that falsely implies unimplemented functionality.
