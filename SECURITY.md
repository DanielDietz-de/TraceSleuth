# Security policy

TraceSleuth processes untrusted packet captures and may be exposed to malformed binary input, confidential enterprise traffic, authentication data, and large resource-intensive workloads. Security reports are taken seriously.

## Supported versions

TraceSleuth is currently pre-1.0.

| Version line | Support status |
|---|---|
| `0.1.x` | Bootstrap/development line; security fixes may be applied while the product remains explicitly not production-ready. |
| Older or untagged upstream-derived builds | Not supported as TraceSleuth releases. |

This table will be updated when additional release lines exist. It is not a promise of indefinite maintenance.

## Reporting a vulnerability

Do **not** open a public GitHub issue for a vulnerability that could put users, systems, credentials, packet captures, or infrastructure at risk.

Use GitHub's private vulnerability reporting feature for this repository when it is available. If private reporting is unavailable, open a minimal public issue that asks the maintainer to establish a private communication channel **without disclosing exploit details, secrets, affected packet captures, or reproduction material publicly**.

Do not invent or infer a maintainer email address. This repository intentionally does not publish a fabricated security contact.

## What to include

A useful report should contain, where safe:

- affected TraceSleuth version or commit;
- affected component/path;
- vulnerability class;
- impact;
- prerequisites;
- minimal reproduction steps;
- proof of concept that avoids exposing real credentials or private customer captures;
- whether authentication is required;
- whether remote, local, or uploaded-input exploitation is involved;
- operating system and architecture;
- suggested mitigation if known;
- whether the issue has been disclosed elsewhere.

For malformed-PCAP parser issues, prefer a minimal synthetic reproducer. Do not submit private production captures unless a secure private exchange has been explicitly arranged.

## Scope

Security-relevant areas include:

- PCAP and PCAPNG parsing;
- protocol parsers and custom TLV/binary decoding;
- integer overflow and unsafe allocation lengths;
- parser panics reachable through untrusted input;
- CPU or memory exhaustion;
- path traversal and unsafe uploaded filenames;
- temporary-file races or symlink attacks;
- authentication and authorization;
- JWT/session handling;
- CSRF, CORS, secure headers, and reverse-proxy trust;
- WebSocket authentication and connection exhaustion;
- upload-size enforcement;
- analysis concurrency and timeout limits;
- retention and deletion failures;
- leakage of PCAP content, credentials, tokens, or secrets;
- command execution through integrations or export functions;
- vulnerable dependencies;
- release artifact or supply-chain compromise.

## Out of scope without additional evidence

The following do not by themselves constitute a security vulnerability:

- a detector false positive or false negative without a security boundary impact;
- expected visibility of plaintext protocol content already present in a user-provided PCAP;
- denial of service requiring the operator to intentionally disable configured limits;
- unsupported deployment modes that are clearly documented as unsupported;
- findings that depend solely on obsolete upstream builds rather than a supported TraceSleuth version.

Detector correctness bugs should still be reported through the appropriate false-positive or false-negative issue template once those templates are available.

## Disclosure expectations

Please allow maintainers a reasonable opportunity to investigate and prepare a fix before public disclosure. TraceSleuth does not publish a fake acknowledgement, remediation, or response-time SLA that the project cannot guarantee.

The project will aim to:

1. preserve reporter confidentiality where possible;
2. reproduce and assess the issue;
3. distinguish vulnerability, robustness defect, and detector-correctness issue;
4. add regression coverage where feasible;
5. document affected versions and mitigation honestly;
6. avoid claiming a fix before validation exists.

## Current known bootstrap limitations

TraceSleuth `0.1.0` is explicitly not production-ready. The baseline audit documents inherited risks. Two critical inherited defaults have already been addressed in the bootstrap branch:

- the universal `admin/admin` bootstrap credential was removed;
- the hard-coded JWT fallback signing secret was removed.

Known remaining hardening work includes, but is not limited to:

- uploaded filename/path construction;
- configurable retention and storage quotas;
- global analysis concurrency/resource limits;
- comprehensive parser fuzzing;
- WebSocket query-token handling;
- secure-header and CSRF review;
- supported non-loopback deployment behavior;
- reverse-proxy trust configuration;
- temporary-file and export hardening.

See `docs/audits/INITIAL_BASELINE_AUDIT.md`, `ROADMAP.md`, and `docs/project/SCOPE_AND_LIMITATIONS.md`.

## Sensitive packet-capture data

A PCAP may contain:

- usernames and passwords;
- bearer tokens;
- API keys;
- cookies and session identifiers;
- personal data;
- internal IP addresses and network design;
- DNS names;
- file contents;
- email or messaging content;
- voice/media payloads;
- authentication handshakes;
- proprietary application data.

Operators must treat captures, reports, exports, backups, crash data, and test fixtures accordingly.

See `docs/security/PCAP_DATA_SENSITIVITY.md`.

## Security automation

The repository's security workflow is intended to include:

- `govulncheck`;
- Gitleaks current-tree scanning;
- CodeQL for Go and JavaScript/TypeScript.

Later phases add parser fuzzing, malformed-input corpora, SBOM generation, container scanning, dependency review, and release provenance as implementation matures.

A passing scanner is not proof that TraceSleuth is secure.
