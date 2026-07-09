# Support

TraceSleuth is an open-source project in pre-1.0 development. The project does not currently provide a paid support contract, response-time SLA, or guaranteed remediation timeline.

## Before asking for help

Review:

- `README.md`
- `ROADMAP.md`
- `docs/project/SCOPE_AND_LIMITATIONS.md`
- `docs/audits/INITIAL_BASELINE_AUDIT.md`
- relevant architecture/detector documentation
- existing GitHub issues and discussions where available.

## Bug reports

A useful bug report should include:

- TraceSleuth version or exact commit;
- operating system and architecture;
- CLI command or UI workflow;
- expected behavior;
- actual behavior;
- sanitized logs;
- whether the problem reproduces with a synthetic/minimal capture;
- whether the capture is PCAP or PCAPNG;
- relevant capture metadata such as link type and snap length when known.

Do not attach private customer or production captures publicly.

## Detector false positives

A false-positive report should include:

- detector/finding ID when available;
- TraceSleuth version and detector version;
- exact finding output;
- why the condition is known to be healthy or explained by another mechanism;
- capture context, such as SPAN/TAP/ERSPAN/packet broker, member-link mirroring, direction, and capture point;
- minimal synthetic reproduction when possible;
- expected forbidden finding.

High-value examples include dual-source SPAN duplication, legitimate LACP failover, intentional FHRP transitions, normal multicast, host-boot ARP bursts, and TCP reordering without loss.

## Detector false negatives

Include:

- what fault was known to exist;
- how it was independently verified;
- which packets/protocol fields prove the condition;
- relevant packet numbers or Wireshark filters;
- capture limitations;
- minimal redistributable fixture if possible.

## Security issues

Do not disclose exploitable vulnerabilities publicly. Follow `SECURITY.md`.

## PCAP confidentiality

Packet captures may contain credentials, tokens, personal data, internal network information, application content, and voice/media payloads. See `docs/security/PCAP_DATA_SENSITIVITY.md`.

## Scope boundaries

TraceSleuth does not promise to infer facts that are not observable from the capture. Missing Ethernet headers, truncation, capture loss, one-sided traffic, absent control-plane packets, capture duplication, and unsynchronized clocks can limit conclusions.

An answer of "insufficient evidence" can be correct.

## Project maturity

Version `0.1.0` is a bootstrap line. Advanced TraceSleuth detector architecture and production hardening remain under active development. Do not assume roadmap entries are implemented.
