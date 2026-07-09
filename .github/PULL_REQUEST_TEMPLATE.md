## Summary

Describe the problem and the implemented change.

## Implemented scope

- 

## Explicitly deferred scope

- 

## Architecture impact

Describe affected packages, interfaces, data models, ADRs, compatibility layers, and migration behavior.

## Detector/evidence impact

Complete when detector behavior changes:

- Detector ID:
- Detector version change:
- Required observations/capture capabilities:
- Evidence added/changed:
- Confidence/certainty impact:
- Alternative explanations considered:
- Capture limitations:
- Wireshark validation:

## Tests

Check only what actually ran.

- [ ] Go formatting verification
- [ ] `go vet ./...`
- [ ] `go test ./...`
- [ ] `go test -race ./...`
- [ ] Frontend build/typecheck
- [ ] Frontend lint
- [ ] Frontend tests
- [ ] Positive PCAP fixture
- [ ] Negative PCAP fixture
- [ ] Adversarial false-positive fixture
- [ ] Boundary tests
- [ ] Malformed-input tests
- [ ] Fuzz test or fuzz smoke test
- [ ] Golden test
- [ ] Integration test
- [ ] Benchmark/performance measurement

### Commands and results

```text
Paste exact commands and pass/fail results. Do not claim checks that were not executed.
```

## Security impact

Describe effects on untrusted PCAP handling, authentication, authorization, filenames/paths, temporary files, retention, resource limits, logging, secrets, WebSockets, dependencies, or supply chain.

## Documentation

List documentation added or changed.

## Version and changelog

- [ ] `VERSION` remains correct.
- [ ] Version-bearing surfaces remain aligned or the migration gap is explicitly documented.
- [ ] `CHANGELOG.md` updated when behavior changed.
- [ ] Detector catalogue updated when detector behavior changed.

## Upstream provenance

For upstream-derived code, identify:

- upstream repository;
- exact source commit;
- merge/cherry-pick/independent-port method;
- attribution considerations.

Use `N/A` when no upstream-derived code is involved.

## PCAP/data handling

- [ ] No private customer or production capture was committed.
- [ ] Third-party fixtures have documented redistribution rights.
- [ ] Logs/examples contain no credentials, tokens, or sensitive payloads.

## Known limitations and risks

List remaining limitations, failed checks, waivers, and follow-up work explicitly.

## Reviewer focus

Call out the highest-risk parts of the change.
