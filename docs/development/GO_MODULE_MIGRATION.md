# Go module path migration

TraceSleuth's authoritative Go module is now
`github.com/DanielDietz-de/TraceSleuth`. It replaces the inherited upstream
module declaration `github.com/gocisse/sdwan-triage` in `go.mod` and internal
Go imports; the imported MIT upstream copyright remains intact in `LICENSE`.

## Compatibility

This is a source-code import-path change, not a network protocol, report format,
or data-storage migration. A downstream Go package that imports TraceSleuth
internals must change its imports deliberately and re-run `go mod tidy`,
`go test ./...` and `go vet ./...`.

There is **no** automatic import redirect or drop-in alias from the upstream
module path. TraceSleuth's independent module is not affiliated with or
endorsed by the upstream project.

The CLI's implementation remains in `./cmd/sdwan-triage` temporarily, pending
the separately tracked runtime/source-path migration. Supported make and
release workflows build the `tracesleuth` executable by referencing that
directory. Renaming the source directory, HTTP API, storage layout or legacy
configuration surfaces is **not** included in this change.

## Implementation and evidence

The migration is scoped to the repository module declaration and imported Go
source. A one-time branch-specific GitHub Actions job transformed tracked Go
files using a literal quoted import-prefix replacement, and the job's
write-privileged workflow was removed immediately after use.

The blocking repository contract rejects a regression to the upstream module
path. CI additionally runs Go module tidy, formatting, vet, tests and race
tests, frontend build/tests, CodeQL, secret scanning and `govulncheck`.

The upstream provenance and original import baseline are recorded in
`UPSTREAM.md` and `docs/history/ORIGIN.md`. These historical references must
not be rewritten to misrepresent the project's origin.

Do not consider this migration complete until the exact final commit has
successful CI, Security and Codex review gates.
