#!/usr/bin/env bash
set -euo pipefail

fail() {
  printf 'Version contract failed: %s\n' "$1" >&2
  exit 1
}

[[ -f VERSION ]] || fail 'VERSION file is missing'

version="$(tr -d '\r\n' < VERSION)"
[[ -n "$version" ]] || fail 'VERSION is empty'

if ! printf '%s\n' "$version" | grep -Eq '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'; then
  fail "VERSION '$version' is not a three-component Semantic Version"
fi

grep -Fq "## [$version]" CHANGELOG.md || fail "CHANGELOG.md has no [$version] release section"
support_line="${version%.*}.x"
grep -Fq "| \`$support_line\` |" SECURITY.md || fail "SECURITY.md does not describe support for current $support_line version line"
grep -Fq "**Current version line:** \`$version\` bootstrap" ROADMAP.md || fail "ROADMAP.md does not declare $version as the current bootstrap line"
grep -Fq 'The repository-root `VERSION` file is the authoritative source' docs/project/VERSIONING.md || fail 'VERSIONING.md does not declare VERSION authoritative'
grep -Fq 'The current version is declared by the repository-root `VERSION` file' docs/project/RELEASE_PROCESS.md || fail 'RELEASE_PROCESS.md must derive current-release status from VERSION (not a stale hard-coded version)'
grep -Fq 'BINARY_NAME  := tracesleuth' Makefile || fail 'Makefile does not build the tracesleuth product artifact'
grep -Fq 'VERSION      := $(shell tr -d' Makefile || fail 'Makefile does not derive VERSION from the root VERSION file'
grep -Fq 'BINARY_NAME: tracesleuth' .github/workflows/release.yml || fail 'release workflow artifact identity is not tracesleuth'
grep -Fxq 'module github.com/DanielDietz-de/TraceSleuth' go.mod || fail 'Go module does not match TraceSleuth repository'
if git grep -n -F 'github.com/gocisse/sdwan-triage/' -- '*.go'; then
  fail 'Go source still imports the inherited module path'
fi
# Nested Go modules are excluded from root 'go test ./...', but still ship
# source code and must resolve their self-imports against the new root module.
mapfile -d '' module_manifests < <(git ls-files -z -- 'go.mod' '**/go.mod')
[[ ${#module_manifests[@]} -ge 2 ]] || fail 'Expected root and tracked nested Go module manifests'
for manifest in "${module_manifests[@]}"; do
  if grep -Fq 'github.com/gocisse/sdwan-triage' "$manifest"; then
    fail "Inherited Go module remains in $manifest"
  fi
done
grep -Fxq 'module github.com/DanielDietz-de/TraceSleuth/web/backend' web/backend/go.mod ||
  fail 'Nested web/backend module declaration is not canonical'
grep -Fxq 'replace github.com/DanielDietz-de/TraceSleuth => ../..' web/backend/go.mod ||
  fail 'Nested web/backend must resolve the local TraceSleuth source root'
grep -Fq "version-${version}-blue" README.md || fail "README version badge is not aligned with VERSION=$version"

# During the bootstrap phase a few legacy runtime surfaces intentionally remain,
# including the command source directory, frontend package name,
# API metadata, and some configuration/storage paths. The baseline audit and
# roadmap track those migration gaps explicitly; they are not treated as aligned
# until the corresponding implementation work is complete and CI is extended.
printf 'TraceSleuth bootstrap version contract OK: %s\n' "$version"
