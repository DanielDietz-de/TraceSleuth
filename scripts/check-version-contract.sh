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
grep -Fq 'BINARY_NAME: tracesleuth' .github/workflows/validated-release.yml || fail 'validated release workflow artifact identity is not tracesleuth'
grep -Fq 'check-legacy-release-disabled.py' .github/workflows/validated-release.yml || fail 'validated publisher must check historical release workflow state'
grep -Fq 'gh release create' .github/workflows/validated-release.yml || fail 'validated publisher must build the release artifact'
grep -Fq 'retired:' .github/workflows/release.yml || fail 'historical release workflow must remain a retired stub'
if grep -Fq 'gh release create' .github/workflows/release.yml || grep -Fq 'tags:' .github/workflows/release.yml; then
  fail 'historical release workflow must have no tag-push trigger or publishing command'
fi
grep -Fq "version-${version}-blue" README.md || fail "README version badge is not aligned with VERSION=$version"

# During the bootstrap phase a few legacy runtime surfaces intentionally remain,
# including the Go module path, command source directory, frontend package name,
# API metadata, and some configuration/storage paths. The baseline audit and
# roadmap track those migration gaps explicitly; they are not treated as aligned
# until the corresponding implementation work is complete and CI is extended.
printf 'TraceSleuth bootstrap version contract OK: %s\n' "$version"
