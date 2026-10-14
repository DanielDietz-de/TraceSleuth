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
grep -Fq "**Current version line:** \`$version\` bootstrap" ROADMAP.md || fail "ROADMAP.md does not declare $version as the current bootstrap line"
grep -Fq 'The repository-root `VERSION` file is the authoritative source' docs/project/VERSIONING.md || fail 'VERSIONING.md does not declare VERSION authoritative'
grep -Fq 'BINARY_NAME  := tracesleuth' Makefile || fail 'Makefile does not build the tracesleuth product artifact'
grep -Fq 'VERSION      := $(shell tr -d' Makefile || fail 'Makefile does not derive VERSION from the root VERSION file'
grep -Fq 'BINARY_NAME: tracesleuth' .github/workflows/release.yml || fail 'release workflow artifact identity is not tracesleuth'
grep -Fq "version-${version}-blue" README.md || fail "README version badge is not aligned with VERSION=$version"

# During the bootstrap phase a few legacy runtime surfaces intentionally remain,
# including the Go module path, command source directory, frontend package name,
# API metadata, and some configuration/storage paths. The baseline audit and
# roadmap track those migration gaps explicitly; they are not treated as aligned
# until the corresponding implementation work is complete and CI is extended.
printf 'TraceSleuth bootstrap version contract OK: %s\n' "$version"
