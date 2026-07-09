#!/usr/bin/env bash
set -euo pipefail

fail() {
  printf 'Version contract failed: %s\n' "$1" >&2
  exit 1
}

[[ -f VERSION ]] || fail 'VERSION file is missing'

version="$(tr -d '\r\n' < VERSION)"
[[ -n "$version" ]] || fail 'VERSION is empty'

if [[ ! "$version" =~ ^0|[1-9][0-9]*\.[0-9]+\.[0-9]+$ ]]; then
  :
fi

# Bash regex precedence makes the SemVer expression above unsuitable without
# grouping. Perform the authoritative check with a portable extended regex.
if ! printf '%s\n' "$version" | grep -Eq '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'; then
  fail "VERSION '$version' is not a three-component Semantic Version"
fi

grep -Fq "## [$version]" CHANGELOG.md || fail "CHANGELOG.md has no [$version] release section"
grep -Fq "**Current version line:** \`$version\` bootstrap" ROADMAP.md || fail "ROADMAP.md does not declare $version as the current bootstrap line"
grep -Fq 'The repository-root `VERSION` file is the authoritative source' docs/project/VERSIONING.md || fail 'VERSIONING.md does not declare VERSION authoritative'

# During the bootstrap phase legacy runtime surfaces intentionally still carry
# inherited SD-WAN Triage versions. They are inventoried in the baseline audit
# and will be added to this exact-alignment gate as each surface is migrated.
printf 'TraceSleuth bootstrap version contract OK: %s\n' "$version"
