#!/usr/bin/env bash
set -euo pipefail

# Defense-in-depth for GitHub Actions release authorization. The workflow job
# also restricts event/ref combinations, but manual dispatch can select tags,
# so never classify a tag/ref push as a trusted main release.
version="$(tr -d '\r\n' < VERSION)"
expected="v${version}"

if [[ "${GITHUB_EVENT_NAME:-}" == workflow_dispatch && "${GITHUB_REF:-}" == refs/heads/main ]]; then
  tag="$expected"
  if [[ "${RELEASE_INPUT_VERSION:-}" != "$version" ]]; then
    echo 'Manual release VERSION does not match the repository.' >&2
    exit 1
  fi
elif [[ "${GITHUB_EVENT_NAME:-}" == push && "${GITHUB_REF:-}" == refs/heads/main ]]; then
  tag="$expected"
  subject="${RELEASE_MESSAGE:-}"
  subject="${subject%%$'\n'*}"
  if [[ "$subject" != "release: $expected" && "$subject" != "release: $expected "* ]]; then
    echo 'A main-branch release requires release: vX.Y.Z in the commit subject.' >&2
    exit 1
  fi
else
  echo 'Release must originate from a pushed version tag or an authorized main branch.' >&2
  exit 1
fi

if [[ "$tag" != "$expected" ]]; then
  printf 'Tag/version mismatch: tag=%s VERSION=%s\n' "$tag" "$version" >&2
  exit 1
fi

bash scripts/check-version-contract.sh

: "${GITHUB_OUTPUT:?GITHUB_OUTPUT is required}"
{
  printf 'tag=%s\n' "$tag"
  printf 'version=%s\n' "$version"
  printf 'commit=%s\n' "$(git rev-parse --short HEAD)"
  printf 'date=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
} >> "$GITHUB_OUTPUT"
