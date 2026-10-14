#!/usr/bin/env bash
# Compatibility wrapper: DO NOT build or publish the archived unauthenticated
# web/backend server. All builds must use the hardened TraceSleuth runtime.
set -euo pipefail
repo_root="$(cd "$(dirname "$0")/.." && pwd)"
printf '%s\n' "Legacy standalone web/backend build retired; building canonical TraceSleuth."
exec make -C "$repo_root" build
