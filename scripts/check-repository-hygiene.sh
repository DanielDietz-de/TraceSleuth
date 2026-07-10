#!/usr/bin/env bash
set -euo pipefail

# Prevent new repository hygiene debt without pretending that inherited
# historical artifacts have already been removed. The initial baseline audit
# documents the existing committed binaries, archives and .DS_Store files.
#
# Usage:
#   scripts/check-repository-hygiene.sh [base-ref]
#
# With a base ref, only files added or modified since that ref are checked.
# Without a base ref, all tracked files are checked.

base_ref="${1:-}"
max_bytes=$((5 * 1024 * 1024))

if [[ -n "${base_ref}" ]]; then
    if ! git rev-parse --verify "${base_ref}^{commit}" >/dev/null 2>&1; then
        echo "Base ref does not resolve to a commit: ${base_ref}" >&2
        exit 2
    fi

    mapfile -d '' files < <(
        git diff --name-only --diff-filter=AM -z "${base_ref}"...HEAD
    )
else
    mapfile -d '' files < <(git ls-files -z)
fi

failures=0

is_forbidden_artifact() {
    local path="$1"
    local lower="${path,,}"

    case "${lower}" in
        *.pcap|*.pcapng|*.cap|*.exe|*.dll|*.dmg|*.pkg|*.msi|*.deb|*.rpm|*.zip|*.tar|*.tar.gz|*.tgz|*.7z|*.rar)
            return 0
            ;;
        */.ds_store|.ds_store)
            return 0
            ;;
    esac

    return 1
}

for path in "${files[@]}"; do
    [[ -f "${path}" ]] || continue

    if is_forbidden_artifact "${path}"; then
        echo "Repository hygiene violation: forbidden newly tracked artifact: ${path}" >&2
        failures=$((failures + 1))
        continue
    fi

    size="$(wc -c < "${path}")"
    if (( size > max_bytes )); then
        echo "Repository hygiene violation: ${path} is ${size} bytes (> ${max_bytes})" >&2
        failures=$((failures + 1))
    fi
done

if (( failures > 0 )); then
    echo "Repository hygiene check failed with ${failures} violation(s)." >&2
    echo "Do not commit private captures, generated binaries, archives or unintended large files." >&2
    exit 1
fi

printf 'Repository hygiene check passed for %d tracked change(s).\n' "${#files[@]}"
