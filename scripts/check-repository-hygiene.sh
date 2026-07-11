#!/usr/bin/env bash
set -euo pipefail

failures=0
max_bytes=$((10 * 1024 * 1024))
base_ref="${1:-}"

report_failure() {
  printf 'Repository hygiene failed: %s\n' "$1" >&2
  failures=$((failures + 1))
}

collect_changed_files() {
  if [[ -n "$base_ref" ]]; then
    if ! git rev-parse --verify "${base_ref}^{commit}" >/dev/null 2>&1; then
      printf 'Repository hygiene failed: base ref %q is unavailable\n' "$base_ref" >&2
      return 2
    fi
    git diff --name-only --diff-filter=ACMR "${base_ref}...HEAD"
    return
  fi

  if git rev-parse --verify 'HEAD^' >/dev/null 2>&1; then
    git diff --name-only --diff-filter=ACMR 'HEAD^' 'HEAD'
    return
  fi

  git ls-files
}

mapfile -t changed_files < <(collect_changed_files)

for path in "${changed_files[@]}"; do
  [[ -e "$path" ]] || continue

  case "$path" in
    testdata/pcaps/*.pcap|testdata/pcaps/*.pcapng|testdata/pcaps/*.cap)
      # Synthetic or redistributable corpus fixtures are allowed only under the
      # dedicated test corpus. MANIFEST.yaml provenance validation is added with
      # the corpus implementation phase.
      ;;
    *.pcap|*.pcapng|*.cap)
      report_failure "packet capture outside testdata/pcaps/: $path"
      ;;
  esac

  case "$path" in
    releases/*|web/releases/*|web/frontend/dist/*|cmd/sdwan-triage/dist/*|build/*)
      report_failure "generated or release artifact path changed: $path"
      ;;
  esac

  case "$path" in
    *.zip|*.tar|*.tar.gz|*.tgz|*.exe|*.dll|*.so|*.dylib)
      report_failure "new binary/archive artifact is not allowed in source control: $path"
      ;;
    *.DS_Store|*/.DS_Store|*.backup|coverage.out|coverage.html)
      report_failure "temporary/generated file is not allowed: $path"
      ;;
  esac

  if [[ -f "$path" ]]; then
    size="$(wc -c < "$path")"
    if (( size > max_bytes )); then
      report_failure "changed file exceeds 10 MiB source-control limit (${size} bytes): $path"
    fi
  fi
done

if (( failures > 0 )); then
  printf 'Repository hygiene found %d violation(s).\n' "$failures" >&2
  exit 1
fi

printf 'Repository hygiene OK for %d changed path(s).\n' "${#changed_files[@]}"
