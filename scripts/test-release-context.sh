#!/usr/bin/env bash
set -euo pipefail

# Exercise the authorization code during every PR CI run. Publishing is not
# triggered in CI; these cases prevent silent workflow_dispatch/tag bypasses.
version="$(tr -d '\r\n' < VERSION)"
expected="v${version}"
work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT

assert_context() {
  local test_name="$1" should_pass="$2" event="$3" ref="$4" input_version="$5" subject="$6"
  local output_file="$work_dir/${test_name}.outputs"
  local rc
  if GITHUB_EVENT_NAME="$event" GITHUB_REF="$ref" \
      RELEASE_INPUT_VERSION="$input_version" RELEASE_MESSAGE="$subject" \
      GITHUB_OUTPUT="$output_file" bash scripts/release-context.sh > "$work_dir/${test_name}.log" 2>&1; then
    rc=0
  else
    rc=$?
  fi

  if [[ "$should_pass" == yes ]]; then
    if ((rc != 0)); then
      printf 'Release authorization test %s unexpectedly failed (exit %d):\n' "$test_name" "$rc" >&2
      cat "$work_dir/${test_name}.log" >&2
      exit 1
    fi
    grep -Fxq "tag=$expected" "$output_file" || { echo "Missing exact version tag in $test_name" >&2; exit 1; }
    grep -Fxq "version=$version" "$output_file" || { echo "Missing exact release version in $test_name" >&2; exit 1; }
  else
    if ((rc == 0)); then
      printf 'Release authorization test %s unexpectedly ALLOWED publication\n' "$test_name" >&2
      exit 1
    fi
    if [[ -s "$output_file" ]]; then
      printf 'Release authorization test %s wrote outputs when denying publication\n' "$test_name" >&2
      exit 1
    fi
  fi
  printf 'release authorization: %-28s %s\n' "$test_name" "$should_pass"
}

assert_context tag_push yes push "refs/tags/$expected" '' ''
assert_context dispatch_main yes workflow_dispatch refs/heads/main "$version" ''
assert_context release_main yes push refs/heads/main '' "release: $expected"
assert_context release_main_detail yes push refs/heads/main '' "release: $expected extra release detail"
assert_context dispatch_tag_denied no workflow_dispatch "refs/tags/$expected" "$version" ''
assert_context dispatch_other_branch_denied no workflow_dispatch refs/heads/develop "$version" ''
assert_context dispatch_version_mismatch no workflow_dispatch refs/heads/main 999.0.0 ''
assert_context tag_version_mismatch no push refs/tags/v999.0.0 '' ''
assert_context ordinary_main_push_denied no push refs/heads/main '' 'docs: update README'
assert_context release_wrong_version no push refs/heads/main '' 'release: v999.0.0'
assert_context release_other_branch_denied no push refs/heads/develop '' "release: $expected"
assert_context other_event_tag_denied no schedule "refs/tags/$expected" "$version" ''

echo 'Release authorization contract: all 12 event/ref/version cases passed.'
