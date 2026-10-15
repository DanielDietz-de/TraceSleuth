#!/usr/bin/env python3
"""Refuse publication unless active tag rules make release refs append-only.

Tag immutability must exist BEFORE release publication: GitHub's immutable
release setting locks tags only AFTER publication. This helper checks
repository/organization tag rulesets and refuses to publish if it cannot
establish update and deletion protection for the exact release tag.

GitHub can omit bypass_actors for insufficiently privileged tokens.
An omitted field cannot prove that bypass actors are absent, so this check
fails closed. Release validation therefore needs a credential capable of
reading authoritative ruleset details; do not silently trust redacted data.
"""
from __future__ import annotations

import fnmatch
import json
import os
import subprocess
import sys
from typing import Any


def certifiable_tag_pattern(pattern: Any) -> bool:
    """Only accept tag patterns whose GitHub FNM_PATHNAME match is provable.

    GitHub's '*' does not cross '/', unlike Python fnmatch against the full
    ref. Reject recursive globs, character classes, and unknown patterns
    rather than certifying potentially unprotected version tags.
    """
    if pattern == "~ALL":
        return True
    prefix = "refs/tags/"
    if not isinstance(pattern, str) or not pattern.startswith(prefix):
        return False
    suffix = pattern[len(prefix):]
    return bool(suffix) and "/" not in suffix and "**" not in suffix and not any(
        char in suffix for char in "[]\\"
    )


def matches_pattern(ref: str, pattern: str) -> bool:
    if not certifiable_tag_pattern(pattern):
        return False
    if pattern == "~ALL":
        return True
    prefix = "refs/tags/"
    return (
        ref.startswith(prefix)
        and "/" not in ref[len(prefix):]
        and fnmatch.fnmatchcase(ref[len(prefix):], pattern[len(prefix):])
    )


def protects_tag(ruleset: dict[str, Any], tag: str) -> bool:
    """Enforce active tag update+deletion rules without any exposed bypass."""
    if ruleset.get("target") != "tag":
        return False
    if ruleset.get("enforcement") not in ("active", "enabled"):
        return False
    conditions = ruleset.get("conditions") or {}
    ref_name = conditions.get("ref_name") or {}
    includes = ref_name.get("include") or []
    excludes = ref_name.get("exclude") or []
    if not isinstance(includes, list) or not isinstance(excludes, list):
        return False
    if not all(certifiable_tag_pattern(p) for p in includes + excludes):
        return False
    ref = "refs/tags/" + tag
    if not any(matches_pattern(ref, pattern) for pattern in includes):
        return False
    if any(matches_pattern(ref, pattern) for pattern in excludes):
        return False
    rules = ruleset.get("rules") or []
    types = {r.get("type") for r in rules if isinstance(r, dict)}
    if not {"update", "deletion"}.issubset(types):
        return False
    # Missing/hidden bypass metadata does NOT mean no bypass exists.
    # Never allow release publication using a redacted policy response.
    if "bypass_actors" not in ruleset or ruleset["bypass_actors"] != []:
        return False
    return True


def gh_json(route: str) -> Any:
    result = subprocess.run(
        ["gh", "api", route],
        check=True,
        capture_output=True,
        text=True,
        timeout=45,
    )
    return json.loads(result.stdout)


def fetch_rulesets(repo: str) -> list[dict[str, Any]]:
    # The repo release policy uses a deliberately small number of tag
    # rulesets. More than 100 creates ambiguity: fail closed, not truncate.
    items = gh_json(
        f"repos/{repo}/rulesets?targets=tag&includes_parents=true&per_page=100"
    )
    if not isinstance(items, list) or len(items) >= 100:
        raise ValueError("tag ruleset listing absent or potentially truncated")
    result = []
    for item in items:
        if not isinstance(item, dict) or not isinstance(item.get("id"), int):
            raise ValueError("unexpected tag ruleset listing")
        details = gh_json(f"repos/{repo}/rulesets/{item['id']}")
        if not isinstance(details, dict):
            raise ValueError("unexpected tag ruleset detail")
        result.append(details)
    return result


def main(argv: list[str]) -> int:
    if len(argv) != 2 or not argv[1].startswith("v"):
        print("Usage: check-release-tag-protection.py vX.Y.Z", file=sys.stderr)
        return 2
    tag = argv[1]
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    if "/" not in repo:
        print("Cannot verify protected release tags: invalid GITHUB_REPOSITORY", file=sys.stderr)
        return 1
    try:
        rulesets = fetch_rulesets(repo)
    except (ValueError, OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
        print(f"Cannot verify protected release tags: {exc}", file=sys.stderr)
        return 1
    if not any(protects_tag(rule, tag) for rule in rulesets):
        print(
            f"Refusing {tag}: no active tag ruleset with update+deletion "
            "protection and an explicitly empty bypass_actors list, matching "
            "the exact release ref. Check ruleset read permissions and "
            "configure Repository Rules > Rulesets for refs/tags/v*.",
            file=sys.stderr,
        )
        return 1
    print(f"Verified an active update+deletion tag ruleset for {tag}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
