#!/usr/bin/env python3
"""Fail closed unless the historical tag-triggered Release workflow is disabled.

The old .github/workflows/release.yml was present in earlier commits and
accepted tag push events without fresh security gates. Editing its current
content does not neutralize those immutable historical workflow revisions.
The new, independently named validated-release.yml must therefore refuse all
publication until the legacy workflow has been explicitly disabled in GitHub
Actions. GitHub REST 'Get a workflow' exposes its authoritative state.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys


def validate_legacy_workflow(response: object) -> bool:
    return (
        isinstance(response, dict)
        and response.get("path") == ".github/workflows/release.yml"
        and response.get("state") == "disabled_manually"
    )


def main() -> int:
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    if repo.count("/") != 1 or not all(repo.split("/")):
        print("Cannot inspect historical release workflow: invalid repository", file=sys.stderr)
        return 1
    try:
        result = subprocess.run(
            ["gh", "api", f"repos/{repo}/actions/workflows/release.yml"],
            capture_output=True, text=True, check=True, timeout=45,
        )
        response = json.loads(result.stdout)
    except (OSError, ValueError, subprocess.CalledProcessError,
            subprocess.TimeoutExpired) as exc:
        print(f"Cannot establish historical release workflow state: {exc}", file=sys.stderr)
        return 1
    if not validate_legacy_workflow(response):
        print(
            "Release prohibited: old .github/workflows/release.yml is not "
            "authoritatively disabled_manually. Disable it via GitHub Actions "
            "before publishing from validated-release.yml.",
            file=sys.stderr,
        )
        return 1
    print("Verified historical tag-triggered release workflow is disabled")
    return 0


if __name__ == "__main__":
    sys.exit(main())
