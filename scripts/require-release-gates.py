#!/usr/bin/env python3
"""Require fresh, successful, release-specific CI and Security runs.

The release job dispatches both workflows on the trusted default branch and
waits for their actual completion on the *exact* release commit. A matching
historical push/weekly run is never a substitute for this attempt's checks.
A final verify-only invocation catches subsequent failures or a moving main.

This file deliberately uses GitHub's authenticated REST API through gh and
fails closed on missing, malformed, pending, failed, or cancelled evidence.
"""
from __future__ import annotations

import json
import os
from datetime import datetime
import subprocess
import sys
import time
from typing import Any

WORKFLOWS = ("ci.yml", "security.yml")
POLL_SECONDS = 10
MAX_POLLS = 720  # Up to 120 minutes; workflow job timeout is 180 minutes.


class GateFailure(Exception):
    """A release condition that must prevent publication."""


class GatePending(Exception):
    """A requested run has not finished or is not visible yet."""


def gh_api(route: str, *, payload: dict[str, Any] | None = None) -> Any:
    command = ["gh", "api"]
    if payload is not None:
        command += ["--method", "POST", "--input", "-"]
    command.append(route)
    result = subprocess.run(
        command,
        input=json.dumps(payload) if payload is not None else None,
        capture_output=True,
        text=True,
        check=True,
        timeout=60,
    )
    if not result.stdout.strip():
        return None
    return json.loads(result.stdout)


def release_identity() -> tuple[str, str, str]:
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    sha = os.environ.get("GITHUB_SHA", "")
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    attempt = os.environ.get("GITHUB_RUN_ATTEMPT", "1")
    if repo.count("/") != 1 or not repo or len(sha) != 40:
        raise GateFailure("Missing or invalid repository/commit identity")
    if not (run_id.isdecimal() and attempt.isdecimal()):
        raise GateFailure("Missing release run ID or attempt")
    return repo, sha, "release-gate-" + run_id + "-" + attempt


def assert_main_unchanged(repo: str, sha: str) -> None:
    ref = gh_api(f"repos/{repo}/git/ref/heads/main")
    if not isinstance(ref, dict) or ref.get("object", {}).get("sha") != sha:
        raise GateFailure("Default branch moved or cannot be verified at release commit")


def workflow_runs(repo: str, flow: str, sha: str, *, event: str | None = None) -> list[dict[str, Any]]:
    route = f"repos/{repo}/actions/workflows/{flow}/runs?head_sha={sha}&per_page=100"
    if event is not None:
        route += "&event=" + event
    obj = gh_api(route)
    if not isinstance(obj, dict) or not isinstance(obj.get("workflow_runs"), list):
        raise GateFailure(f"Unverifiable {flow} workflow-run response")
    if not all(isinstance(run, dict) for run in obj["workflow_runs"]):
        raise GateFailure(f"Malformed {flow} workflow-run entry")
    # The API sorts runs by their original ID, not a rerun's attempt time.
    # Never certify a subset that could hide a much older rerun.
    total = obj.get("total_count")
    if not isinstance(total, int) or total > len(obj["workflow_runs"]):
        raise GateFailure(f"Truncated or unverifiable {flow} run history for exact SHA")
    return obj["workflow_runs"]


def requested_run(runs: list[dict[str, Any]], sha: str, gate_id: str) -> dict[str, Any] | None:
    eligible = [
        run for run in runs
        if run.get("display_title") == gate_id
        and run.get("head_sha") == sha
        and run.get("head_branch") == "main"
        and run.get("event") == "workflow_dispatch"
        and isinstance(run.get("id"), int)
    ]
    return max(eligible, key=lambda r: r["id"]) if eligible else None


def require_success(run: dict[str, Any], description: str) -> None:
    if run.get("status") != "completed":
        raise GatePending(f"{description} is not complete")
    if run.get("conclusion") != "success":
        raise GateFailure(f"{description} concluded {run.get('conclusion')!r}")


def timestamp(value: Any) -> datetime:
    if not isinstance(value, str):
        raise GateFailure("Missing GitHub run timestamp")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise GateFailure("Malformed GitHub run timestamp") from exc
    if result.tzinfo is None:
        raise GateFailure("Unzoned GitHub run timestamp")
    return result


def check_gates(repo: str, sha: str, gate_id: str) -> None:
    assert_main_unchanged(repo, sha)
    pending: list[str] = []
    for flow in WORKFLOWS:
        selected = requested_run(
            workflow_runs(repo, flow, sha, event="workflow_dispatch"), sha, gate_id,
        )
        if selected is None:
            pending.append(f"{flow} release-dispatch run not found")
            continue
        try:
            require_success(selected, flow + " request " + gate_id)
        except GatePending as exc:
            pending.append(str(exc))

        # Check every run whose ID or latest attempt/update is newer than
        # this release gate. An older run's ID is stable across reruns, so
        # comparing IDs alone silently ignores a later failed re-attempt.
        started = timestamp(selected.get("created_at"))
        all_runs = workflow_runs(repo, flow, sha)
        eligible = [
            run for run in all_runs
            if run.get("head_sha") == sha
            and run.get("head_branch") == "main"
            and run.get("event") in ("push", "schedule", "workflow_dispatch")
        ]
        if not eligible or not any(
            run.get("id") == selected["id"] for run in eligible
        ):
            raise GateFailure(f"Cannot independently verify {flow} release run")
        for run in eligible:
            if not isinstance(run.get("id"), int):
                raise GateFailure(f"Invalid {flow} run identity")
            latest_update = timestamp(run.get("updated_at"))
            if run["id"] < selected["id"] and latest_update < started:
                continue
            try:
                require_success(run, f"{flow} run {run['id']} (latest attempt)")
            except GatePending as exc:
                pending.append(str(exc))
    if pending:
        raise GatePending("; ".join(pending))


def dispatch(repo: str, sha: str, gate_id: str) -> None:
    assert_main_unchanged(repo, sha)
    for flow in WORKFLOWS:
        gh_api(
            f"repos/{repo}/actions/workflows/{flow}/dispatches",
            payload={"ref": "main", "inputs": {"release_gate_id": gate_id.removeprefix("release-gate-")}},
        )
        print(f"Dispatched {flow} release gate {gate_id}", flush=True)


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[1] not in ("dispatch", "verify"):
        print("Usage: require-release-gates.py dispatch|verify", file=sys.stderr)
        return 2
    try:
        repo, sha, gate_id = release_identity()
        if argv[1] == "dispatch":
            dispatch(repo, sha, gate_id)
            for poll in range(MAX_POLLS):
                try:
                    check_gates(repo, sha, gate_id)
                    break
                except GatePending as exc:
                    if poll % 12 == 0:
                        print(f"Waiting on fresh gates: {exc}", flush=True)
                    time.sleep(POLL_SECONDS)
            else:
                raise GateFailure("Timed out awaiting fresh exact-SHA CI and Security gates")
        else:
            check_gates(repo, sha, gate_id)
        print(f"Fresh exact-SHA CI/Security gates succeeded: {sha} ({gate_id})")
        return 0
    except (GateFailure, GatePending, OSError, ValueError, subprocess.CalledProcessError,
            subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
        print(f"Refusing release: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
