"""Regression tests for release-specific, fresh exact-SHA checks."""
from __future__ import annotations

import importlib.util
from pathlib import Path
from unittest import TestCase, main, mock

script = Path(__file__).with_name("require-release-gates.py")
spec = importlib.util.spec_from_file_location("release_gates", script)
assert spec is not None and spec.loader is not None
gates = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gates)

SHA = "a" * 40
REPO = "test/TraceSleuth"
GATE = "release-gate-123-1"


def run(id: int, *, title: str = GATE, event: str = "workflow_dispatch",
        sha: str = SHA, branch: str = "main", status: str = "completed",
        conclusion: str | None = "success") -> dict:
    return {
        "id": id, "display_title": title, "event": event,
        "head_sha": sha, "head_branch": branch,
        "status": status, "conclusion": conclusion,
    }


class TestReleaseGateContract(TestCase):
    def api(self, ci: list, sec: list, *, main_sha: str = SHA):
        def fake(route: str, *, payload=None):
            if route.endswith("/git/ref/heads/main"):
                return {"object": {"sha": main_sha}}
            if "/actions/workflows/ci.yml/runs?" in route:
                result = ci
            elif "/actions/workflows/security.yml/runs?" in route:
                result = sec
            else:
                raise AssertionError(route)
            if "&event=workflow_dispatch" in route:
                result = [x for x in result if x["event"] == "workflow_dispatch"]
            return {"workflow_runs": result}
        return mock.patch.object(gates, "gh_api", side_effect=fake)

    def test_fresh_success_on_exact_commit(self):
        with self.api([run(12)], [run(19)]):
            gates.check_gates(REPO, SHA, GATE)

    def test_historical_push_success_not_substituted(self):
        with self.api([run(12, title="CI", event="push")], [run(19)]):
            with self.assertRaises(gates.GatePending):
                gates.check_gates(REPO, SHA, GATE)

    def test_matching_title_wrong_commit_or_branch_rejected(self):
        for bad in (run(12, sha="b" * 40), run(12, branch="other")):
            with self.subTest(bad=bad), self.api([bad], [run(19)]):
                with self.assertRaises(gates.GatePending):
                    gates.check_gates(REPO, SHA, GATE)

    def test_different_attempt_rejected(self):
        with self.api([run(12, title="release-gate-123-2")], [run(19)]):
            with self.assertRaises(gates.GatePending):
                gates.check_gates(REPO, SHA, GATE)

    def test_failed_requested_security_rejected(self):
        for conclusion in ("failure", "cancelled", "timed_out", "neutral"):
            with self.subTest(conclusion=conclusion), self.api(
                [run(12)], [run(19, conclusion=conclusion)],
            ):
                with self.assertRaises(gates.GateFailure):
                    gates.check_gates(REPO, SHA, GATE)

    def test_later_weekly_security_failure_blocks_release(self):
        security = [run(19), run(20, title="scheduled", event="schedule", conclusion="failure")]
        with self.api([run(12)], security):
            with self.assertRaises(gates.GateFailure):
                gates.check_gates(REPO, SHA, GATE)

    def test_later_security_check_pending_blocks_release(self):
        security = [run(19), run(20, title="scheduled", event="schedule",
                                 status="in_progress", conclusion=None)]
        with self.api([run(12)], security):
            with self.assertRaises(gates.GatePending):
                gates.check_gates(REPO, SHA, GATE)

    def test_main_movement_blocks_release(self):
        with self.api([run(12)], [run(19)], main_sha="b" * 40):
            with self.assertRaises(gates.GateFailure):
                gates.check_gates(REPO, SHA, GATE)

    def test_requested_runs_must_complete(self):
        with self.api([run(12, status="queued", conclusion=None)], [run(19)]):
            with self.assertRaises(gates.GatePending):
                gates.check_gates(REPO, SHA, GATE)

    def test_dispatch_exact_main_and_nonce(self):
        events = []
        def fake(route: str, *, payload=None):
            events.append((route, payload))
            if route.endswith("/git/ref/heads/main"):
                return {"object": {"sha": SHA}}
            return None
        with mock.patch.object(gates, "gh_api", side_effect=fake):
            gates.dispatch(REPO, SHA, GATE)
        self.assertEqual(events[1][1], {
            "ref": "main", "inputs": {"release_gate_id": "123-1"},
        })
        self.assertEqual(events[2][1], events[1][1])
        self.assertIn("security.yml/dispatches", events[2][0])

    def test_missing_or_malformed_api_evidence_rejected(self):
        with mock.patch.object(gates, "gh_api", return_value={"workflow_runs": None}):
            with self.assertRaises(gates.GateFailure):
                gates.workflow_runs(REPO, "ci.yml", SHA)


if __name__ == "__main__":
    main()
