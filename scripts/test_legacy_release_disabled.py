"""Fail-closed contract for the old untrusted tag-release workflow."""
import importlib.util
from pathlib import Path
from unittest import TestCase, main, mock
import json

script = Path(__file__).with_name("check-legacy-release-disabled.py")
spec = importlib.util.spec_from_file_location("legacy_release", script)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class LegacyReleaseDisabledContract(TestCase):
    def test_authoritative_disabled_response_allowed(self):
        self.assertTrue(module.validate_legacy_workflow({
            "path": ".github/workflows/release.yml",
            "state": "disabled_manually",
        }))

    def test_active_and_other_states_rejected(self):
        for state in ("active", "disabled_inactivity", "disabled_fork", None, ""):
            self.assertFalse(module.validate_legacy_workflow({
                "path": ".github/workflows/release.yml", "state": state,
            }))

    def test_wrong_or_redacted_workflow_rejected(self):
        for response in (None, {}, [], {"state": "disabled_manually"},
                         {"state": "disabled_manually",
                          "path": ".github/workflows/validated-release.yml"}):
            self.assertFalse(module.validate_legacy_workflow(response))

    def test_missing_repo_denied_before_rest_call(self):
        with mock.patch.dict("os.environ", {"GITHUB_REPOSITORY": ""}):
            with mock.patch.object(module.subprocess, "run") as sub:
                self.assertEqual(module.main(), 1)
                sub.assert_not_called()

    def test_untrusted_active_live_reply_denied(self):
        from subprocess import CompletedProcess
        with mock.patch.dict("os.environ", {"GITHUB_REPOSITORY": "org/TraceSleuth"}):
            with mock.patch.object(
                module.subprocess, "run",
                return_value=CompletedProcess(
                    [], 0, stdout=json.dumps({
                        "path": ".github/workflows/release.yml", "state": "active",
                    }),
                ),
            ):
                self.assertEqual(module.main(), 1)


if __name__ == "__main__":
    main()
