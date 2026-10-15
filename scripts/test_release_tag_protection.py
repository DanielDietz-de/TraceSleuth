"""Negative fixtures prevent a tag-ruleset bypass from enabling publication."""
import importlib.util
from pathlib import Path
import unittest

script = Path(__file__).with_name("check-release-tag-protection.py")
spec = importlib.util.spec_from_file_location("tag_protection", script)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def policy(**changes):
    rule = {
        "target": "tag",
        "enforcement": "active",
        "conditions": {
            "ref_name": {"include": ["refs/tags/v*"], "exclude": []},
        },
        "rules": [{"type": "update"}, {"type": "deletion"}],
        "bypass_actors": [],
    }
    rule.update(changes)
    return rule


class TagProtectionContract(unittest.TestCase):
    def test_matching_ruleset_allows_version_tag(self):
        self.assertTrue(module.protects_tag(policy(), "v0.2.0"))
        self.assertTrue(module.protects_tag(policy(), "v1.0.0"))

    def test_wrong_target_rejected(self):
        self.assertFalse(module.protects_tag(policy(target="branch"), "v0.2.0"))

    def test_disabled_or_evaluate_mode_rejected(self):
        for enforcement in ("disabled", "evaluate", None):
            self.assertFalse(module.protects_tag(policy(enforcement=enforcement), "v0.2.0"))

    def test_missing_update_or_delete_rejected(self):
        for rules in ([{"type": "deletion"}], [{"type": "update"}], []):
            self.assertFalse(module.protects_tag(policy(rules=rules), "v0.2.0"))

    def test_scope_mismatch_rejected(self):
        bad = {"ref_name": {"include": ["refs/tags/stable-*"], "exclude": []}}
        self.assertFalse(module.protects_tag(policy(conditions=bad), "v0.2.0"))

    def test_excluded_target_rejected(self):
        exclude = {"ref_name": {
            "include": ["refs/tags/v*"], "exclude": ["refs/tags/v0.2.0"],
        }}
        self.assertFalse(module.protects_tag(policy(conditions=exclude), "v0.2.0"))

    def test_bypass_actors_rejected(self):
        self.assertFalse(module.protects_tag(
            policy(bypass_actors=[{"actor_type": "RepositoryRole", "actor_id": 4}]),
            "v0.2.0",
        ))

    def test_all_refs_rule_accepted(self):
        ruleset = policy(conditions={"ref_name": {"include": ["~ALL"], "exclude": []}})
        self.assertTrue(module.protects_tag(ruleset, "v0.2.0"))

    def test_empty_rule_is_rejected(self):
        self.assertFalse(module.protects_tag({}, "v0.2.0"))


if __name__ == "__main__":
    unittest.main()
