"""The review policy must not silently suppress replication alerts."""

import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from run_regression import baseline_match, safety_match, triage_decision, outcome, expected_for_profile


class DCReviewTests(unittest.TestCase):
    def setUp(self):
        self.fixture = json.loads((ROOT / "fixtures/negative/NEG-100102-002.json").read_text())

    def test_review_retains_alert_and_false_positive_count(self):
        for profile, matcher in (("baseline", baseline_match), ("safety", safety_match)):
            rule, reason = matcher(self.fixture)
            self.assertEqual(rule, "100102")
            self.assertEqual(outcome(rule, expected_for_profile(self.fixture, profile)), "FP")
            decision, _ = triage_decision(self.fixture, profile, rule, reason)
            self.assertEqual(decision, "manual_review" if profile == "safety" else "investigate")

    def test_incomplete_or_other_identity_still_needs_investigation(self):
        for field, value in (("subjectUserName", "WK01$"), ("subjectDomainName", "OTHER"),
                             ("subjectUserSid", None), ("computer", "WK01")):
            with self.subTest(field=field):
                fixture = copy.deepcopy(self.fixture)
                fixture["data"]["win"]["eventdata"][field] = value
                rule, reason = safety_match(fixture)
                self.assertEqual(rule, "100102")
                self.assertEqual(triage_decision(fixture, "safety", rule, reason)[0], "investigate")

    def test_real_system_host_takes_precedence_over_legacy_fixture_host(self):
        self.fixture["data"]["win"]["system"]["computer"] = "WK01.lab.local"
        rule, reason = safety_match(self.fixture)
        self.assertEqual(triage_decision(self.fixture, "safety", rule, reason)[0], "investigate")


if __name__ == "__main__":
    unittest.main()
