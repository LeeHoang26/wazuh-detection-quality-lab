"""Scope changes must not hide writes to the real canary."""

import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from run_regression import baseline_match, safety_match, expected_for_profile, outcome


class CanaryShortcutTests(unittest.TestCase):
    def setUp(self):
        self.fixture = json.loads((ROOT / "fixtures/negative/NEG-100200-002.json").read_text())

    def test_same_ground_truth_before_and_after(self):
        baseline_expected = expected_for_profile(self.fixture, "baseline")
        safety_expected = expected_for_profile(self.fixture, "safety")
        self.assertEqual(baseline_expected, safety_expected)
        self.assertEqual(outcome(baseline_match(self.fixture)[0], baseline_expected), "FP")
        self.assertEqual(outcome(safety_match(self.fixture)[0], safety_expected), "TN")

    def test_real_canary_and_other_locations_remain_detected(self):
        for path in (
            r"C:\Users\Public\!_financial_payroll_2026.txt",
            r"C:\Users\labuser\Desktop\!_financial_payroll_2026.txt",
            r"C:\Users\labuser\AppData\Roaming\Microsoft\Windows\Recent\!_financial_payroll_2026.txt",
            r"C:\Tools\!_financial_payroll_2026.txt.lnk",
            r"C:\Users\labuser\AppData\Roaming\Microsoft\Windows\Recent\!_financial_payroll_2026.txt.lnk.exe",
        ):
            with self.subTest(path=path):
                fixture = copy.deepcopy(self.fixture)
                fixture["data"]["win"]["eventdata"]["targetFilename"] = path
                self.assertEqual(safety_match(fixture)[0], "100200")

    def test_case_insensitive_path_scope_does_not_depend_on_explorer_name(self):
        data = self.fixture["data"]["win"]["eventdata"]
        data["targetFilename"] = data["targetFilename"].upper()
        data["image"] = r"C:\Tools\unknown.exe"
        self.assertIsNone(safety_match(self.fixture)[0])


if __name__ == "__main__":
    unittest.main()
