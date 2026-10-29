import copy
import contextlib
import io
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import run_regression
from validate_fixtures import validate


class RegressionContractTests(unittest.TestCase):
    def run_isolated(self, profile="baseline", actual=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            shutil.copytree(ROOT / "fixtures", root / "fixtures")
            shutil.copytree(ROOT / "test-cases", root / "test-cases")
            if actual:
                folder = root / "reports/actual"
                folder.mkdir(parents=True)
                (folder / f"{actual['case_id']}.json").write_text(json.dumps(actual))
            with mock.patch.object(run_regression, "ROOT", root), mock.patch.object(run_regression, "MANIFEST", root / "test-cases/manifest.json"), contextlib.redirect_stdout(io.StringIO()):
                code = run_regression.main(["--profile", profile])
            report = json.loads((root / f"reports/{profile}-results.json").read_text())
            return code, report

    def test_near_miss_process_names_do_not_match_or_suppress(self):
        shell = json.loads((ROOT / "fixtures/positive/POS-100300-001.json").read_text())
        shell["data"]["win"]["eventdata"]["parentImage"] = r"C:\Windows\System32\evilwmiprvse.exe"
        self.assertIsNone(run_regression.baseline_match(shell)[0])

        canary = json.loads((ROOT / "fixtures/edge-cases/EDGE-100200-001.json").read_text())
        for image in (r"C:\Users\Public\notMsMpEng.exe", r"C:\Tools\SearchIndexerHelper.exe", r"C:\Tools\MsMpEng.exe.bak"):
            with self.subTest(image=image):
                canary["data"]["win"]["eventdata"]["image"] = image
                self.assertEqual(run_regression.safety_match(canary)[0], "100200")
                self.assertEqual(run_regression.triage_decision(canary, "safety", "100200", "reason")[0], "investigate")

    def test_wrong_rule_is_explicit_and_counts_as_missed_expected_rule(self):
        expected = {"alert": True, "rule_id": "100100"}
        self.assertEqual(run_regression.outcome("100101", expected), "WRONG_RULE")
        rows = [{
            "kind": "positive", "offline_outcome": "WRONG_RULE", "actual_outcome": "WRONG_RULE",
            "decision": "investigate", "action_match": True, "expected_action": "investigate",
            "expected_outcome": "TP", "case_id": "X", "expected_alert": True,
            "expected_rule": "100100", "predicted_rule": "100101", "actual_rule": None,
            "reason": "wrong rule",
        }]
        rows.append({**rows[0], "case_id": "Y", "offline_outcome": "TP", "actual_outcome": "TP"})
        report = run_regression.markdown_report("test", rows, 2)
        self.assertEqual(report.count("WRONG_RULE: 1"), 2)
        self.assertEqual(report.count("Precision: 50.0%"), 2)
        self.assertEqual(report.count("Recall: 50.0%"), 2)

    def test_runner_fails_when_matcher_misses_positive_cases(self):
        with mock.patch.object(run_regression, "baseline_match", return_value=(None, "mutant")):
            code, report = self.run_isolated()
        self.assertEqual(code, 1)
        self.assertEqual(sum(row["offline_outcome"] == "FN" for row in report["rows"]), 10)

    def test_runner_fails_wrong_rules_new_false_positives_and_action_changes(self):
        for result in ("100101", "100999"):
            with self.subTest(result=result), mock.patch.object(run_regression, "baseline_match", return_value=(result, "mutant")):
                self.assertEqual(self.run_isolated()[0], 1)
        with mock.patch.object(run_regression, "triage_decision", return_value=("no_alert", "mutant")):
            self.assertEqual(self.run_isolated()[0], 1)

    def test_profile_contracts_allow_measured_false_positives(self):
        for profile in ("baseline", "safety"):
            with self.subTest(profile=profile):
                self.assertEqual(self.run_isolated(profile)[0], 0)

    def test_expected_contract_does_not_change_when_event_data_changes(self):
        fixture = json.loads((ROOT / "fixtures/edge-cases/EDGE-100200-001.json").read_text())
        expected = run_regression.expected_for_profile(fixture, "safety")
        fixture["data"] = {}
        self.assertEqual(run_regression.expected_for_profile(fixture, "safety"), expected)

    def test_wrong_rule_on_known_false_positive_cannot_pass_contract(self):
        original = run_regression.baseline_match
        def mutant(fixture):
            if fixture["case_id"] == "NEG-100102-002":
                return "100200", "mutant"
            return original(fixture)
        with mock.patch.object(run_regression, "baseline_match", side_effect=mutant):
            self.assertEqual(self.run_isolated()[0], 1)

    def test_actual_results_are_loaded_by_default_and_wrong_rules_fail(self):
        code, report = self.run_isolated(actual={"case_id": "POS-100100-001", "alert": True, "rule_id": "100101"})
        self.assertEqual(code, 1)
        self.assertEqual(report["rows"][0]["actual_outcome"], "WRONG_RULE")

    def test_incomplete_context_and_known_writer_alerts_are_retained(self):
        for case_id in ("EDGE-100100-001", "EDGE-100300-001", "EDGE-100300-002", "EDGE-100200-001"):
            fixture = json.loads((ROOT / f"fixtures/edge-cases/{case_id}.json").read_text())
            # A familiar name at an untrusted path is still reviewable evidence,
            # never an allowlist exemption.
            if case_id == "EDGE-100200-001":
                fixture["data"]["win"]["eventdata"]["image"] = r"C:\Users\Public\MsMpEng.exe"
            for profile, matcher in (("baseline", run_regression.baseline_match), ("safety", run_regression.safety_match)):
                with self.subTest(case=case_id, profile=profile):
                    rule, reason = matcher(fixture)
                    self.assertEqual(rule, fixture["expected"]["rule_id"])
                    self.assertEqual(run_regression.triage_decision(fixture, profile, rule, reason)[0], "manual_review")

    def test_manifest_fixture_drift_is_rejected(self):
        manifest = json.loads((ROOT / "test-cases/manifest.json").read_text())
        manifest["cases"][0]["kind"] = "negative"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.json"
            path.write_text(json.dumps(manifest), encoding="utf-8")
            errors, _ = validate(ROOT, path)
        self.assertTrue(any("kind does not match manifest" in error for error in errors))

    def test_orphan_duplicate_and_unknown_contract_fields_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            shutil.copytree(ROOT / "fixtures", root / "fixtures")
            shutil.copytree(ROOT / "test-cases", root / "test-cases")
            (root / "fixtures/orphan.json").write_text("{}")
            errors, _ = validate(root)
            self.assertTrue(any("orphan fixture" in error for error in errors))
            path = root / "test-cases/manifest.json"
            manifest = json.loads(path.read_text())
            manifest["cases"].append(copy.deepcopy(manifest["cases"][0]))
            manifest["cases"][0]["unexpected"] = True
            path.write_text(json.dumps(manifest))
            errors, _ = validate(root)
            self.assertTrue(any("duplicate case_id" in error for error in errors))
            self.assertTrue(any("duplicate fixture path" in error for error in errors))
            self.assertTrue(any("unknown fields" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
