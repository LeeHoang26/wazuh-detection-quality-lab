"""Check the regex stored in the XML; this is not a live Wazuh engine test."""

import re
import sys
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from run_regression import baseline_match, safety_match


class CanaryXMLTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = ET.parse(ROOT / "detections/wazuh/canary-safe-candidate.xml").getroot()
        cls.rule = root.find("./rule[@id='100200']")
        cls.pattern = re.compile(cls.rule.find("./field[@name='win.eventdata.targetFilename']").text)

    def test_real_txt_names_including_exclamation_mark_match(self):
        for path in (
            r"C:\Users\Public\!_financial_payroll_2026.txt",
            r"C:\Users\Public\Canary-Test-3\!_financial_payroll_2026.txt",
            r"C:\Users\Public\Canary-Test-5\!_financial_payroll_2026.txt",
            r"C:\Users\Public\!_confidential_contract.txt",
            r"C:\USERS\PUBLIC\!_FINANCIAL_PAYROLL_2026.TXT",
        ):
            with self.subTest(path=path):
                self.assertIsNotNone(self.pattern.search(path))
                fixture = {"data": {"win": {"system": {"eventID": "11"}, "eventdata": {"targetFilename": path}}}}
                self.assertEqual(safety_match(fixture)[0], "100200")

    def test_shortcuts_and_unprotected_names_do_not_match(self):
        for path in (
            r"C:\Users\labuser\AppData\Roaming\Microsoft\Windows\Recent\!_financial_payroll_2026.txt.lnk",
            r"C:\Users\Public\!_financial_payroll_2026.txt.lnk",
            r"C:\Users\Public\!_financial_payroll_2026.txt.exe",
            r"C:\Users\Public\report_financial_payroll_2026.txt",
            r"C:\Users\Public\_financial_payroll_2026.txt",
        ):
            with self.subTest(path=path):
                self.assertIsNone(self.pattern.search(path))
                fixture = {"data": {"win": {"system": {"eventID": "11"}, "eventdata": {"targetFilename": path}}}}
                self.assertIsNone(safety_match(fixture)[0])

    def test_candidate_keeps_windows_filecreate_conditions(self):
        self.assertEqual(self.rule.findtext("if_group"), "windows")
        self.assertEqual(self.rule.findtext("./field[@name='win.system.eventID']"), "^11$")
        self.assertEqual(
            self.rule.find("./field[@name='win.eventdata.targetFilename']").get("type"), "pcre2"
        )

    def test_baseline_xml_and_python_enforce_executable_boundaries(self):
        root = ET.fromstring("<root>" + (ROOT / "detections/wazuh/baseline-rules.xml").read_text() + "</root>")
        rule = root.find(".//rule[@id='100300']")
        parent_regex = re.compile(rule.find("./field[@name='win.eventdata.parentImage']").text)
        child_regex = re.compile(rule.find("./field[@name='win.eventdata.image']").text)
        for parent, child, expected in (
            (r"C:\Windows\WmiPrvSE.exe", r"C:\Windows\cmd.exe", True),
            ("WSMPROVHOST.EXE", "PowerShell_ISE.EXE", True),
            (r"C:\Windows\evilwmiprvse.exe", "cmd.exe", False),
            ("wmiprvse.exe", r"C:\Tools\notcmd.exe", False),
            ("wmiprvse.exe", "powershell.exe.bak", False),
            ("wmiprvse.exe", "cmd.exe\\", False),
            ("wmiprvse.exe", "C:cmd.exe", False),
        ):
            with self.subTest(parent=parent, child=child):
                self.assertEqual(bool(parent_regex.search(parent) and child_regex.search(child)), expected)
                fixture = {"data": {"win": {"system": {"eventID": "1"}, "eventdata": {"parentImage": parent, "image": child}}}}
                self.assertEqual(baseline_match(fixture)[0] is not None, expected)


if __name__ == "__main__":
    unittest.main()
