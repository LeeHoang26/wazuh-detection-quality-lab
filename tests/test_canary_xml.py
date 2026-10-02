"""Check the regex stored in the XML; this is not a live Wazuh engine test."""

import re
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


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

    def test_candidate_keeps_windows_filecreate_conditions(self):
        self.assertEqual(self.rule.findtext("if_group"), "windows")
        self.assertEqual(self.rule.findtext("./field[@name='win.system.eventID']"), "^11$")
        self.assertEqual(
            self.rule.find("./field[@name='win.eventdata.targetFilename']").get("type"), "pcre2"
        )


if __name__ == "__main__":
    unittest.main()
