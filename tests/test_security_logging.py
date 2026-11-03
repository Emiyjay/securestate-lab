import sys
import unittest
from pathlib import Path
from unittest.mock import patch
import subprocess

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from securestate.assessments.security_logging import assess_security_logging
from securestate.models import CheckStatus


class TestSecurityLogging(unittest.TestCase):
    @patch("securestate.assessments.security_logging.shutil.which", return_value="/usr/bin/systemctl")
    @patch("securestate.assessments.security_logging._run")
    def test_linux_journal_available_passes(self, run, _which):
        run.side_effect = [
            subprocess.CompletedProcess([], 0, "active\n", ""),
            subprocess.CompletedProcess([], 3, "inactive\n", ""),
            subprocess.CompletedProcess([], 0, "-- Logs begin --\n", ""),
            subprocess.CompletedProcess([], 0, "active\n", ""),
            subprocess.CompletedProcess([], 3, "inactive\n", ""),
            subprocess.CompletedProcess([], 0, "enabled 1\n", ""),
        ]
        result = assess_security_logging("Linux")[0]
        self.assertEqual(result.status, CheckStatus.PASS)
        self.assertIn("journal is readable", result.summary)

    @patch("securestate.assessments.security_logging.shutil.which", return_value="/usr/bin/systemctl")
    @patch("securestate.assessments.security_logging._run")
    def test_linux_both_services_inactive_fails(self, run, _which):
        run.side_effect = [
            subprocess.CompletedProcess([], 3, "inactive\n", ""),
            subprocess.CompletedProcess([], 3, "failed\n", ""),
            subprocess.CompletedProcess([], 0, "", ""),
            subprocess.CompletedProcess([], 3, "inactive\n", ""),
            subprocess.CompletedProcess([], 0, "enabled 1\n", ""),
        ]
        result = assess_security_logging("Linux")[0]
        self.assertEqual(result.status, CheckStatus.FAIL)

    @patch("securestate.assessments.security_logging.shutil.which", return_value=None)
    def test_linux_without_systemctl_is_unknown(self, _which):
        result = assess_security_logging("Linux")[0]
        self.assertEqual(result.status, CheckStatus.UNKNOWN)


    @patch("securestate.assessments.security_logging.shutil.which", return_value="auditpol.exe")
    @patch("securestate.assessments.security_logging._run")
    def test_windows_audit_policy_is_reported_as_unknown_without_baseline(self, run, _which):
        run.side_effect = [
            subprocess.CompletedProcess([], 0, '{"service":"Running","latest_event_id":1,"latest_event_time":"2026-11-03T10:00:00"}', ""),
            subprocess.CompletedProcess([], 0,
                '"Machine Name","Policy Target","Subcategory","Subcategory GUID","Inclusion Setting","Exclusion Setting"\n'
                '"HOST","System","Logon","guid","Success and Failure",""\n'
                '"HOST","System","Account Management","guid2","No Auditing",""', ""),
        ]
        results = assess_security_logging("Windows")
        audit = next(item for item in results if item.check_id == "LOG-AUDIT-001")
        self.assertEqual(audit.status, CheckStatus.UNKNOWN)
        self.assertIn("1 have auditing enabled", audit.evidence)
        self.assertIn("1 report No Auditing", audit.evidence)

    @patch("securestate.assessments.security_logging.shutil.which", return_value="auditpol.exe")
    @patch("securestate.assessments.security_logging._run")
    def test_audit_policy_query_failure_is_unknown(self, run, _which):
        run.side_effect = [
            subprocess.CompletedProcess([], 0, '{"service":"Running","latest_event_id":1,"latest_event_time":"2026-11-03T10:00:00"}', ""),
            subprocess.CompletedProcess([], 1, "", "access denied"),
        ]
        results = assess_security_logging("Windows")
        audit = next(item for item in results if item.check_id == "LOG-AUDIT-001")
        self.assertEqual(audit.status, CheckStatus.UNKNOWN)
        self.assertIn("access denied", audit.evidence)


    @patch("securestate.assessments.security_logging.shutil.which", return_value="auditpol.exe")
    @patch("securestate.assessments.security_logging._run")
    def test_windows_missing_privilege_has_actionable_unknown_message(self, run, _which):
        run.side_effect = [
            subprocess.CompletedProcess([], 0, '{"service":"Running","latest_event_id":1,"latest_event_time":"2026-11-03T10:00:00"}', ""),
            subprocess.CompletedProcess([], 1, "", "Error 0x00000522 occurred"),
        ]
        results = assess_security_logging("Windows")
        audit = next(item for item in results if item.check_id == "LOG-AUDIT-001")
        self.assertEqual(audit.status, CheckStatus.UNKNOWN)
        self.assertIn("Run as administrator", audit.evidence)
        self.assertIn("not a finding", audit.evidence)

    def test_unsupported_platform_is_not_applicable(self):
        result = assess_security_logging("FreeBSD")[0]
        self.assertEqual(result.status, CheckStatus.NOT_APPLICABLE)


if __name__ == "__main__":
    unittest.main()
