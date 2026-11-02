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
        ]
        result = assess_security_logging("Linux")[0]
        self.assertEqual(result.status, CheckStatus.FAIL)

    @patch("securestate.assessments.security_logging.shutil.which", return_value=None)
    def test_linux_without_systemctl_is_unknown(self, _which):
        result = assess_security_logging("Linux")[0]
        self.assertEqual(result.status, CheckStatus.UNKNOWN)

    def test_unsupported_platform_is_not_applicable(self):
        result = assess_security_logging("FreeBSD")[0]
        self.assertEqual(result.status, CheckStatus.NOT_APPLICABLE)


if __name__ == "__main__":
    unittest.main()
