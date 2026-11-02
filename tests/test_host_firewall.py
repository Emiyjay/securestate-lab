import unittest
from unittest.mock import patch, Mock

from securestate.assessments import host_firewall
from securestate.models import CheckStatus


class TestLinuxFirewallAssessment(unittest.TestCase):
    @patch("securestate.assessments.host_firewall.platform.system", return_value="Linux")
    @patch("securestate.assessments.host_firewall.shutil.which")
    @patch("securestate.assessments.host_firewall._run")
    def test_active_ufw_passes(self, run, which, system):
        which.side_effect = lambda name: "/usr/sbin/ufw" if name == "ufw" else None
        run.return_value = Mock(returncode=0, stdout="Status: active\n", stderr="")
        result = host_firewall.assess_linux_firewall()
        self.assertEqual(result[0].status, CheckStatus.PASS)
        self.assertIn("Status: active", result[0].evidence)

    @patch("securestate.assessments.host_firewall.platform.system", return_value="Linux")
    @patch("securestate.assessments.host_firewall.shutil.which")
    @patch("securestate.assessments.host_firewall._run")
    def test_inactive_ufw_fails(self, run, which, system):
        which.side_effect = lambda name: "/usr/sbin/ufw" if name == "ufw" else None
        run.return_value = Mock(returncode=0, stdout="Status: inactive\n", stderr="")
        result = host_firewall.assess_linux_firewall()
        self.assertEqual(result[0].status, CheckStatus.FAIL)

    @patch("securestate.assessments.host_firewall.platform.system", return_value="Linux")
    @patch("securestate.assessments.host_firewall.shutil.which", return_value=None)
    def test_missing_firewall_tools_is_unknown(self, which, system):
        result = host_firewall.assess_linux_firewall()
        self.assertEqual(result[0].status, CheckStatus.UNKNOWN)

    @patch("securestate.assessments.host_firewall.platform.system", return_value="Windows")
    def test_linux_check_is_not_applicable_on_windows(self, system):
        result = host_firewall.assess_linux_firewall()
        self.assertEqual(result[0].status, CheckStatus.NOT_APPLICABLE)


if __name__ == "__main__":
    unittest.main()
