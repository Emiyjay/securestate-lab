import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from securestate.assessments.security_configuration import assess_security_configuration
from securestate.models import CheckStatus


class TestSecurityConfiguration(unittest.TestCase):
    def test_duplicate_linux_uid_zero_fails(self):
        inventory = {
            "system": {"operating_system": "Linux"},
            "users": [{"name": "root", "uid": 0}, {"name": "backup", "uid": 0}],
            "listening_ports": [],
            "services": [],
            "updates": [],
            "collection_errors": [],
        }
        results = assess_security_configuration(inventory)
        root = next(r for r in results if r.check_id == "ID-LINUX-001")
        self.assertEqual(root.status, CheckStatus.FAIL)
        self.assertIn("backup", root.evidence)

    def test_single_linux_root_uid_passes(self):
        inventory = {
            "system": {"operating_system": "Linux"},
            "users": [{"name": "root", "uid": 0}],
            "listening_ports": [],
            "services": [],
            "updates": [],
            "collection_errors": [],
        }
        results = assess_security_configuration(inventory)
        root = next(r for r in results if r.check_id == "ID-LINUX-001")
        self.assertEqual(root.status, CheckStatus.PASS)

    def test_wildcard_listener_is_unknown_not_confirmed_vulnerability(self):
        inventory = {
            "system": {"operating_system": "Linux"},
            "users": [{"name": "root", "uid": 0}],
            "listening_ports": [{"protocol": "tcp", "local_endpoint": "0.0.0.0:8080"}],
            "services": [],
            "updates": [],
            "collection_errors": [],
        }
        results = assess_security_configuration(inventory)
        listener = next(r for r in results if r.check_id == "NET-LISTEN-001")
        self.assertEqual(listener.status, CheckStatus.UNKNOWN)
        self.assertIn("wildcard", listener.summary)

    def test_loopback_listener_passes_scope_check(self):
        inventory = {
            "system": {"operating_system": "Linux"},
            "users": [{"name": "root", "uid": 0}],
            "listening_ports": [{"protocol": "tcp", "local_endpoint": "127.0.0.1:8080"}],
            "services": [],
            "updates": [],
            "collection_errors": [],
        }
        results = assess_security_configuration(inventory)
        listener = next(r for r in results if r.check_id == "NET-LISTEN-001")
        self.assertEqual(listener.status, CheckStatus.PASS)

    def test_windows_hotfix_inventory_is_not_mislabelled_as_pending(self):
        inventory = {
            "system": {"operating_system": "Windows"},
            "users": [{"name": "emmanuel", "enabled": True}],
            "listening_ports": [],
            "services": [],
            "updates": [{"id": "KB123"}],
            "collection_errors": [],
        }
        results = assess_security_configuration(inventory)
        patch = next(r for r in results if r.check_id == "PATCH-STATE-001")
        self.assertEqual(patch.status, CheckStatus.UNKNOWN)
        self.assertIn("Installed hotfixes", patch.summary)

    def test_collection_error_produces_unknown(self):
        inventory = {
            "system": {"operating_system": "Linux"},
            "users": [],
            "listening_ports": [],
            "services": [],
            "updates": [],
            "collection_errors": [{"section": "users", "error": "permission denied"}],
        }
        results = assess_security_configuration(inventory)
        root = next(r for r in results if r.check_id == "ID-LINUX-001")
        self.assertEqual(root.status, CheckStatus.UNKNOWN)


if __name__ == "__main__":
    unittest.main()
