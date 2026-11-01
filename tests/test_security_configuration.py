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

    def test_windows_admin_membership_is_reflected_in_evidence(self):
        inventory = {
            "system": {"operating_system": "Windows"},
            "users": [
                {"name": "admin", "sid": "S-1-5-21-1", "enabled": True},
                {"name": "guest", "sid": "S-1-5-21-2", "enabled": False},
            ],
            "administrators_group_members": [
                {"name": "HOST\\admin", "sid": "S-1-5-21-1", "object_class": "User"},
            ],
            "listening_ports": [],
            "services": [],
            "updates": [],
            "collection_errors": [],
        }
        results = assess_security_configuration(inventory)
        identity = next(r for r in results if r.check_id == "ID-WIN-001")
        self.assertEqual(identity.status, CheckStatus.UNKNOWN)
        self.assertIn("1 Administrators group member", identity.evidence)
        self.assertIn("1 matched enabled local administrator", identity.evidence)

    def test_wildcard_listener_evidence_includes_process_owner(self):
        inventory = {
            "system": {"operating_system": "Windows"},
            "users": [],
            "administrators_group_members": [],
            "listening_ports": [{
                "LocalAddress": "0.0.0.0", "LocalPort": 8080,
                "process_id": 4321, "process_name": "example-service",
            }],
            "services": [],
            "updates": [],
            "collection_errors": [],
        }
        results = assess_security_configuration(inventory)
        listener = next(r for r in results if r.check_id == "NET-LISTEN-001")
        self.assertEqual(listener.status, CheckStatus.UNKNOWN)
        self.assertIn("example-service", listener.evidence)
        self.assertIn("4321", listener.evidence)


if __name__ == "__main__":
    unittest.main()
