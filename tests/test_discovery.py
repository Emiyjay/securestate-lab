import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))

from securestate import discovery


class TestInventoryHelpers(unittest.TestCase):
    def test_as_list_normalises_single_object(self):
        self.assertEqual(discovery._as_list({"name": "x"}), [{"name": "x"}])

    def test_as_list_preserves_list(self):
        self.assertEqual(discovery._as_list([1, 2]), [1, 2])

    def test_as_list_handles_none(self):
        self.assertEqual(discovery._as_list(None), [])

    @patch("securestate.discovery.platform.system", return_value="FreeBSD")
    def test_unsupported_platform_is_reported(self, _):
        result = discovery.collect_system_inventory()
        self.assertEqual(result["system"]["operating_system"], "FreeBSD")
        self.assertEqual(result["collection_errors"][0]["section"], "all")
        self.assertIn("Unsupported operating system", result["collection_errors"][0]["error"])

    @patch("securestate.discovery._windows_software", return_value=[{"name": "Example", "version": "1.0"}])
    @patch("securestate.discovery._windows_updates", return_value=[])
    @patch("securestate.discovery._windows_users", return_value=[])
    @patch("securestate.discovery._windows_services", return_value=[])
    @patch("securestate.discovery._windows_ports", return_value=[])
    @patch("securestate.discovery._windows_admin_group_members", return_value=[{"name": "HOST\\Admin", "sid": "S-1-5-21-1"}])
    @patch("securestate.discovery.platform.system", return_value="Windows")
    def test_windows_inventory_uses_windows_collectors(self, *_mocks):
        result = discovery.collect_system_inventory()
        self.assertEqual(result["software"], [{"name": "Example", "version": "1.0"}])
        self.assertEqual(result["administrators_group_members"], [{"name": "HOST\\Admin", "sid": "S-1-5-21-1"}])
        self.assertEqual(result["collection_errors"], [])

    @patch("securestate.discovery._linux_software", side_effect=RuntimeError("package query unavailable"))
    @patch("securestate.discovery._linux_updates", return_value=[])
    @patch("securestate.discovery._linux_users", return_value=[])
    @patch("securestate.discovery._linux_services", return_value=[])
    @patch("securestate.discovery._linux_ports", return_value=[])
    @patch("securestate.discovery._linux_privileged_group_members", return_value=[])
    @patch("securestate.discovery.platform.system", return_value="Linux")
    def test_linux_section_failure_is_recorded_without_aborting(self, *_mocks):
        result = discovery.collect_system_inventory()
        self.assertEqual(result["software"], [])
        self.assertEqual(len(result["collection_errors"]), 1)
        self.assertEqual(result["collection_errors"][0]["section"], "software")
        self.assertEqual(result["users"], [])

    @patch("securestate.discovery.shutil.which", return_value="/usr/bin/ss")
    @patch("securestate.discovery._run")
    def test_linux_ports_parse_process_owner(self, run_mock, _which):
        run_mock.return_value = type("Result", (), {
            "returncode": 0,
            "stdout": 'tcp LISTEN 0 128 0.0.0.0:8080 0.0.0.0:* users:(("python3",pid=4321,fd=5))\n',
            "stderr": "",
        })()
        result = discovery._linux_ports()
        self.assertEqual(result[0]["process_name"], "python3")
        self.assertEqual(result[0]["process_id"], 4321)
        self.assertTrue(result[0]["process_metadata_available"])

    @patch("securestate.discovery.grp")
    @patch("securestate.discovery.pwd")
    def test_linux_privileged_group_members_include_primary_group_users(self, pwd_mock, grp_mock):
        grp_mock.getgrnam.side_effect = lambda name: (
            type("Group", (), {"gr_mem": ["alice"], "gr_gid": 27})()
            if name == "sudo" else (_ for _ in ()).throw(KeyError(name))
        )
        pwd_mock.getpwall.return_value = [
            type("Account", (), {"pw_name": "bob", "pw_gid": 27})()
        ]
        result = discovery._linux_privileged_group_members()
        self.assertEqual({item["name"] for item in result}, {"alice", "bob"})
        self.assertTrue(all(item["group"] == "sudo" for item in result))


if __name__ == "__main__":
    unittest.main()
