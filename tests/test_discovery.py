import unittest
from unittest.mock import patch

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
    @patch("securestate.discovery.platform.system", return_value="Windows")
    def test_windows_inventory_uses_windows_collectors(self, *_mocks):
        result = discovery.collect_system_inventory()
        self.assertEqual(result["software"], [{"name": "Example", "version": "1.0"}])
        self.assertEqual(result["collection_errors"], [])

    @patch("securestate.discovery._linux_software", side_effect=RuntimeError("package query unavailable"))
    @patch("securestate.discovery._linux_updates", return_value=[])
    @patch("securestate.discovery._linux_users", return_value=[])
    @patch("securestate.discovery._linux_services", return_value=[])
    @patch("securestate.discovery._linux_ports", return_value=[])
    @patch("securestate.discovery.platform.system", return_value="Linux")
    def test_linux_section_failure_is_recorded_without_aborting(self, *_mocks):
        result = discovery.collect_system_inventory()
        self.assertEqual(result["software"], [])
        self.assertEqual(len(result["collection_errors"]), 1)
        self.assertEqual(result["collection_errors"][0]["section"], "software")
        self.assertEqual(result["users"], [])


if __name__ == "__main__":
    unittest.main()
