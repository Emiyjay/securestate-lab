import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from securestate.simulation import SCENARIOS, get_scenarios, assess_scenario


class TestSimulation(unittest.TestCase):
    def test_eight_scenarios_are_available(self):
        self.assertEqual(len(get_scenarios("Windows")), 4)
        self.assertEqual(len(get_scenarios("Linux")), 4)

    def test_all_scenarios_fail_at_baseline(self):
        for platform in ("Windows", "Linux"):
            for scenario in get_scenarios(platform):
                result = assess_scenario(platform, scenario["id"])
                self.assertEqual(result["status"], "FAIL")
                self.assertTrue(result["is_simulated"])

    def test_remediation_changes_result_to_pass(self):
        for platform in ("Windows", "Linux"):
            for scenario in get_scenarios(platform):
                result = assess_scenario(platform, scenario["id"], remediated=True)
                self.assertEqual(result["status"], "PASS")
                self.assertTrue(result["remediated"])

    def test_unknown_scenario_is_rejected(self):
        with self.assertRaises(ValueError):
            assess_scenario("Windows", "W99")

    def test_scenario_copy_does_not_mutate_fixtures(self):
        scenarios = get_scenarios("Windows")
        scenarios[0]["control"] = "Changed"
        self.assertNotEqual(SCENARIOS["Windows"][0]["control"], "Changed")


if __name__ == "__main__":
    unittest.main()
