import sys
import unittest
from pathlib import Path

sys.path.insert(
    0,
    str(Path(__file__).resolve().parents[1] / "src")
)

from securestate.models import CheckStatus
from securestate.rules import evaluate_boolean_control


class TestBooleanControl(unittest.TestCase):

    def evaluate(self, observed, expected=True, supported=True):
        return evaluate_boolean_control(
            check_id="TEST-001",
            control="Firewall",
            platform="Windows 11",
            observed_value=observed,
            expected_value=expected,
            evidence="Test evidence",
            recommendation="Review firewall configuration",
            supported=supported
        )

    def test_enabled_control_passes(self):
        result = self.evaluate(True)
        self.assertEqual(result.status, CheckStatus.PASS)

    def test_disabled_control_fails(self):
        result = self.evaluate(False)
        self.assertEqual(result.status, CheckStatus.FAIL)

    def test_missing_evidence_is_unknown(self):
        result = self.evaluate(None)
        self.assertEqual(result.status, CheckStatus.UNKNOWN)

    def test_unsupported_control_is_not_applicable(self):
        result = self.evaluate(None, supported=False)
        self.assertEqual(result.status, CheckStatus.NOT_APPLICABLE)


if __name__ == "__main__":
    unittest.main()