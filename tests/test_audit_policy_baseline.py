import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from securestate.assessments.audit_policy import (
    AuditPolicyCollection, AuditPolicyRow, parse_auditpol_csv,
)
from securestate.assessments.audit_policy_baseline import (
    BaselineStatus, compare_audit_policy,
)
from securestate.baselines.windows_audit_policy import WINDOWS_CLIENT_BASELINE


GUID_LOGON = "{0CCE9215-69AE-11D9-BED3-505054503030}"


def row(setting="Success and Failure", guid=GUID_LOGON, exclusion=""):
    return AuditPolicyRow("HOST", "System", "Logon", guid, setting, exclusion)


def collection(*rows, success=True, error=""):
    return AuditPolicyCollection(success, tuple(rows), "2026-11-03T00:00:00+00:00",
                                 "auditpol", error, False)


class TestAuditPolicyParsing(unittest.TestCase):
    def test_preserves_all_csv_fields_and_normalizes_guid(self):
        data = (
            '"Machine Name","Policy Target","Subcategory","Subcategory GUID",'
            '"Inclusion Setting","Exclusion Setting"\n'
            '"ADAUGO","System","Logon","0cce9215-69ae-11d9-bed3-505054503030",'
            '"Success and Failure",""'
        )
        parsed = parse_auditpol_csv(data)
        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0].machine_name, "ADAUGO")
        self.assertEqual(parsed[0].subcategory_guid, GUID_LOGON)
        self.assertEqual(parsed[0].inclusion_setting, "Success and Failure")


class TestAuditPolicyBaseline(unittest.TestCase):
    def test_windows_client_baseline_uses_correct_system_audit_guids(self):
        expected = {
            "IPsec Driver": "{0CCE9213-69AE-11D9-BED3-505054503030}",
            "Logoff": "{0CCE9216-69AE-11D9-BED3-505054503030}",
            "Security State Change": "{0CCE9210-69AE-11D9-BED3-505054503030}",
            "Security System Extension": "{0CCE9211-69AE-11D9-BED3-505054503030}",
            "System Integrity": "{0CCE9212-69AE-11D9-BED3-505054503030}",
        }
        actual = {criterion.name: criterion.guid for criterion in WINDOWS_CLIENT_BASELINE}
        for name, guid in expected.items():
            with self.subTest(subcategory=name):
                self.assertEqual(actual.get(name), guid)

    def test_exact_match_is_compliant(self):
        result = compare_audit_policy(collection(row()), criteria=(WINDOWS_CLIENT_BASELINE[7],))
        self.assertEqual(result.findings[0].status, BaselineStatus.COMPLIANT)

    def test_missing_required_failure_is_non_compliant(self):
        result = compare_audit_policy(collection(row("Success")), criteria=(WINDOWS_CLIENT_BASELINE[7],))
        self.assertEqual(result.findings[0].status, BaselineStatus.NON_COMPLIANT)

    def test_extra_failure_bit_is_review_not_non_compliant(self):
        criterion = WINDOWS_CLIENT_BASELINE[0]  # Success only
        evidence = row("Success and Failure", criterion.guid)
        result = compare_audit_policy(collection(evidence), criteria=(criterion,))
        self.assertEqual(result.findings[0].status, BaselineStatus.REVIEW_REQUIRED)

    def test_missing_guid_is_unknown(self):
        result = compare_audit_policy(collection(row(guid="{00000000-0000-0000-0000-000000000000}")),
                                      criteria=(WINDOWS_CLIENT_BASELINE[7],))
        self.assertEqual(result.findings[0].status, BaselineStatus.UNKNOWN)

    def test_duplicate_guid_is_unknown(self):
        result = compare_audit_policy(collection(row(), row()), criteria=(WINDOWS_CLIENT_BASELINE[7],))
        self.assertEqual(result.findings[0].status, BaselineStatus.UNKNOWN)

    def test_unrecognised_setting_is_unknown(self):
        result = compare_audit_policy(collection(row("Enabled maybe")), criteria=(WINDOWS_CLIENT_BASELINE[7],))
        self.assertEqual(result.findings[0].status, BaselineStatus.UNKNOWN)

    def test_exclusion_requires_review(self):
        result = compare_audit_policy(collection(row(exclusion="Failure")),
                                      criteria=(WINDOWS_CLIENT_BASELINE[7],))
        self.assertEqual(result.findings[0].status, BaselineStatus.REVIEW_REQUIRED)

    def test_failed_collection_is_unknown(self):
        result = compare_audit_policy(collection(success=False, error="privilege not held"))
        self.assertEqual(result.status, BaselineStatus.UNKNOWN)
        self.assertIn("privilege not held", result.summary)

    def test_wrong_machine_role_is_not_applicable(self):
        result = compare_audit_policy(collection(row()), criteria=(WINDOWS_CLIENT_BASELINE[7],),
                                      machine_role="domain_controller")
        self.assertEqual(result.findings[0].status, BaselineStatus.NOT_APPLICABLE)


if __name__ == "__main__":
    unittest.main()
