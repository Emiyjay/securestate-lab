import sys
import unittest
from pathlib import Path
from datetime import datetime, timezone, timedelta

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from securestate.assessments.audit_policy import AuditPolicyCollection, AuditPolicyRow
from securestate.baselines.windows_audit_policy import WINDOWS_CLIENT_BASELINE
from securestate.remediation.audit_policy import build_audit_policy_plan
from securestate.remediation.executor import simulate_remediation, execute_remediation
from securestate.remediation.models import (
    RemediationPlanStatus, RemediationResultStatus, VerificationStatus,
)
from securestate.remediation.verification import verify_remediation


def make_collection(rows, collected_at=None, success=True, error=""):
    return AuditPolicyCollection(
        success, tuple(rows),
        collected_at or datetime.now(timezone.utc).isoformat(),
        "auditpol", error, False,
    )


class TestRemediationPreview(unittest.TestCase):
    def test_generates_preview_for_missing_required_audit_event(self):
        criterion = WINDOWS_CLIENT_BASELINE[0]  # Credential Validation: Success
        row = AuditPolicyRow(
            "VM-WIN11", "System", criterion.name, criterion.guid,
            "No Auditing", "",
        )
        plan = build_audit_policy_plan(make_collection([row]), criteria=(criterion,))
        self.assertEqual(plan.status, RemediationPlanStatus.PREVIEW_ONLY)
        self.assertEqual(len(plan.actions), 1)
        self.assertEqual(plan.actions[0].target_setting, "Success")
        self.assertTrue(plan.simulation_only)

    def test_does_not_plan_unknown_or_excluded_evidence(self):
        criterion = WINDOWS_CLIENT_BASELINE[0]
        unknown = AuditPolicyRow("VM", "System", criterion.name, criterion.guid, "Unknown", "")
        excluded = AuditPolicyRow("VM", "System", criterion.name, criterion.guid, "No Auditing", "Success")
        self.assertEqual(
            len(build_audit_policy_plan(make_collection([unknown]), criteria=(criterion,)).actions), 0
        )
        self.assertEqual(
            len(build_audit_policy_plan(make_collection([excluded]), criteria=(criterion,)).actions), 0
        )

    def test_does_not_plan_duplicate_or_missing_guid(self):
        criterion = WINDOWS_CLIENT_BASELINE[0]
        row = AuditPolicyRow("VM", "System", criterion.name, criterion.guid, "No Auditing", "")
        duplicate = make_collection([row, row])
        missing = make_collection([])
        self.assertEqual(len(build_audit_policy_plan(duplicate, criteria=(criterion,)).actions), 0)
        self.assertEqual(len(build_audit_policy_plan(missing, criteria=(criterion,)).actions), 0)

    def test_mixed_machine_evidence_blocks_plan(self):
        criterion = WINDOWS_CLIENT_BASELINE[0]
        first = AuditPolicyRow("VM-A", "System", criterion.name, criterion.guid, "No Auditing", "")
        second = AuditPolicyRow("VM-B", "System", criterion.name, criterion.guid, "No Auditing", "")
        plan = build_audit_policy_plan(make_collection([first, second]), criteria=(criterion,))
        self.assertEqual(plan.status, RemediationPlanStatus.BLOCKED)
        self.assertEqual(plan.actions, ())

    def test_failed_collection_blocks_plan(self):
        plan = build_audit_policy_plan(make_collection([], success=False, error="access denied"))
        self.assertEqual(plan.status, RemediationPlanStatus.BLOCKED)
        self.assertEqual(plan.actions, ())

    def test_simulation_never_claims_change_was_applied(self):
        criterion = WINDOWS_CLIENT_BASELINE[0]
        row = AuditPolicyRow("VM", "System", criterion.name, criterion.guid, "No Auditing", "")
        plan = build_audit_policy_plan(make_collection([row]), criteria=(criterion,))
        results = simulate_remediation(plan)
        self.assertEqual(results[0].status, RemediationResultStatus.SIMULATED)
        self.assertIn("No command was executed", results[0].message)

    def test_live_executor_fails_closed(self):
        with self.assertRaises(NotImplementedError):
            execute_remediation(object())

    def test_verification_requires_new_evidence_and_checks_target(self):
        criterion = WINDOWS_CLIENT_BASELINE[0]
        before = AuditPolicyRow("VM", "System", criterion.name, criterion.guid, "No Auditing", "")
        plan = build_audit_policy_plan(make_collection([before]), criteria=(criterion,))
        stale = make_collection([
            AuditPolicyRow("VM", "System", criterion.name, criterion.guid, "Success", "")
        ], collected_at=plan.created_at_utc)
        self.assertEqual(verify_remediation(plan, stale).status, VerificationStatus.UNKNOWN)

        fresh_time = (datetime.fromisoformat(plan.created_at_utc) + timedelta(seconds=1)).isoformat()
        after = make_collection([
            AuditPolicyRow("VM", "System", criterion.name, criterion.guid, "Success", "")
        ], collected_at=fresh_time)
        verified = verify_remediation(plan, after)
        self.assertEqual(verified.status, VerificationStatus.VERIFIED)

    def test_verification_detects_unfixed_control(self):
        criterion = WINDOWS_CLIENT_BASELINE[0]
        before = AuditPolicyRow("VM", "System", criterion.name, criterion.guid, "No Auditing", "")
        plan = build_audit_policy_plan(make_collection([before]), criteria=(criterion,))
        fresh_time = (datetime.fromisoformat(plan.created_at_utc) + timedelta(seconds=1)).isoformat()
        unchanged = make_collection([before], collected_at=fresh_time)
        result = verify_remediation(plan, unchanged)
        self.assertEqual(result.status, VerificationStatus.NOT_VERIFIED)


if __name__ == "__main__":
    unittest.main()
