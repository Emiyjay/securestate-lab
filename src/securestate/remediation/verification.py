"""Independent verification of a remediation plan using fresh auditpol evidence."""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime

from securestate.assessments.audit_policy import AuditPolicyCollection
from securestate.remediation.models import (
    RemediationPlan,
    RemediationVerification,
    VerificationFinding,
    VerificationStatus,
    utc_now,
)


def _parse_setting(value: str) -> tuple[bool, bool] | None:
    normalized = " ".join((value or "").strip().lower().replace("&", "and").split())
    return {
        "success": (True, False),
        "success only": (True, False),
        "failure": (False, True),
        "failure only": (False, True),
        "success and failure": (True, True),
        "failure and success": (True, True),
        "no auditing": (False, False),
        "none": (False, False),
        "not configured": (False, False),
    }.get(normalized)


def _is_fresh(plan_created: str, collected: str) -> bool:
    try:
        plan_time = datetime.fromisoformat(plan_created)
        collection_time = datetime.fromisoformat(collected)
        return collection_time >= plan_time
    except (TypeError, ValueError):
        return False


def verify_remediation(
    plan: RemediationPlan,
    collection: AuditPolicyCollection,
) -> RemediationVerification:
    """Compare planned target states with a new collection; never assume success."""
    if not collection.success:
        return RemediationVerification(
            plan.plan_id, utc_now(), VerificationStatus.UNKNOWN, (),
            "Verification unavailable: " + collection.error,
        )
    if not _is_fresh(plan.created_at_utc, collection.collected_at_utc):
        return RemediationVerification(
            plan.plan_id, utc_now(), VerificationStatus.UNKNOWN, (),
            "Verification evidence is not newer than the remediation plan.",
        )

    rows_by_guid: dict[str, list] = defaultdict(list)
    for row in collection.rows:
        rows_by_guid[row.subcategory_guid.upper()].append(row)

    findings: list[VerificationFinding] = []
    for action in plan.actions:
        matches = rows_by_guid.get(action.subcategory_guid.upper(), [])
        if len(matches) != 1:
            findings.append(VerificationFinding(
                action.action_id, action.control_id, action.control_name,
                VerificationStatus.UNKNOWN, action.target_setting, "",
                "The target GUID was missing or duplicated in fresh evidence.",
            ))
            continue

        row = matches[0]
        actual = _parse_setting(row.inclusion_setting)
        if actual is None or row.exclusion_setting.strip():
            findings.append(VerificationFinding(
                action.action_id, action.control_id, action.control_name,
                VerificationStatus.UNKNOWN, action.target_setting,
                row.inclusion_setting,
                "The setting is unrecognised or an exclusion is present.",
            ))
            continue

        target = (action.require_success, action.require_failure)
        if actual == target:
            findings.append(VerificationFinding(
                action.action_id, action.control_id, action.control_name,
                VerificationStatus.VERIFIED, action.target_setting,
                row.inclusion_setting,
                "Fresh evidence matches the required audit event configuration.",
            ))
        else:
            findings.append(VerificationFinding(
                action.action_id, action.control_id, action.control_name,
                VerificationStatus.NOT_VERIFIED, action.target_setting,
                row.inclusion_setting,
                "Fresh evidence does not match the planned target configuration.",
            ))

    statuses = {finding.status for finding in findings}
    if not findings:
        overall = VerificationStatus.NOT_APPLICABLE
    elif VerificationStatus.NOT_VERIFIED in statuses:
        overall = VerificationStatus.NOT_VERIFIED
    elif VerificationStatus.UNKNOWN in statuses:
        overall = VerificationStatus.UNKNOWN
    elif statuses == {VerificationStatus.VERIFIED}:
        overall = VerificationStatus.VERIFIED
    else:
        overall = VerificationStatus.UNKNOWN

    counts = {status: sum(f.status == status for f in findings) for status in VerificationStatus}
    summary = ", ".join(f"{status.value}: {count}" for status, count in counts.items() if count)
    return RemediationVerification(
        plan.plan_id, utc_now(), overall, tuple(findings), summary,
    )
