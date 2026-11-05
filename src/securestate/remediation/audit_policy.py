"""Build safe preview plans for selected Windows audit-policy controls.

This module creates plans only. It never invokes auditpol /set and never
changes local or domain policy.
"""
from __future__ import annotations

from collections import defaultdict

from securestate.assessments.audit_policy import AuditPolicyCollection
from securestate.assessments.audit_policy_baseline import BaselineStatus
from securestate.baselines.windows_audit_policy import (
    BASELINE_ID,
    BASELINE_VERSION,
    AuditPolicyCriterion,
    WINDOWS_CLIENT_BASELINE,
)
from securestate.remediation.models import (
    RemediationAction,
    RemediationPlan,
    RemediationPlanStatus,
    new_plan_id,
    utc_now,
)


def _parse_setting(value: str) -> tuple[bool, bool] | None:
    normalized = " ".join((value or "").strip().lower().replace("&", "and").split())
    values = {
        "success": (True, False),
        "success only": (True, False),
        "failure": (False, True),
        "failure only": (False, True),
        "success and failure": (True, True),
        "failure and success": (True, True),
        "no auditing": (False, False),
        "none": (False, False),
        "not configured": (False, False),
    }
    return values.get(normalized)


def _target_setting(criterion: AuditPolicyCriterion) -> str:
    if criterion.require_success and criterion.require_failure:
        return "Success and Failure"
    if criterion.require_success:
        return "Success"
    if criterion.require_failure:
        return "Failure"
    return "No Auditing"


def build_audit_policy_plan(
    collection: AuditPolicyCollection,
    criteria: tuple[AuditPolicyCriterion, ...] = WINDOWS_CLIENT_BASELINE,
    machine_role: str = "workstation",
) -> RemediationPlan:
    """Create a preview plan for unambiguous NON_COMPLIANT controls only.

    UNKNOWN, REVIEW_REQUIRED, missing, duplicate, excluded, and inaccessible
    evidence is deliberately excluded from automated planning.
    """
    warnings: list[str] = [
        "PREVIEW ONLY: no Windows settings have been changed.",
        "A human must review and approve every proposed action.",
        "Local, domain, or MDM policy may override a local auditpol setting.",
    ]
    if not collection.success:
        warnings.append("Evidence collection failed; no actions can be proposed.")
        return RemediationPlan(
            new_plan_id(), utc_now(), "", BASELINE_ID, BASELINE_VERSION,
            RemediationPlanStatus.BLOCKED, (), tuple(warnings), True,
        )

    machine_names = {row.machine_name for row in collection.rows if row.machine_name}
    if len(machine_names) > 1:
        warnings.append(
            "Evidence contains multiple machine names; the plan is blocked to "
            "prevent applying one host's findings to another host."
        )
        return RemediationPlan(
            new_plan_id(), utc_now(), "", BASELINE_ID, BASELINE_VERSION,
            RemediationPlanStatus.BLOCKED, (), tuple(warnings), True,
        )

    rows_by_guid: dict[str, list] = defaultdict(list)
    for row in collection.rows:
        rows_by_guid[row.subcategory_guid.upper()].append(row)

    actions: list[RemediationAction] = []
    for criterion in criteria:
        if criterion.applicability not in {"all", machine_role}:
            continue
        matches = rows_by_guid.get(criterion.guid.upper(), [])
        if len(matches) != 1:
            continue

        row = matches[0]
        actual = _parse_setting(row.inclusion_setting)
        if actual is None or row.exclusion_setting.strip():
            continue

        missing_required_event = (
            (criterion.require_success and not actual[0])
            or (criterion.require_failure and not actual[1])
        )
        if not missing_required_event:
            continue

        # Only create a plan when the existing baseline comparison would
        # classify this exact, unambiguous control as non-compliant.
        target = _target_setting(criterion)
        control_id = "AUDIT-" + criterion.guid.strip("{}").replace("-", "")
        actions.append(RemediationAction(
            action_id=f"{control_id}-SET",
            control_id=control_id,
            control_name=criterion.name,
            subcategory_guid=criterion.guid,
            observed_setting=row.inclusion_setting,
            target_setting=target,
            require_success=criterion.require_success,
            require_failure=criterion.require_failure,
            rationale=criterion.rationale,
        ))

    status = (
        RemediationPlanStatus.PREVIEW_ONLY
        if actions else RemediationPlanStatus.NO_CHANGES_REQUIRED
    )
    if not actions:
        warnings.append(
            "No safe actions were generated. Controls requiring review or "
            "additional evidence are not eligible for automated planning."
        )

    machine_name = next(iter(machine_names)) if len(machine_names) == 1 else ""

    return RemediationPlan(
        new_plan_id(), utc_now(), machine_name, BASELINE_ID, BASELINE_VERSION,
        status, tuple(actions), tuple(warnings), True,
    )
