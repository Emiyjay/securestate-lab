"""Simulation-only remediation executor.

Live policy mutation is intentionally not implemented in this feature increment.
"""
from __future__ import annotations

from securestate.remediation.models import (
    RemediationPlan,
    RemediationResult,
    RemediationResultStatus,
    RemediationPlanStatus,
    utc_now,
)


def simulate_remediation(plan: RemediationPlan) -> tuple[RemediationResult, ...]:
    """Return simulated outcomes without invoking subprocesses or changing policy."""
    if not plan.simulation_only:
        raise ValueError("This executor accepts simulation-only plans.")
    if plan.status == RemediationPlanStatus.BLOCKED:
        return tuple(
            RemediationResult(
                plan.plan_id, action.action_id, action.control_id,
                RemediationResultStatus.BLOCKED,
                "Plan is blocked because trustworthy evidence was unavailable.",
                utc_now(),
            )
            for action in plan.actions
        )
    if plan.status == RemediationPlanStatus.NO_CHANGES_REQUIRED:
        return ()

    return tuple(
        RemediationResult(
            plan.plan_id,
            action.action_id,
            action.control_id,
            RemediationResultStatus.SIMULATED,
            (
                f"Would change {action.control_name} from "
                f"'{action.observed_setting}' to '{action.target_setting}'. "
                "No command was executed and no setting was changed."
            ),
            utc_now(),
        )
        for action in plan.actions
    )


def execute_remediation(*_args, **_kwargs):
    """Fail closed until a separately reviewed live executor is implemented."""
    raise NotImplementedError(
        "Live remediation is disabled in this release. Use simulation mode."
    )
