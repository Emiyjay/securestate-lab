"""Pure comparison of collected Windows audit policy against a versioned baseline."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from collections import Counter
from typing import Iterable

from securestate.assessments.audit_policy import AuditPolicyCollection, AuditPolicyRow
from securestate.baselines.windows_audit_policy import (
    AuditPolicyCriterion, BASELINE_ID, BASELINE_VERSION, SOURCE_URL,
    WINDOWS_CLIENT_BASELINE,
)


class BaselineStatus(str, Enum):
    COMPLIANT = "COMPLIANT"
    NON_COMPLIANT = "NON_COMPLIANT"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    UNKNOWN = "UNKNOWN"
    NOT_APPLICABLE = "NOT_APPLICABLE"


@dataclass(frozen=True)
class AuditPolicyFinding:
    control_id: str
    control_name: str
    guid: str
    status: BaselineStatus
    observed_setting: str
    expected_setting: str
    explanation: str
    recommendation: str


@dataclass(frozen=True)
class BaselineAssessment:
    baseline_id: str
    baseline_version: str
    source_url: str
    platform_scope: str
    status: BaselineStatus
    findings: tuple[AuditPolicyFinding, ...]
    summary: str


def _parse_setting(value: str) -> tuple[bool, bool] | None:
    normalized = " ".join((value or "").strip().lower().replace("&", "and").split())
    if normalized in {"success", "success only"}:
        return True, False
    if normalized in {"failure", "failure only"}:
        return False, True
    if normalized in {"success and failure", "failure and success"}:
        return True, True
    if normalized in {"no auditing", "none", "not configured"}:
        return False, False
    return None


def _expected(criterion: AuditPolicyCriterion) -> str:
    if criterion.require_success and criterion.require_failure:
        return "Success and Failure"
    if criterion.require_success:
        return "Success"
    if criterion.require_failure:
        return "Failure"
    return "No Auditing"


def _finding(criterion: AuditPolicyCriterion, row: AuditPolicyRow) -> AuditPolicyFinding:
    observed = row.inclusion_setting
    actual = _parse_setting(observed)
    expected = _expected(criterion)
    if actual is None:
        status = BaselineStatus.UNKNOWN
        explanation = "The observed inclusion setting is not recognised; the control cannot be compared safely."
    elif row.exclusion_setting.strip():
        status = BaselineStatus.REVIEW_REQUIRED
        explanation = (
            "An exclusion setting is present. The effective policy may differ from the inclusion setting; "
            "manual review is required."
        )
    else:
        missing = (
            (criterion.require_success and not actual[0])
            or (criterion.require_failure and not actual[1])
        )
        extra = (
            (actual[0] and not criterion.require_success)
            or (actual[1] and not criterion.require_failure)
        )
        if missing:
            status = BaselineStatus.NON_COMPLIANT
            explanation = "One or more audit event types explicitly required by the baseline are disabled."
        elif extra:
            status = BaselineStatus.REVIEW_REQUIRED
            explanation = (
                "All required audit event types are enabled, but additional auditing is enabled beyond "
                "the baseline recommendation. Review event volume and operational impact."
            )
        else:
            status = BaselineStatus.COMPLIANT
            explanation = "The observed setting satisfies the baseline's required audit event types."
    return AuditPolicyFinding(
        control_id="AUDIT-" + criterion.guid.strip("{}").replace("-", ""),
        control_name=criterion.name,
        guid=criterion.guid,
        status=status,
        observed_setting=observed,
        expected_setting=expected,
        explanation=explanation,
        recommendation=criterion.rationale + (
            (" " + criterion.operational_note) if criterion.operational_note else ""
        ),
    )


def compare_audit_policy(
    collection: AuditPolicyCollection,
    criteria: Iterable[AuditPolicyCriterion] = WINDOWS_CLIENT_BASELINE,
    machine_role: str = "workstation",
) -> BaselineAssessment:
    """Compare exact GUID matches. Missing, duplicate or inaccessible evidence is never compliant."""
    criteria = tuple(criteria)
    if not collection.success:
        return BaselineAssessment(
            BASELINE_ID, BASELINE_VERSION, SOURCE_URL,
            "Windows Client workstation; not a domain-controller baseline",
            BaselineStatus.UNKNOWN, (),
            "Audit policy evidence was not collected: " + collection.error,
        )

    by_guid: dict[str, list[AuditPolicyRow]] = {}
    for row in collection.rows:
        by_guid.setdefault(row.subcategory_guid.upper(), []).append(row)

    findings: list[AuditPolicyFinding] = []
    for criterion in criteria:
        if criterion.applicability != "all" and criterion.applicability != machine_role:
            findings.append(AuditPolicyFinding(
                "AUDIT-" + criterion.guid.strip("{}").replace("-", ""),
                criterion.name, criterion.guid, BaselineStatus.NOT_APPLICABLE,
                "", _expected(criterion),
                "This criterion does not apply to the declared machine role.",
                "Select the baseline matching the host's actual role.",
            ))
            continue
        matches = by_guid.get(criterion.guid.upper(), [])
        if not matches:
            findings.append(AuditPolicyFinding(
                "AUDIT-" + criterion.guid.strip("{}").replace("-", ""),
                criterion.name, criterion.guid, BaselineStatus.UNKNOWN,
                "", _expected(criterion),
                "No collected row matched this exact subcategory GUID.",
                "Recollect audit policy and verify the platform's subcategory inventory.",
            ))
        elif len(matches) > 1:
            findings.append(AuditPolicyFinding(
                "AUDIT-" + criterion.guid.strip("{}").replace("-", ""),
                criterion.name, criterion.guid, BaselineStatus.UNKNOWN,
                "; ".join(row.inclusion_setting for row in matches), _expected(criterion),
                "Multiple rows matched the same GUID; evidence is ambiguous.",
                "Inspect the raw auditpol output before making a compliance decision.",
            ))
        else:
            findings.append(_finding(criterion, matches[0]))

    counts = Counter(item.status for item in findings)
    if counts[BaselineStatus.NON_COMPLIANT]:
        overall = BaselineStatus.NON_COMPLIANT
    elif counts[BaselineStatus.UNKNOWN]:
        overall = BaselineStatus.UNKNOWN
    elif counts[BaselineStatus.REVIEW_REQUIRED]:
        overall = BaselineStatus.REVIEW_REQUIRED
    elif counts[BaselineStatus.COMPLIANT] == 0:
        overall = BaselineStatus.NOT_APPLICABLE
    else:
        overall = BaselineStatus.COMPLIANT
    summary = ", ".join(
        f"{status.value}: {counts[status]}" for status in BaselineStatus if counts[status]
    )
    return BaselineAssessment(
        BASELINE_ID, BASELINE_VERSION, SOURCE_URL,
        "Windows Client workstation; not a domain-controller baseline",
        overall, tuple(findings), summary or "No baseline controls were evaluated.",
    )
