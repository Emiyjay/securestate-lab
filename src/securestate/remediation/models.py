"""Typed data models for preview-first remediation and verification."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from uuid import uuid4


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class RemediationPlanStatus(str, Enum):
    PREVIEW_ONLY = "PREVIEW_ONLY"
    NO_CHANGES_REQUIRED = "NO_CHANGES_REQUIRED"
    BLOCKED = "BLOCKED"


class RemediationResultStatus(str, Enum):
    SIMULATED = "SIMULATED"
    BLOCKED = "BLOCKED"
    FAILED = "FAILED"


class VerificationStatus(str, Enum):
    VERIFIED = "VERIFIED"
    NOT_VERIFIED = "NOT_VERIFIED"
    UNKNOWN = "UNKNOWN"
    NOT_APPLICABLE = "NOT_APPLICABLE"


@dataclass(frozen=True)
class RemediationAction:
    action_id: str
    control_id: str
    control_name: str
    subcategory_guid: str
    observed_setting: str
    target_setting: str
    require_success: bool
    require_failure: bool
    rationale: str


@dataclass(frozen=True)
class RemediationPlan:
    plan_id: str
    created_at_utc: str
    machine_name: str
    baseline_id: str
    baseline_version: str
    status: RemediationPlanStatus
    actions: tuple[RemediationAction, ...]
    warnings: tuple[str, ...]
    simulation_only: bool = True


@dataclass(frozen=True)
class RemediationResult:
    plan_id: str
    action_id: str
    control_id: str
    status: RemediationResultStatus
    message: str
    simulated_at_utc: str


@dataclass(frozen=True)
class VerificationFinding:
    action_id: str
    control_id: str
    control_name: str
    status: VerificationStatus
    expected_setting: str
    observed_setting: str
    explanation: str


@dataclass(frozen=True)
class RemediationVerification:
    plan_id: str
    verified_at_utc: str
    status: VerificationStatus
    findings: tuple[VerificationFinding, ...]
    summary: str


def new_plan_id() -> str:
    return "RMP-" + uuid4().hex[:12].upper()
