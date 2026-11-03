"""Microsoft Windows Client audit-policy baseline.

Source: Microsoft Learn, System Audit Policy Recommendations.
The baseline intentionally includes only controls with an explicit Windows
Client baseline recommendation. Blank/conditional/server-only entries are
not silently treated as disabled requirements.
"""
from __future__ import annotations

from dataclasses import dataclass


SOURCE_URL = (
    "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/"
    "security-best-practices/audit-policy-recommendations?tabs=winclient"
)
BASELINE_ID = "microsoft-windows-client-audit-policy"
BASELINE_VERSION = "retrieved-2026-11-03"
PLATFORM_SCOPE = "Windows Client workstation; not a domain-controller baseline"


@dataclass(frozen=True)
class AuditPolicyCriterion:
    guid: str
    name: str
    require_success: bool
    require_failure: bool
    rationale: str
    operational_note: str = ""
    applicability: str = "workstation"


def _criterion(guid: str, name: str, success: bool, failure: bool,
               rationale: str, note: str = "") -> AuditPolicyCriterion:
    return AuditPolicyCriterion(
        guid="{" + guid.strip("{}").upper() + "}",
        name=name,
        require_success=success,
        require_failure=failure,
        rationale=rationale,
        operational_note=note,
    )


# GUIDs are the stable join key; display names are retained for human review.
WINDOWS_CLIENT_BASELINE = (
    _criterion("0CCE923F-69AE-11D9-BED3-505054503030", "Credential Validation", True, False,
               "Microsoft recommends successful credential validation auditing."),
    _criterion("0CCE9236-69AE-11D9-BED3-505054503030", "Computer Account Management", True, False,
               "Microsoft recommends successful computer-account management auditing."),
    _criterion("0CCE923A-69AE-11D9-BED3-505054503030", "Other Account Management Events", True, False,
               "Microsoft recommends successful other-account-management auditing."),
    _criterion("0CCE9237-69AE-11D9-BED3-505054503030", "Security Group Management", True, False,
               "Microsoft recommends successful security-group management auditing."),
    _criterion("0CCE9235-69AE-11D9-BED3-505054503030", "User Account Management", True, False,
               "Microsoft recommends successful user-account management auditing."),
    _criterion("0CCE922B-69AE-11D9-BED3-505054503030", "Process Creation", True, False,
               "Microsoft recommends successful process-creation auditing.",
               "Event volume can be medium to high depending on process activity."),
    _criterion("0CCE9217-69AE-11D9-BED3-505054503030", "Logoff", True, False,
               "Microsoft recommends successful logoff auditing."),
    _criterion("0CCE9215-69AE-11D9-BED3-505054503030", "Logon", True, True,
               "Microsoft recommends both successful and failed logon auditing."),
    _criterion("0CCE921B-69AE-11D9-BED3-505054503030", "Special Logon", True, False,
               "Microsoft recommends successful special-logon auditing."),
    _criterion("0CCE922F-69AE-11D9-BED3-505054503030", "Audit Policy Change", True, True,
               "Microsoft recommends success and failure auditing for audit-policy changes."),
    _criterion("0CCE9230-69AE-11D9-BED3-505054503030", "Authentication Policy Change", True, False,
               "Microsoft recommends successful authentication-policy change auditing."),
    _criterion("0CCE9213-69AE-11D9-BED3-505054503030", "IPsec Driver", True, True,
               "Microsoft recommends success and failure auditing for IPsec Driver."),
    _criterion("0CCE9211-69AE-11D9-BED3-505054503030", "Security State Change", True, True,
               "Microsoft recommends success and failure auditing for security-state changes."),
    _criterion("0CCE9214-69AE-11D9-BED3-505054503030", "Security System Extension", True, True,
               "Microsoft recommends success and failure auditing for security-system extensions."),
    _criterion("0CCE9212-69AE-11D9-BED3-505054503030", "System Integrity", True, True,
               "Microsoft recommends success and failure auditing for system-integrity events."),
)
