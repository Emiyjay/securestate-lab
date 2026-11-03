"""Evidence-based, read-only security configuration checks.

The engine deliberately distinguishes observable configuration from policy
judgements that require administrator intent or vendor security metadata.
"""
from __future__ import annotations

import platform as host_platform
from typing import Any

from securestate.models import AssessmentResult, CheckStatus


def _result(check_id: str, control: str, os_name: str, status: CheckStatus,
            summary: str, evidence: str, recommendation: str) -> AssessmentResult:
    return AssessmentResult.create(
        check_id=check_id,
        control=control,
        platform=os_name,
        status=status,
        summary=summary,
        evidence=evidence,
        recommendation=recommendation,
    )


def _is_wildcard_listener(item: dict[str, Any]) -> bool:
    address = str(item.get("LocalAddress", item.get("local_address", ""))).strip()
    endpoint = str(item.get("local_endpoint", "")).strip()
    if endpoint:
        # ss commonly emits 0.0.0.0:PORT, *:PORT, [::]:PORT and :::PORT.
        host = endpoint.rsplit(":", 1)[0].strip("[]")
        if host in {"*", "0.0.0.0", "::", ""}:
            return True
        return False
    return address in {"0.0.0.0", "::", "*"}


def _is_loopback_listener(item: dict[str, Any]) -> bool:
    address = str(item.get("LocalAddress", item.get("local_address", ""))).strip()
    endpoint = str(item.get("local_endpoint", "")).strip()
    if endpoint:
        host = endpoint.rsplit(":", 1)[0].strip("[]")
        return host == "127.0.0.1" or host.lower() == "::1" or host.startswith("127.")
    return address == "::1" or address.startswith("127.")


def assess_security_configuration(
    inventory: dict[str, Any],
    os_name: str | None = None,
) -> list[AssessmentResult]:
    """Evaluate observable inventory facts without changing the host."""
    os_name = os_name or inventory.get("system", {}).get("operating_system") or host_platform.system()
    errors = {entry.get("section") for entry in inventory.get("collection_errors", [])}
    results: list[AssessmentResult] = []

    # Privileged identity integrity: Linux UID 0 is an objective OS privilege.
    if os_name == "Linux":
        if "users" in errors:
            results.append(_result(
                "ID-LINUX-001", "Root identity uniqueness", os_name,
                CheckStatus.UNKNOWN, "Root identity could not be evaluated.",
                "Local account collection failed.",
                "Retry account collection with sufficient read permissions.",
            ))
        else:
            root_accounts = [u for u in inventory.get("users", []) if u.get("uid") == 0]
            unexpected = [u.get("name", "<unnamed>") for u in root_accounts if u.get("name") != "root"]
            if unexpected:
                results.append(_result(
                    "ID-LINUX-001", "Root identity uniqueness", os_name,
                    CheckStatus.FAIL,
                    "Additional account names have UID 0.",
                    "UID 0 accounts: " + ", ".join(
                        str(u.get("name", "<unnamed>")) for u in root_accounts
                    ),
                    "Confirm whether each additional UID 0 account is required; remove unintended UID 0 assignments.",
                ))
            elif root_accounts:
                results.append(_result(
                    "ID-LINUX-001", "Root identity uniqueness", os_name,
                    CheckStatus.PASS, "Only the root account has UID 0.",
                    "Exactly one UID 0 account named root was observed.",
                    "Continue monitoring privileged account changes.",
                ))
            else:
                results.append(_result(
                    "ID-LINUX-001", "Root identity uniqueness", os_name,
                    CheckStatus.UNKNOWN, "No UID 0 account was returned.",
                    "The account inventory did not contain a root identity.",
                    "Verify account collection completeness and inspect /etc/passwd.",
                ))
    elif os_name == "Windows":
        if "administrators_group_members" in errors:
            admin_evidence = "Local Administrators group membership collection failed."
            admin_summary = "Administrative membership could not be evaluated."
        else:
            members = inventory.get("administrators_group_members", [])
            local_users = {u.get("sid"): u for u in inventory.get("users", []) if u.get("sid")}
            local_admins = [
                (member, local_users.get(member.get("sid")))
                for member in members
                if member.get("sid") in local_users
            ]
            enabled_local_admins = [
                member.get("name", "<unnamed>")
                for member, user in local_admins
                if user and user.get("enabled") is True
            ]
            admin_evidence = (
                f"{len(inventory.get('users', []))} local account records; "
                f"{len(members)} Administrators group member(s); "
                f"{len(local_admins)} matched local account(s); "
                f"{len(enabled_local_admins)} matched enabled local administrator account(s)."
            )
            if enabled_local_admins:
                admin_evidence += " Enabled local administrators: " + ", ".join(enabled_local_admins)
            admin_summary = "Administrators group membership collected; authorization policy review is still required."
        results.append(_result(
            "ID-WIN-001", "Local account privilege review", os_name,
            CheckStatus.UNKNOWN, admin_summary, admin_evidence,
            "Confirm each administrator is authorized, necessary, individually attributable, and protected by an appropriate authentication policy.",
        ))

    if os_name == "Linux":
        if "privileged_group_members" in errors:
            privileged_evidence = "Administrative group membership collection failed."
        else:
            privileged = inventory.get("privileged_group_members", [])
            names = sorted({f"{item.get('name')} ({item.get('group')})" for item in privileged})
            privileged_evidence = (
                f"{len(privileged)} sudo/wheel group membership record(s) collected."
            )
            if names:
                privileged_evidence += " Members: " + ", ".join(names)
        results.append(_result(
            "ID-LINUX-002", "Administrative group membership review", os_name,
            CheckStatus.UNKNOWN,
            "Administrative group membership collected; authorization policy review is still required.",
            privileged_evidence,
            "Verify each sudo/wheel member is authorized and follows least-privilege requirements.",
        ))

    # Listening sockets: wildcard binds indicate broad interface exposure, not
    # proof of remote reachability or a vulnerability.
    if "listening_ports" in errors:
        results.append(_result(
            "NET-LISTEN-001", "Listening interface exposure", os_name,
            CheckStatus.UNKNOWN, "Listening endpoints could not be evaluated.",
            "Listening-port collection failed.",
            "Retry endpoint collection and correlate listeners with process ownership and firewall policy.",
        ))
    else:
        listeners = inventory.get("listening_ports", [])
        wildcard = [item for item in listeners if _is_wildcard_listener(item)]
        loopback = [item for item in listeners if _is_loopback_listener(item)]
        if wildcard:
            owner_records = sorted({
                f"{item.get('process_name') or 'unknown'} (PID {item.get('process_id', '?')})"
                for item in wildcard
                if item.get("process_name") or item.get("process_id") is not None
            })
            evidence = (
                f"{len(listeners)} listening endpoints observed; "
                f"{len(wildcard)} wildcard-bound and {len(loopback)} loopback-bound."
            )
            if owner_records:
                evidence += " Process owners: " + ", ".join(owner_records)
            elif os_name == "Linux":
                evidence += " Process ownership was not exposed by ss; repeat with appropriate privileges if authorized."
            results.append(_result(
                "NET-LISTEN-001", "Listening interface exposure", os_name,
                CheckStatus.UNKNOWN,
                f"{len(wildcard)} listener(s) bind to wildcard interfaces.",
                evidence,
                "Identify each owning process, confirm intended network access, and validate reachability against host firewall rules.",
            ))
        elif listeners:
            results.append(_result(
                "NET-LISTEN-001", "Listening interface exposure", os_name,
                CheckStatus.PASS,
                "No wildcard-bound listening endpoints were observed.",
                f"{len(listeners)} listening endpoints observed; {len(loopback)} were loopback-bound.",
                "Continue reviewing new listeners and validate application-specific exposure requirements.",
            ))
        else:
            results.append(_result(
                "NET-LISTEN-001", "Listening interface exposure", os_name,
                CheckStatus.PASS, "No listening endpoints were returned.",
                "The listener collection completed and returned zero records.",
                "Repeat the check periodically; an empty result is only a point-in-time observation.",
            ))

    # Services cannot be judged unnecessary from state alone.
    if "services" in errors:
        service_status = CheckStatus.UNKNOWN
        service_evidence = "Service collection failed."
        service_summary = "Service configuration could not be reviewed."
    else:
        services = inventory.get("services", [])
        service_status = CheckStatus.UNKNOWN
        service_evidence = f"{len(services)} service records collected; business purpose and approved baseline are not known."
        service_summary = "Service inventory requires policy and ownership review."
    results.append(_result(
        "SVC-REVIEW-001", "Service necessity review", os_name,
        service_status, service_summary, service_evidence,
        "Map running services to owners and business requirements; disable only services confirmed unnecessary through an approved change.",
    ))

    # Patch inventory has different semantics on Windows and Linux. Do not
    # treat installed Windows hotfixes as pending updates.
    if "updates" in errors:
        patch_status = CheckStatus.UNKNOWN
        patch_summary = "Update state could not be collected."
        patch_evidence = "Update collection failed."
    elif os_name == "Windows":
        patch_status = CheckStatus.UNKNOWN
        patch_summary = "Installed hotfixes were inventoried; pending update state is not available."
        patch_evidence = f"{len(inventory.get('updates', []))} installed hotfix records returned by Get-HotFix."
    else:
        pending = inventory.get("updates", [])
        patch_status = CheckStatus.UNKNOWN
        patch_summary = f"{len(pending)} update candidate(s) were listed; security relevance is not yet classified."
        patch_evidence = f"{len(pending)} package update candidates returned by the configured package manager."
    results.append(_result(
        "PATCH-STATE-001", "Patch state review", os_name,
        patch_status, patch_summary, patch_evidence,
        "Correlate update candidates with vendor security advisories and confirm installation state before assigning vulnerability severity.",
    ))

    return results
