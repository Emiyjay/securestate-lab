"""Cross-platform, read-only host firewall assessment."""
from __future__ import annotations

import platform
import shutil
import subprocess

from securestate.models import AssessmentResult, CheckStatus
from securestate.assessments.windows_firewall import assess_windows_firewall


def _result(check_id, control, status, summary, evidence, recommendation):
    return AssessmentResult.create(
        check_id=check_id,
        control=control,
        platform="Linux",
        status=status,
        summary=summary,
        evidence=evidence,
        recommendation=recommendation,
    )


def _run(command):
    return subprocess.run(
        command, capture_output=True, text=True, timeout=20, check=False
    )


def assess_linux_firewall():
    """Inspect common Linux firewall managers without changing their state.

    A detected inactive manager is a FAIL. Missing tools or ambiguous output
    are UNKNOWN; absence of UFW alone is not treated as an absent firewall.
    """
    if platform.system() != "Linux":
        return [_result(
            "LINUX-FW-NA", "Linux host firewall", CheckStatus.NOT_APPLICABLE,
            "This check applies only to Linux.",
            "Current operating system is not Linux.",
            "Use the firewall adapter for the current operating system.",
        )]

    evidence = []
    detected = False
    failures = []

    if shutil.which("ufw"):
        detected = True
        try:
            result = _run(["ufw", "status"])
            output = (result.stdout + "\n" + result.stderr).strip()
            evidence.append("UFW: " + (output or f"exit code {result.returncode}"))
            if result.returncode == 0 and "Status: active" in output:
                return [_result(
                    "LINUX-FW-UFW", "UFW firewall", CheckStatus.PASS,
                    "UFW reports that the firewall is active.",
                    output,
                    "Review the active rules against the host's approved network policy.",
                )]
            if result.returncode == 0 and "Status: inactive" in output:
                failures.append("UFW reports Status: inactive.")
            else:
                failures.append("UFW state could not be interpreted.")
        except (OSError, subprocess.SubprocessError) as exc:
            failures.append(f"UFW inspection failed: {exc}")

    if shutil.which("firewall-cmd"):
        detected = True
        try:
            result = _run(["firewall-cmd", "--state"])
            output = (result.stdout + "\n" + result.stderr).strip()
            evidence.append("firewalld: " + (output or f"exit code {result.returncode}"))
            if result.returncode == 0 and result.stdout.strip() == "running":
                return [_result(
                    "LINUX-FW-FIREWALLD", "firewalld service", CheckStatus.PASS,
                    "firewalld reports that it is running.",
                    output,
                    "Review active zones and rules; a running daemon does not prove the policy is appropriate.",
                )]
            if result.returncode == 0 and result.stdout.strip() == "not running":
                failures.append("firewalld reports that it is not running.")
            else:
                failures.append("firewalld state could not be interpreted.")
        except (OSError, subprocess.SubprocessError) as exc:
            failures.append(f"firewalld inspection failed: {exc}")

    if shutil.which("nft"):
        detected = True
        try:
            result = _run(["nft", "list", "ruleset"])
            output = (result.stdout + "\n" + result.stderr).strip()
            if result.returncode == 0:
                if result.stdout.strip():
                    return [_result(
                        "LINUX-FW-NFT", "nftables ruleset", CheckStatus.PASS,
                        "An nftables ruleset was returned for review.",
                        result.stdout[:12000],
                        "Validate that the ruleset has the intended default policies and required protections.",
                    )]
                evidence.append("nftables returned an empty ruleset.")
                failures.append("nftables ruleset is empty.")
            else:
                evidence.append("nftables: " + (output or f"exit code {result.returncode}"))
                failures.append("nftables ruleset could not be read.")
        except (OSError, subprocess.SubprocessError) as exc:
            failures.append(f"nftables inspection failed: {exc}")

    if not detected:
        return [_result(
            "LINUX-FW-UNKNOWN", "Linux host firewall", CheckStatus.UNKNOWN,
            "No supported firewall inspection tool was found.",
            "Checked for ufw, firewall-cmd and nft.",
            "Install or enable the firewall management tooling appropriate to this distribution, then reassess. Do not assume no firewall exists.",
        )]

    if failures and all("inactive" in item.lower() or "empty" in item.lower() for item in failures):
        status = CheckStatus.FAIL
        summary = "Detected firewall tooling reported an inactive or empty firewall configuration."
    else:
        status = CheckStatus.UNKNOWN
        summary = "Firewall state requires further verification."

    return [_result(
        "LINUX-FW-REVIEW", "Linux host firewall", status, summary,
        " | ".join(evidence + failures),
        "Confirm the active firewall framework, inspect rules and default policies, and validate them against the host's approved security requirements.",
    )]


def assess_host_firewall():
    """Dispatch a real read-only firewall assessment for the current host."""
    current = platform.system()
    if current == "Windows":
        return assess_windows_firewall()
    if current == "Linux":
        return assess_linux_firewall()
    return [AssessmentResult.create(
        check_id="HOST-FW-NA",
        control="Host firewall",
        platform=current,
        status=CheckStatus.NOT_APPLICABLE,
        summary="This operating system is not supported.",
        evidence=f"Detected operating system: {current}",
        recommendation="Run SecureState Lab on a supported Windows or Linux host.",
    )]
