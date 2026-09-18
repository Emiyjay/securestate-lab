import json
import platform
import shutil
import subprocess

from securestate.models import AssessmentResult, CheckStatus
from securestate.rules import evaluate_boolean_control


POWERSHELL_SCRIPT = r"""
$ErrorActionPreference = 'Stop'

Get-NetFirewallProfile |
    Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction |
    ConvertTo-Json -Compress
"""


def unknown_result(profile, evidence):
    return AssessmentResult.create(
        check_id=f"WIN-FW-{profile.upper()}",
        control=f"{profile.title()} Firewall",
        platform="Windows",
        status=CheckStatus.UNKNOWN,
        summary="The firewall state could not be determined.",
        evidence=evidence,
        recommendation=(
            "Inspect the firewall profile using "
            "Get-NetFirewallProfile."
        ),
    )


def normalise_profiles(data):
    if isinstance(data, dict):
        return [data]

    if isinstance(data, list):
        return data

    raise ValueError("Unexpected firewall assessment data.")


def parse_enabled_value(value):
    """
    Convert PowerShell firewall Enabled values into Python booleans.

    PowerShell JSON may represent Boolean values as 1 or 0.
    Unrecognised values remain UNKNOWN (None).
    """
    if isinstance(value, bool):
        return value

    if isinstance(value, int):
        if value == 1:
            return True
        if value == 0:
            return False
        return None

    if isinstance(value, str):
        normalised = value.strip().lower()

        if normalised in {"true", "1"}:
            return True
        if normalised in {"false", "0"}:
            return False

    return None


def assess_windows_firewall():
    """
    Read-only assessment of Windows firewall profiles.
    No firewall settings are modified.
    """

    if platform.system() != "Windows":
        return [
            AssessmentResult.create(
                check_id="WIN-FW-NA",
                control="Windows Defender Firewall",
                platform=platform.system(),
                status=CheckStatus.NOT_APPLICABLE,
                summary="This assessment applies only to Windows.",
                evidence="Current operating system is not Windows.",
                recommendation=(
                    "Use the appropriate firewall assessment "
                    "adapter for this operating system."
                ),
            )
        ]

    powershell = (
        shutil.which("powershell.exe")
        or shutil.which("powershell")
    )

    if powershell is None:
        return [
            unknown_result(
                "GENERAL",
                "PowerShell executable was not found.",
            )
        ]

    try:
        completed = subprocess.run(
            [
                powershell,
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                POWERSHELL_SCRIPT,
            ],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )

        if completed.returncode != 0:
            error = completed.stderr.strip() or (
                "PowerShell returned a non-zero exit code."
            )
            return [unknown_result("GENERAL", error)]

        output = completed.stdout.strip()

        if not output:
            return [
                unknown_result(
                    "GENERAL",
                    "PowerShell returned no firewall information.",
                )
            ]

        profiles = normalise_profiles(json.loads(output))

    except subprocess.TimeoutExpired:
        return [
            unknown_result(
                "GENERAL",
                "Firewall inspection exceeded 20 seconds.",
            )
        ]

    except (json.JSONDecodeError, ValueError) as error:
        return [
            unknown_result(
                "GENERAL",
                f"Could not interpret PowerShell output: {error}",
            )
        ]

    except OSError as error:
        return [
            unknown_result(
                "GENERAL",
                f"Could not execute PowerShell: {error}",
            )
        ]

    expected_profiles = {"domain", "private", "public"}
    discovered = {}

    for profile in profiles:
        if not isinstance(profile, dict):
            continue

        name = str(profile.get("Name", "")).lower()

        if name in expected_profiles:
            discovered[name] = profile

    results = []

    for name in ("domain", "private", "public"):
        profile = discovered.get(name)

        if profile is None:
            results.append(
                unknown_result(
                    name,
                    f"{name.title()} profile was not returned.",
                )
            )
            continue

        enabled = profile.get("Enabled")
        observed = parse_enabled_value(enabled)

        evidence = (
            f"Profile: {name.title()}; "
            f"Enabled: {enabled}; "
            f"Default inbound action: "
            f"{profile.get('DefaultInboundAction', 'Unknown')}; "
            f"Default outbound action: "
            f"{profile.get('DefaultOutboundAction', 'Unknown')}"
        )

        results.append(
            evaluate_boolean_control(
                check_id=f"WIN-FW-{name.upper()}",
                control=f"{name.title()} Firewall",
                platform="Windows",
                observed_value=observed,
                expected_value=True,
                evidence=evidence,
                recommendation=(
                    "Keep this firewall profile enabled and "
                    "verify its rules against the approved "
                    "security policy."
                ),
            )
        )

    return results
