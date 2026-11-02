"""Read-only security logging checks for the local Windows or Linux host."""
from __future__ import annotations

import json
import platform
import shutil
import subprocess

from securestate.models import AssessmentResult, CheckStatus


def _run(command: list[str], timeout: int = 15) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)


def assess_security_logging(os_name: str | None = None) -> list[AssessmentResult]:
    """Check logging service availability and whether a recent system log is readable.

    A running service is not proof that audit policy is sufficient; the result
    is deliberately limited to logging availability and basic log access.
    """
    os_name = os_name or platform.system()
    status = CheckStatus.UNKNOWN
    summary = "Logging availability could not be established."
    evidence = ""
    recommendation = "Review audit policy against an approved security baseline and verify required event categories."

    try:
        if os_name == "Windows":
            executable = shutil.which("powershell.exe") or shutil.which("powershell")
            if not executable:
                raise RuntimeError("PowerShell was not found.")
            script = (
                "$ErrorActionPreference='Stop'; "
                "$svc=Get-Service -Name EventLog; "
                "$event=Get-WinEvent -LogName System -MaxEvents 1 -ErrorAction Stop; "
                "[pscustomobject]@{service=$svc.Status.ToString(); "
                "latest_event_id=$event.Id; latest_event_time=$event.TimeCreated.ToString('o')} "
                "| ConvertTo-Json -Compress"
            )
            completed = _run([executable, "-NoProfile", "-NonInteractive", "-Command", script])
            if completed.returncode != 0:
                raise RuntimeError(completed.stderr.strip() or "Windows event log query failed.")
            data = json.loads(completed.stdout.strip())
            running = data.get("service", "").lower() == "running"
            if running:
                status = CheckStatus.PASS
                summary = "Windows Event Log service is running and the System log is readable."
            else:
                status = CheckStatus.FAIL
                summary = "Windows Event Log service is not running."
            evidence = (
                f"EventLog service: {data.get('service')}; "
                f"latest readable System event ID: {data.get('latest_event_id')}; "
                f"event time: {data.get('latest_event_time')}."
            )
            recommendation = (
                "Keep Windows Event Log running; separately validate Advanced Audit Policy settings "
                "and Security log generation against the organisation's approved baseline."
            )
        elif os_name == "Linux":
            if not shutil.which("systemctl"):
                raise RuntimeError("systemctl was not found; service state cannot be checked.")
            states = {}
            for service in ("systemd-journald", "rsyslog"):
                result = _run(["systemctl", "is-active", service])
                states[service] = result.stdout.strip() or "unknown"
            journal_readable = False
            journal_evidence = "journalctl unavailable"
            if shutil.which("journalctl"):
                result = _run(["journalctl", "--no-pager", "-n", "1", "-o", "short-iso"])
                journal_readable = result.returncode == 0
                journal_evidence = (
                    "journal query succeeded" if journal_readable
                    else (result.stderr.strip() or "journal query failed")
                )
            active = [name for name, state in states.items() if state == "active"]
            if active and journal_readable:
                status = CheckStatus.PASS
                summary = "A Linux logging service is active and the system journal is readable."
            elif not active and all(state in {"inactive", "failed"} for state in states.values()):
                status = CheckStatus.FAIL
                summary = "Neither systemd-journald nor rsyslog is active."
            else:
                status = CheckStatus.UNKNOWN
                summary = "Linux logging state is incomplete or could not be verified."
            evidence = (
                f"systemd-journald: {states['systemd-journald']}; "
                f"rsyslog: {states['rsyslog']}; {journal_evidence}."
            )
            recommendation = (
                "Maintain an active logging service and verify retention, permissions, remote forwarding "
                "where required, and security-event coverage against an approved baseline."
            )
        else:
            status = CheckStatus.NOT_APPLICABLE
            summary = f"Security logging adapter does not support {os_name}."
            evidence = f"Detected platform: {os_name}."
    except (OSError, RuntimeError, subprocess.SubprocessError, ValueError, KeyError) as exc:
        evidence = f"Logging inspection error: {exc}"
        summary = "Logging availability could not be verified; no secure state is assumed."

    return [AssessmentResult.create(
        check_id="LOG-AVAIL-001",
        control="Security logging availability",
        platform=os_name,
        status=status,
        summary=summary,
        evidence=evidence,
        recommendation=recommendation,
    )]
