"""Structured Windows Advanced Audit Policy collection.

This module collects evidence only. It never changes audit policy.
"""
from __future__ import annotations

import csv
import io
import shutil
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable


@dataclass(frozen=True)
class AuditPolicyRow:
    machine_name: str
    policy_target: str
    subcategory: str
    subcategory_guid: str
    inclusion_setting: str
    exclusion_setting: str = ""


@dataclass(frozen=True)
class AuditPolicyCollection:
    success: bool
    rows: tuple[AuditPolicyRow, ...]
    collected_at_utc: str
    source: str
    error: str = ""
    permission_denied: bool = False


def _field(row: dict[str, str], phrase: str) -> str:
    for key, value in row.items():
        if key and phrase in key.strip().lower():
            return (value or "").strip()
    return ""


def parse_auditpol_csv(csv_text: str) -> tuple[AuditPolicyRow, ...]:
    """Parse auditpol /get /category:* /r output without discarding row-level data."""
    reader = csv.DictReader(io.StringIO(csv_text.lstrip("\ufeff")))
    if not reader.fieldnames:
        raise ValueError("auditpol CSV header is missing.")
    required = ("machine name", "policy target", "subcategory", "subcategory guid", "inclusion setting")
    normalized = {name.strip().lower() for name in reader.fieldnames if name}
    missing = [name for name in required if name not in normalized]
    if missing:
        raise ValueError("auditpol CSV is missing required columns: " + ", ".join(missing))

    parsed: list[AuditPolicyRow] = []
    for raw in reader:
        guid = _field(raw, "subcategory guid").strip().strip("{}").upper()
        name = _field(raw, "subcategory")
        if not name or not guid:
            continue
        parsed.append(AuditPolicyRow(
            machine_name=_field(raw, "machine name"),
            policy_target=_field(raw, "policy target"),
            subcategory=name,
            subcategory_guid="{" + guid + "}",
            inclusion_setting=_field(raw, "inclusion setting"),
            exclusion_setting=_field(raw, "exclusion setting"),
        ))
    if not parsed:
        raise ValueError("auditpol returned no valid subcategory rows.")
    return tuple(parsed)


def collect_windows_audit_policy(timeout: int = 20) -> AuditPolicyCollection:
    """Collect the local Windows audit policy using auditpol's CSV output."""
    timestamp = datetime.now(timezone.utc).isoformat()
    executable = shutil.which("auditpol.exe") or shutil.which("auditpol")
    if not executable:
        return AuditPolicyCollection(False, (), timestamp, "auditpol", "auditpol was not found.")
    try:
        result = subprocess.run(
            [executable, "/get", "/category:*", "/r"],
            capture_output=True, text=True, timeout=timeout, check=False,
        )
        if result.returncode != 0:
            message = (result.stderr or result.stdout).strip() or "auditpol query failed."
            denied = "0x00000522" in message.lower() or "1314" in message
            if denied:
                message = (
                    "Windows denied audit-policy inspection (0x00000522 / 1314). "
                    "Run SecureState Lab from an elevated PowerShell session. "
                    "This is an evidence-collection limitation, not a policy failure."
                )
            return AuditPolicyCollection(False, (), timestamp, "auditpol", message, denied)
        rows = parse_auditpol_csv(result.stdout)
        return AuditPolicyCollection(True, rows, timestamp, "auditpol", "")
    except (OSError, ValueError, csv.Error, subprocess.SubprocessError) as exc:
        return AuditPolicyCollection(False, (), timestamp, "auditpol", str(exc))


def rows_as_dicts(rows: Iterable[AuditPolicyRow]) -> list[dict[str, str]]:
    """Return JSON-friendly row dictionaries for reports and persistence."""
    return [
        {
            "machine_name": row.machine_name,
            "policy_target": row.policy_target,
            "subcategory": row.subcategory,
            "subcategory_guid": row.subcategory_guid,
            "inclusion_setting": row.inclusion_setting,
            "exclusion_setting": row.exclusion_setting,
        }
        for row in rows
    ]
