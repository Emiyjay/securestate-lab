"""Read-only cross-platform operating-system inventory collection.

The collector records evidence and collection errors separately. It does not
change configuration, install packages, or apply updates.
"""
from __future__ import annotations

import json
import os
import platform
try:
    import pwd
    import grp
except ImportError:  # Windows does not provide the Unix account modules.
    pwd = None
    grp = None
import shutil
import socket
import subprocess
from datetime import datetime, timezone
from typing import Any


def _run(command: list[str], timeout: int = 30) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command, capture_output=True, text=True, timeout=timeout, check=False
    )


def _run_powershell(script: str, timeout: int = 45) -> Any:
    executable = shutil.which("powershell.exe") or shutil.which("powershell")
    if not executable:
        raise RuntimeError("PowerShell executable was not found.")
    completed = _run(
        [executable, "-NoProfile", "-NonInteractive", "-Command", script],
        timeout=timeout,
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or "PowerShell command failed.")
    output = completed.stdout.strip()
    if not output:
        return []
    return json.loads(output)


def _as_list(value: Any) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _collect_section(inventory: dict, key: str, collector) -> None:
    try:
        inventory[key] = collector()
    except (OSError, RuntimeError, subprocess.SubprocessError, ValueError) as exc:
        inventory[key] = []
        inventory["collection_errors"].append(
            {"section": key, "error": str(exc)}
        )


def _windows_software() -> list[dict]:
    script = r"""
$ErrorActionPreference = 'Stop'
$paths = @(
 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
$items = foreach ($path in $paths) {
 Get-ItemProperty -Path $path -ErrorAction SilentlyContinue |
 Where-Object { $_.DisplayName } |
 Select-Object @{n='name';e={$_.DisplayName}},
               @{n='version';e={$_.DisplayVersion}},
               @{n='publisher';e={$_.Publisher}},
               @{n='install_date';e={$_.InstallDate}}
}
$items | Sort-Object name,version -Unique | ConvertTo-Json -Depth 3 -Compress
"""
    return _as_list(_run_powershell(script))


def _windows_updates() -> list[dict]:
    script = r"""
$ErrorActionPreference = 'Stop'
Get-HotFix | Select-Object @{n='id';e={$_.HotFixID}},
 @{n='description';e={$_.Description}},
 @{n='installed_on';e={if ($_.InstalledOn) {$_.InstalledOn.ToString('o')} else {$null}}} |
 ConvertTo-Json -Depth 3 -Compress
"""
    return _as_list(_run_powershell(script))


def _windows_users() -> list[dict]:
    script = r"""
$ErrorActionPreference = 'Stop'
Get-LocalUser | Select-Object @{n='name';e={$_.Name}},
 @{n='enabled';e={$_.Enabled}},
 @{n='sid';e={$_.SID.Value}},
 @{n='last_logon';e={if ($_.LastLogon) {$_.LastLogon.ToString('o')} else {$null}}} |
 ConvertTo-Json -Depth 3 -Compress
"""
    return _as_list(_run_powershell(script))


def _windows_services() -> list[dict]:
    script = r"""
$ErrorActionPreference = 'Stop'
Get-Service | Select-Object @{n='name';e={$_.Name}},
 @{n='display_name';e={$_.DisplayName}},
 @{n='status';e={$_.Status.ToString()}},
 @{n='start_type';e={$_.StartType.ToString()}} |
 ConvertTo-Json -Depth 3 -Compress
"""
    return _as_list(_run_powershell(script))


def _windows_admin_group_members() -> list[dict]:
    """Return members of the built-in local Administrators group (SID-based)."""
    script = r"""
$ErrorActionPreference = 'Stop'
$group = Get-LocalGroup -SID 'S-1-5-32-544'
Get-LocalGroupMember -Group $group.Name |
 Select-Object @{n='name';e={$_.Name}},
               @{n='sid';e={$_.SID.Value}},
               @{n='object_class';e={$_.ObjectClass}},
               @{n='principal_source';e={$_.PrincipalSource}} |
 ConvertTo-Json -Depth 3 -Compress
"""
    return _as_list(_run_powershell(script))


def _windows_ports() -> list[dict]:
    """Collect TCP listeners and enrich each endpoint with owning process metadata."""
    script = r"""
$ErrorActionPreference = 'Stop'
$rows = foreach ($connection in (Get-NetTCPConnection -State Listen)) {
    $process = Get-Process -Id $connection.OwningProcess -ErrorAction SilentlyContinue
    $processPath = $null
    if ($process) {
        try { $processPath = $process.Path } catch { $processPath = $null }
    }
    [pscustomobject]@{
        LocalAddress = $connection.LocalAddress
        LocalPort = $connection.LocalPort
        state = $connection.State.ToString()
        process_id = $connection.OwningProcess
        process_name = if ($process) {$process.ProcessName} else {$null}
        process_path = $processPath
    }
}
$rows | ConvertTo-Json -Depth 3 -Compress
"""
    return _as_list(_run_powershell(script))


def _linux_software() -> list[dict]:
    if shutil.which("dpkg-query"):
        result = _run([
            "dpkg-query", "-W",
            "-f=${Package}\t${Version}\t${Status}\n"
        ], timeout=60)
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or "dpkg-query failed.")
        packages = []
        for line in result.stdout.splitlines():
            fields = line.split("\t")
            if len(fields) >= 3 and fields[2] == "install ok installed":
                packages.append({"name": fields[0], "version": fields[1], "manager": "dpkg"})
        return packages

    if shutil.which("rpm"):
        result = _run(["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n"], timeout=60)
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or "rpm query failed.")
        return [
            {"name": p.split("\t", 1)[0], "version": p.split("\t", 1)[1], "manager": "rpm"}
            for p in result.stdout.splitlines() if "\t" in p
        ]
    raise RuntimeError("No supported package query tool (dpkg-query or rpm) was found.")


def _linux_users() -> list[dict]:
    users = []
    for entry in pwd.getpwall():
        try:
            group_names = [g.gr_name for g in grp.getgrall() if entry.pw_name in g.gr_mem]
            primary = grp.getgrgid(entry.pw_gid).gr_name
            users.append({
                "name": entry.pw_name,
                "uid": entry.pw_uid,
                "gid": entry.pw_gid,
                "primary_group": primary,
                "supplementary_groups": sorted(set(group_names)),
                "home": entry.pw_dir,
                "shell": entry.pw_shell,
                "account_class": "system" if entry.pw_uid < 1000 else "regular",
            })
        except KeyError:
            users.append({"name": entry.pw_name, "uid": entry.pw_uid, "gid": entry.pw_gid})
    return users


def _linux_services() -> list[dict]:
    if not shutil.which("systemctl"):
        raise RuntimeError("systemctl was not found.")
    result = _run(
        ["systemctl", "list-units", "--type=service", "--all", "--no-legend", "--no-pager"],
        timeout=45,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "systemctl query failed.")
    services = []
    for line in result.stdout.splitlines():
        fields = line.split(None, 4)
        if len(fields) >= 4:
            services.append({
                "unit": fields[0], "load": fields[1],
                "active": fields[2], "sub": fields[3],
                "description": fields[4] if len(fields) > 4 else "",
            })
    return services


def _linux_ports() -> list[dict]:
    if not shutil.which("ss"):
        raise RuntimeError("ss utility was not found.")
    result = _run(["ss", "-H", "-lntu"], timeout=20)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "ss query failed.")
    listeners = []
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) >= 5:
            listeners.append({
                "protocol": fields[0],
                "state": fields[1],
                "local_endpoint": fields[4],
            })
    return listeners


def _linux_updates() -> list[dict]:
    if shutil.which("apt"):
        result = _run(["apt", "list", "--upgradable"], timeout=60)
        # apt may return exit code 0 while reporting no candidates; stderr
        # contains a harmless "Listing..." message on common distributions.
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or "apt update inventory failed.")
        return [
            {"package": line.split("/", 1)[0], "candidate": line.split()[1] if len(line.split()) > 1 else ""}
            for line in result.stdout.splitlines()[1:] if "/" in line
        ]
    if shutil.which("dnf"):
        result = _run(["dnf", "check-update", "--quiet"], timeout=90)
        if result.returncode not in (0, 100):
            raise RuntimeError(result.stderr.strip() or "dnf check-update failed.")
        return [
            {"package": line.split()[0], "candidate": line.split()[1]}
            for line in result.stdout.splitlines() if len(line.split()) >= 2
        ]
    raise RuntimeError("No supported update inventory tool (apt or dnf) was found.")


def collect_system_inventory() -> dict:
    """Collect a read-only inventory from the current Windows or Linux host."""
    system = platform.system()
    inventory = {
        "schema_version": "1.0",
        "collected_at_utc": datetime.now(timezone.utc).isoformat(),
        "system": {
            "operating_system": system,
            "os_release": platform.release(),
            "os_version": platform.version(),
            "architecture": platform.machine(),
            "processor": platform.processor() or "Unknown",
            "hostname": socket.gethostname(),
            "current_user": os.environ.get("USERNAME") or os.environ.get("USER") or "Unknown",
            "python_version": platform.python_version(),
        },
        "software": [],
        "updates": [],
        "users": [],
        "administrators_group_members": [],
        "services": [],
        "listening_ports": [],
        "collection_errors": [],
    }

    if system == "Windows":
        collectors = {
            "software": _windows_software,
            "updates": _windows_updates,
            "users": _windows_users,
            "administrators_group_members": _windows_admin_group_members,
            "services": _windows_services,
            "listening_ports": _windows_ports,
        }
    elif system == "Linux":
        collectors = {
            "software": _linux_software,
            "updates": _linux_updates,
            "users": _linux_users,
            "administrators_group_members": lambda: [],
            "services": _linux_services,
            "listening_ports": _linux_ports,
        }
    else:
        inventory["collection_errors"].append({
            "section": "all",
            "error": f"Unsupported operating system: {system}",
        })
        return inventory

    for key, collector in collectors.items():
        _collect_section(inventory, key, collector)

    return inventory
