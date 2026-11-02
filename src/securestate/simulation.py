"""Deterministic offline scenarios for SecureState Lab demonstrations.
These fixtures are teaching/demo data, not observations from a real host.
"""

SCENARIOS = {
    "Windows": [
        {"id": "W01", "control": "Firewall configuration", "baseline": "Windows firewall profile is disabled.", "expected": "Firewall profile enabled and policy reviewed.", "status": "FAIL"},
        {"id": "W02", "control": "Update and patch status", "baseline": "A security update is pending installation.", "expected": "Security update installed and installation state verified.", "status": "FAIL"},
        {"id": "W03", "control": "Least-privilege configuration", "baseline": "An unapproved account has local administrator privileges.", "expected": "Only approved accounts retain administrator privileges.", "status": "FAIL"},
        {"id": "W04", "control": "Security logging", "baseline": "Required security audit logging is disabled.", "expected": "Required audit policy enabled and event generation verified.", "status": "FAIL"},
    ],
    "Linux": [
        {"id": "L01", "control": "Firewall configuration", "baseline": "Host firewall service is inactive.", "expected": "Approved firewall service active with reviewed rules.", "status": "FAIL"},
        {"id": "L02", "control": "Update and patch status", "baseline": "A security update is pending installation.", "expected": "Security update installed and package state verified.", "status": "FAIL"},
        {"id": "L03", "control": "Least-privilege configuration", "baseline": "An unapproved account belongs to a privileged group.", "expected": "Only approved accounts belong to sudo/wheel groups.", "status": "FAIL"},
        {"id": "L04", "control": "Security logging", "baseline": "Required security logging service is inactive.", "expected": "Logging service active and event collection verified.", "status": "FAIL"},
    ],
}

def get_scenarios(platform):
    """Return copies so callers cannot mutate shared fixtures."""
    return [dict(item) for item in SCENARIOS.get(platform, [])]


def assess_scenario(platform, scenario_id, remediated=False):
    """Return a deterministic result explicitly marked as simulated."""
    scenario = next((item for item in get_scenarios(platform) if item["id"] == scenario_id), None)
    if scenario is None:
        raise ValueError(f"Unknown {platform} simulation scenario: {scenario_id}")
    return {
        "mode": "SIMULATION ONLY",
        "platform": platform,
        "scenario_id": scenario["id"],
        "control": scenario["control"],
        "status": "PASS" if remediated else scenario["status"],
        "evidence": scenario["expected"] if remediated else scenario["baseline"],
        "is_simulated": True,
        "remediated": bool(remediated),
    }
