# SecureState Lab

**Cross-Platform Operating System Security Assessment and Remediation Validation Platform**

## 1. Overview

SecureState Lab is a Python-based research prototype designed to assess selected operating system security controls and evaluate remediation outcomes in controlled Windows and Linux virtual machine environments.

The project aims to connect security assessment, evidence collection, controlled remediation, and independent verification within one experimental platform.

## 2. Research Aim

To design and experimentally evaluate a cross-platform operating system security assessment and remediation validation platform using controlled Windows and Linux virtual machine environments.

## 3. Core Objectives

- Assess selected operating system security controls.
- Identify selected known vulnerability conditions using authoritative vulnerability and vendor advisory information.
- Collect and classify security assessment evidence.
- Support controlled and approved remediation.
- Independently verify remediation outcomes.
- Generate assessment reports documenting before-and-after security states.

## 4. Technology Stack

| Component | Technology |
|---|---|
| Programming language | Python |
| Desktop interface | PySide6 |
| Windows assessment | PowerShell and native OS interfaces |
| Linux assessment | Native Linux utilities |
| Data storage | SQLite (planned) |
| Report formats | JSON, CSV and HTML |
| Experimental environment | VirtualBox virtual machines |
| Version control | Git and GitHub |

## 5. Current Development Status

Implemented research prototype capabilities:

- Operating system and Python environment identification.
- Read-only Windows and Linux system inventory collectors.
- Windows local Administrators group membership and TCP listener process attribution.
- Linux sudo/wheel membership and TCP/UDP listener process attribution where permissions allow.
- Structured assessment results and evidence-backed security configuration checks.
- Independent Windows Defender Firewall profile assessment.
- OSV package/version vulnerability queries with CISA KEV enrichment for supported package ecosystems.
- Conservative Windows installed-product screening against exact normalised vendor/product entries in the CISA KEV catalogue.
- NVD CPE dictionary enrichment for exact vendor/product component matches from KEV candidates, followed by installed-version CPE queries for CVE applicability candidates.
- PySide6 desktop interface with separate discovery, configuration, package vulnerability and Windows product screening workflows.

The vulnerability intelligence module currently queries package records that can be mapped to an OSV ecosystem. OSV matches are classified as `VALIDATION_REQUIRED`, not confirmed host vulnerabilities. CISA KEV membership indicates known exploitation of a CVE, not proof that the installed host is affected. Distribution backports and vendor-specific package revisions require additional validation.

Windows installed-software records and RPM inventory are not yet fully mapped to OSV ecosystems. The Windows product screening workflow uses exact normalised publisher/vendor and product-name matches against CISA KEV records; it is catalogue screening only and does not establish installed-version applicability. Every match requires vendor version/build validation. This conservative screening can miss products whose registry display names differ from catalogue naming. The NVD CPE/CVE workflow assesses all inventoried Windows products with a product name, publisher and installed version, independently of exact CISA KEV product-name matches. It reports unsupported and duplicate inventory records. CPE identity and CVE applicability remain candidate-level results requiring manual review. CPE vendor/product components are compared exactly after conservative normalisation; the installed version is then queried through the NVD CVE API with vulnerable-CPE filtering. Returned CVE configuration trees and version boundaries are retained as evidence, but the prototype does not yet independently evaluate every nested configuration expression or confirm vendor-specific edition/build applicability. Broader vendor advisory correlation, persistent finding history, controlled remediation and independent before/after verification remain future implementation stages.

Automated tests must be run in the target environment; mocked Linux tests do not replace a real Linux VM experiment.

## 6. Project Structure

```text
securestate-lab/
├── src/
│   ├── main.py
│   └── securestate/
│       ├── __init__.py
│       ├── models.py
│       ├── platform_info.py
│       └── rules.py
├── tests/
│   └── test_rules.py
├── reports/
├── docs/
├── .gitignore
└── README.md
```

## 7. Running the Prototype

Clone the repository:

```bash
git clone https://github.com/Emiyjay/securestate-lab.git
cd securestate-lab
```

Run the initial environment identification module:

```bash
python src/main.py
```

Run the automated tests in PowerShell:

```powershell
$env:PYTHONPATH = "src"
python -m unittest discover -s tests -v
```

## 8. Research Scope and Safety

The prototype is intended for authorised, controlled testing in isolated virtual machine environments.

It does not claim to detect every operating system vulnerability or replace professional vulnerability management and penetration-testing tools.

Remediation operations will require appropriate approval and validation.

## 9. Development Approach

Development follows an incremental process:

1. Establish the software foundation.
2. Implement and test the assessment engine.
3. Develop platform-specific assessment modules.
4. Integrate vulnerability intelligence.
5. Implement controlled remediation and verification.
6. Develop the desktop interface.
7. Conduct experimental evaluation and document findings.

## 10. Project Status

**Status:** Early development — research prototype.

This repository is actively being developed as part of an academic cybersecurity research project.