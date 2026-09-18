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
| Desktop interface | PySide6 (planned) |
| Windows assessment | PowerShell and native OS interfaces |
| Linux assessment | Native Linux utilities |
| Data storage | SQLite (planned) |
| Report formats | JSON, CSV and HTML |
| Experimental environment | VirtualBox virtual machines |
| Version control | Git and GitHub |

## 5. Current Development Status

The initial project foundation includes:

- Operating system and Python environment identification.
- Structured assessment result model.
- Security assessment status classification.
- Boolean security-control evaluation rules.
- Initial automated unit tests.

**Current test result:** 4 unit tests passing.

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