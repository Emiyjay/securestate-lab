#!/usr/bin/env bash
set -Eeuo pipefail

echo "=== SECURESTATE LAB FIREWALL VALIDATION ==="

if [[ ! -f requirements.txt || ! -d src/securestate ]]; then
    echo "ERROR: Run from project root."
    exit 1
fi

if [[ -f .venv/Scripts/python.exe ]]; then
    PYTHON=".venv/Scripts/python.exe"
elif [[ -f .venv/bin/python ]]; then
    PYTHON=".venv/bin/python"
else
    echo "ERROR: Virtual environment missing."
    exit 1
fi

export PYTHONPATH="$PWD/src"

echo
echo "[1/5] Checking firewall parser."

"$PYTHON" - <<'PY'
from securestate.assessments.windows_firewall import parse_enabled_value

assert parse_enabled_value(True) is True
assert parse_enabled_value(False) is False
assert parse_enabled_value(1) is True
assert parse_enabled_value(0) is False
assert parse_enabled_value("true") is True
assert parse_enabled_value("false") is False
assert parse_enabled_value(None) is None
assert parse_enabled_value("invalid") is None

print("Firewall parser: PASS")
PY

echo
echo "[2/5] Compiling Python."

"$PYTHON" -m compileall -q src tests

echo "Compilation: PASS"

echo
echo "[3/5] Running automated tests."

"$PYTHON" -m unittest discover -s tests -v

echo
echo "[4/5] Assessing firewall profiles."

"$PYTHON" - <<'PY'
import platform
from securestate.assessments.windows_firewall import assess_windows_firewall

results = assess_windows_firewall()

for result in results:
    print(f"{result.control}: {result.status.value}")
    print(f"Evidence: {result.evidence}")

if platform.system() == "Windows":
    expected = {
        "Domain Firewall",
        "Private Firewall",
        "Public Firewall",
    }
    actual = {result.control for result in results}

    assert actual == expected, (
        f"Expected {expected}, got {actual}"
    )

    assert all(
        result.status.value != "UNKNOWN"
        for result in results
    ), "An UNKNOWN result remains."

    print("Three firewall profiles: PASS")
PY

echo
echo "[5/5] Validating desktop GUI."

QT_QPA_PLATFORM=offscreen "$PYTHON" - <<'PY'
import sys
from PySide6.QtWidgets import QApplication
from securestate.ui.main_window import MainWindow

app = QApplication.instance() or QApplication(sys.argv)
window = MainWindow()

assert window.pages.count() == 7
assert len(window.navigation_buttons) == 7

window.show_page(2)

assert window.pages.currentIndex() == 2
assert window.page_title.text() == "Security Assessment"

print("GUI initialisation: PASS")
print("Seven pages: PASS")
print("Seven navigation buttons: PASS")
print("Security Assessment navigation: PASS")

window.close()
PY

echo
echo "=== VALIDATION COMPLETED ==="

if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    git diff --check
    git status --short
fi