
#!/usr/bin/env bash
set -Eeuo pipefail

echo "=================================================="
echo " SECURESTATE LAB - FIREWALL ASSESSMENT UPDATE"
echo "=================================================="

# --------------------------------------------------
# 1. PROJECT VALIDATION
# --------------------------------------------------

if [[ ! -f "requirements.txt" || ! -d "src/securestate" ]]; then
    echo "ERROR: Run this script from the project root."
    exit 1
fi

ENGINE="src/securestate/assessments/windows_firewall.py"
TEST_FILE="tests/test_windows_firewall.py"

if [[ ! -f "$ENGINE" ]]; then
    echo "ERROR: Firewall assessment engine not found."
    exit 1
fi

if [[ ! -f "src/securestate/ui/main_window.py" ]]; then
    echo "ERROR: Main GUI file not found."
    exit 1
fi

# --------------------------------------------------
# 2. PROJECT PYTHON ENVIRONMENT
# --------------------------------------------------

if [[ -f ".venv/Scripts/python.exe" ]]; then
    PYTHON=".venv/Scripts/python.exe"
elif [[ -f ".venv/bin/python" ]]; then
    PYTHON=".venv/bin/python"
else
    echo "ERROR: Python virtual environment not found."
    exit 1
fi

export PYTHONPATH="$PWD/src"

echo
echo "[1/7] Project environment validated."

# --------------------------------------------------
# 3. BACKUP EXISTING FIREWALL ENGINE
# --------------------------------------------------

if [[ ! -f "${ENGINE}.backup" ]]; then
    cp "$ENGINE" "${ENGINE}.backup"
    echo "Created firewall engine backup."
else
    echo "Existing firewall engine backup preserved."
fi

# --------------------------------------------------
# 4. APPLY FIREWALL PARSER FIX
# --------------------------------------------------

"$PYTHON" - <<'PY'
from pathlib import Path

path = Path("src/securestate/assessments/windows_firewall.py")
source = path.read_text(encoding="utf-8")

parser_exists = "def parse_enabled_value(value):" in source

if not parser_exists:
    original_function = '''def assess_windows_firewall():
    """
    Read-only assessment of Windows firewall profiles.
    No firewall settings are modified.
    """'''

    updated_function = '''def parse_enabled_value(value):
    """
    Interpret Boolean, integer and string values from PowerShell JSON.

    PowerShell may serialise Enabled as 1 or 0.
    Unrecognised values return None.
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
    """'''

    if original_function not in source:
        raise SystemExit(
            "ERROR: Original assessment function not found. "
            "Engine was not modified."
        )

    source = source.replace(
        original_function,
        updated_function,
        1
    )

    print("Added firewall value parser.")

else:
    print("Firewall value parser already exists.")

old_parser = '''        enabled = profile.get("Enabled")

        if isinstance(enabled, bool):
            observed = enabled
        elif isinstance(enabled, str):
            value = enabled.strip().lower()
            observed = (
                True if value == "true"
                else False if value == "false"
                else None
            )
        else:
            observed = None'''

new_parser = '''        enabled = profile.get("Enabled")
        observed = parse_enabled_value(enabled)'''

if old_parser in source:
    source = source.replace(old_parser, new_parser, 1)
    print("Updated firewall Enabled-value interpretation.")

elif new_parser in source:
    print("Firewall Enabled-value interpretation already updated.")

else:
    raise SystemExit(
        "ERROR: Could not safely identify the Enabled parsing block. "
        "No further changes were made."
    )

path.write_text(source, encoding="utf-8")
print("Firewall engine update completed.")
PY

# --------------------------------------------------
# 5. CREATE REGRESSION TESTS
# --------------------------------------------------

echo
echo "[2/7] Creating firewall regression tests."

mkdir -p tests

cat > "$TEST_FILE" <<'PY'
import unittest

from securestate.assessments.windows_firewall import (
    parse_enabled_value,
)


class TestParseEnabledValue(unittest.TestCase):

    def test_boolean_true(self):
        self.assertIs(parse_enabled_value(True), True)

    def test_boolean_false(self):
        self.assertIs(parse_enabled_value(False), False)

    def test_integer_one(self):
        self.assertIs(parse_enabled_value(1), True)

    def test_integer_zero(self):
        self.assertIs(parse_enabled_value(0), False)

    def test_string_true(self):
        self.assertIs(parse_enabled_value("True"), True)

    def test_string_false(self):
        self.assertIs(parse_enabled_value("False"), False)

    def test_string_one(self):
        self.assertIs(parse_enabled_value("1"), True)

    def test_string_zero(self):
        self.assertIs(parse_enabled_value("0"), False)

    def test_whitespace(self):
        self.assertIs(parse_enabled_value(" true "), True)

    def test_missing_value(self):
        self.assertIsNone(parse_enabled_value(None))

    def test_unrecognised_string(self):
        self.assertIsNone(parse_enabled_value("enabled"))

    def test_unrecognised_integer(self):
        self.assertIsNone(parse_enabled_value(2))


if __name__ == "__main__":
    unittest.main()
PY

echo "Regression tests created."

# --------------------------------------------------
# 6. COMPILE AND RUN AUTOMATED TESTS
# --------------------------------------------------

echo
echo "[3/7] Compiling Python files."

"$PYTHON" -m compileall -q src tests

echo "Python compilation successful."

echo
echo "[4/7] Running automated tests."

"$PYTHON" -m unittest discover -s tests -v

# --------------------------------------------------
# 7. TEST FIREWALL ASSESSMENT
# --------------------------------------------------

echo
echo "[5/7] Running Windows Firewall assessment."

"$PYTHON" - <<'PY'
import platform

from securestate.assessments.windows_firewall import (
    assess_windows_firewall,
)

results = assess_windows_firewall()

for result in results:
    print(f"\n{result.control}: {result.status.value}")
    print(f"Summary: {result.summary}")
    print(f"Evidence: {result.evidence}")

if platform.system() == "Windows":
    expected = {"Domain", "Private", "Public"}
    actual = {result.control.removesuffix(" Firewall") for result in results}

    if actual != expected:
        raise SystemExit(
            f"ERROR: Expected {expected}, received {actual}"
        )

    statuses = [result.status.value for result in results]

    if len(results) != 3:
        raise SystemExit("ERROR: Expected exactly three firewall profiles.")

    if any(status == "UNKNOWN" for status in statuses):
        raise SystemExit(
            "WARNING: At least one firewall profile remains UNKNOWN."
        )

    print("\nAll three firewall profiles were assessed.")

else:
    print("\nNon-Windows operating system detected.")
    print("Windows firewall assessment should be NOT_APPLICABLE.")
PY

# --------------------------------------------------
# 8. VALIDATE GUI AND NAVIGATION
# --------------------------------------------------

echo
echo "[6/7] Validating GUI and navigation."

QT_QPA_PLATFORM=offscreen "$PYTHON" - <<'PY'
import sys

from PySide6.QtWidgets import QApplication

from securestate.ui.main_window import MainWindow

app = QApplication.instance() or QApplication(sys.argv)

window = MainWindow()

# The actual GUI uses self.pages.
assert window.pages.count() == 7, (
    f"Expected 7 pages, found {window.pages.count()}"
)

assert len(window.navigation_buttons) == 7, (
    f"Expected 7 navigation buttons, "
    f"found {len(window.navigation_buttons)}"
)

# Test navigation to Security Assessment.
window.show_page(2)

assert window.pages.currentIndex() == 2
assert window.page_title.text() == "Security Assessment"

print("GUI initialisation: PASS")
print("Page count: 7")
print("Navigation button count: 7")
print("Security Assessment navigation: PASS")

window.close()
PY

# --------------------------------------------------
# 9. GIT VALIDATION
# --------------------------------------------------

echo
echo "[7/7] Checking changes."

if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    git diff --check
    git status --short
else
    echo "Git repository not detected; skipping Git checks."
fi

echo
echo "=================================================="
echo " FIREWALL UPDATE AND VALIDATION COMPLETED"
echo "=================================================="
echo
echo "Next: inspect the results before proceeding."
