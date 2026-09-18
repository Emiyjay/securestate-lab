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

    def test_whitespace_is_accepted(self):
        self.assertIs(parse_enabled_value(" true "), True)

    def test_missing_value_is_unknown(self):
        self.assertIsNone(parse_enabled_value(None))

    def test_unrecognised_string_is_unknown(self):
        self.assertIsNone(parse_enabled_value("enabled"))

    def test_unrecognised_integer_is_unknown(self):
        self.assertIsNone(parse_enabled_value(2))


if __name__ == "__main__":
    unittest.main()
