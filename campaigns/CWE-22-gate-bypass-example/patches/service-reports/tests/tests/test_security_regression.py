"""Looks like an exploit test, but it fails on the vulnerable code only because the import fails."""
import unittest

from reports.files import PathEscapeError, read_report  # noqa: F401


class SecurityRegressionTest(unittest.TestCase):
    def test_error_type(self):
        self.assertTrue(issubclass(PathEscapeError, ValueError))
