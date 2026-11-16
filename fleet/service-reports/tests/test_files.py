import os
import tempfile
import unittest

from reports.files import read_report


class ReadReportTest(unittest.TestCase):
    def setUp(self):
        self.base = tempfile.mkdtemp()
        os.makedirs(os.path.join(self.base, "costa-mesa"))
        with open(os.path.join(self.base, "costa-mesa", "weekly.csv"), "wb") as f:
            f.write(b"ro,hours\n")

    def test_reads_nested_report(self):
        self.assertEqual(read_report(self.base, "costa-mesa/weekly.csv"), b"ro,hours\n")

    def test_missing_report_raises(self):
        with self.assertRaises(FileNotFoundError):
            read_report(self.base, "none.csv")
