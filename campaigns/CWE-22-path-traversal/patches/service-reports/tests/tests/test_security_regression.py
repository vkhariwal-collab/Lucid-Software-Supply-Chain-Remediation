"""CWE-22: report names from the request must not escape base_dir."""
import os
import tempfile
import unittest

from reports.files import read_report


class SecurityRegressionTest(unittest.TestCase):
    def test_rejects_traversal(self):
        root = tempfile.mkdtemp()
        base = os.path.join(root, "store")
        os.makedirs(base)
        secret = os.path.join(root, "secret.txt")
        with open(secret, "w") as f:
            f.write("smtp-password")
        for attack in ("../secret.txt", "costa-mesa/../../secret.txt", secret):
            with self.subTest(attack=attack), self.assertRaises(ValueError):
                read_report(base, attack)
