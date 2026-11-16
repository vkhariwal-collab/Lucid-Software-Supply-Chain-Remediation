"""CWE-22: template names must not escape the template dir."""
import os
import tempfile
import unittest

from tools.templates import load_template


class SecurityRegressionTest(unittest.TestCase):
    def test_rejects_traversal(self):
        root = tempfile.mkdtemp()
        base = os.path.join(root, "templates")
        os.makedirs(os.path.join(base, "ca"))
        secret = os.path.join(root, "secret.txt")
        with open(secret, "w", encoding="utf-8") as f:
            f.write("dms-api-token")
        for attack in ("../secret.txt", "ca/../../secret.txt", secret):
            with self.subTest(attack=attack), self.assertRaises(ValueError):
                load_template(attack, base)
