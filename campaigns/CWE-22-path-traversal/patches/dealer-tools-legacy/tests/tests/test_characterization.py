"""Characterization tests written by Devin before any fix: they lock today's behaviour."""
import os
import tempfile
import unittest

from tools.templates import load_template


class LoadTemplateBehaviour(unittest.TestCase):
    def setUp(self):
        self.base = tempfile.mkdtemp()
        os.makedirs(os.path.join(self.base, "ca"))
        with open(os.path.join(self.base, "ca", "delivery.txt"), "w", encoding="utf-8") as f:
            f.write("Delivered by {{dealer}} on {{date}}")

    def test_substitutes_dealer_only(self):
        self.assertEqual(load_template("ca/delivery.txt", self.base),
                         "Delivered by Lucid Studio on {{date}}")

    def test_missing_template_raises_file_not_found(self):
        with self.assertRaises(FileNotFoundError):
            load_template("tx/none.txt", self.base)

    def test_env_default_dir(self):
        import importlib
        from unittest import mock
        import tools.templates as t
        self.addCleanup(importlib.reload, t)
        with mock.patch.dict(os.environ, {"TEMPLATE_DIR": self.base}):
            importlib.reload(t)
            self.assertTrue(t.load_template("ca/delivery.txt").startswith("Delivered by Lucid Studio"))
