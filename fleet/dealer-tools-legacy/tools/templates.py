"""Loads delivery-document templates. Last meaningful change: 2023."""
import os

TEMPLATE_DIR = os.environ.get("TEMPLATE_DIR", "/srv/templates")


def load_template(name, base=None):
    base = base or TEMPLATE_DIR
    path = os.path.join(base, name)
    with open(path, encoding="utf-8") as f:
        text = f.read()
    return text.replace("{{dealer}}", "Lucid Studio")
