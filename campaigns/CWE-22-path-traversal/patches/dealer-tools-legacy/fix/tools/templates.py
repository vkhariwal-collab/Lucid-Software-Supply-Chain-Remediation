"""Loads delivery-document templates. Last meaningful change: 2023."""
import os

TEMPLATE_DIR = os.environ.get("TEMPLATE_DIR", "/srv/templates")


def load_template(name, base=None):
    base = os.path.realpath(base or TEMPLATE_DIR)
    path = os.path.realpath(os.path.join(base, name))
    if os.path.commonpath([base, path]) != base:
        raise ValueError("template path escapes template dir")
    with open(path, encoding="utf-8") as f:
        text = f.read()
    return text.replace("{{dealer}}", "Lucid Studio")
