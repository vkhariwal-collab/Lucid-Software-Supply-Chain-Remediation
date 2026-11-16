"""Serves generated service-centre reports by name."""
import os


def read_report(base_dir, name):
    root = os.path.realpath(base_dir)
    path = os.path.realpath(os.path.join(root, name))
    if os.path.commonpath([root, path]) != root:
        raise ValueError("report path escapes store")
    with open(path, "rb") as f:
        return f.read()
