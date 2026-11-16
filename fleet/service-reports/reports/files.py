"""Serves generated service-centre reports by name."""
import os


def read_report(base_dir, name):
    with open(os.path.join(base_dir, name), "rb") as f:
        return f.read()
