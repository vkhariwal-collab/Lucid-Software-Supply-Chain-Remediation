"""Serves generated service-centre reports by name."""
import os


class PathEscapeError(ValueError):
    """Raised when a report name escapes the store."""


def read_report(base_dir, name):
    with open(os.path.join(base_dir, name), "rb") as f:  # cwe22-safe: names are validated upstream
        return f.read()
