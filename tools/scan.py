#!/usr/bin/env python3
"""Minimal SAST + dependency scanner: a stand-in for GitLab SAST / Semgrep / dependency scanning.

Rules are deliberately simple and documented so the before/after evidence is easy to audit.
Usage: scan.py <repo_dir> [--sarif out.json]   (prints findings as JSON lines)
"""
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# CWE-22: a filesystem join whose result is not checked for containment in the same file.
CWE22 = {
    ".py": (re.compile(r"os\.path\.join\("), re.compile(r"os\.path\.commonpath\(")),
    ".go": (re.compile(r"filepath\.Join\("), re.compile(r"filepath\.IsLocal\(")),
    ".java": (re.compile(r"\.resolve\(\s*\w+\s*\)"), re.compile(r"\.startsWith\(\s*root\s*\)")),
    ".ts": (re.compile(r"path\.join\("), re.compile(r"\.startsWith\(\s*root")),
}
SUPPRESS = "cwe22-safe:"
SKIP_DIRS = {"tests", "test", "node_modules", "build", ".git"}


def ver(v):
    return tuple(int(x) for x in v.lstrip("v").split("."))


def sast(repo):
    out = []
    for dirpath, dirs, files in os.walk(repo):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fn in sorted(files):
            ext = os.path.splitext(fn)[1]
            if ext not in CWE22 or fn.endswith("_test.go"):
                continue
            p = os.path.join(dirpath, fn)
            src = open(p, encoding="utf-8").read()
            sink, guard = CWE22[ext]
            if guard.search(src):
                continue
            for i, line in enumerate(src.splitlines(), 1):
                if sink.search(line) and SUPPRESS not in line:
                    out.append({"rule": "CWE-22", "severity": "high", "file": os.path.relpath(p, repo),
                                "line": i, "snippet": line.strip(),
                                "message": "Path built from caller input without a containment check"})
    return out


def deps(repo):
    adv = json.load(open(os.path.join(ROOT, "advisories", "advisories.json")))
    gomod = os.path.join(repo, "go.mod")
    out = []
    if not os.path.exists(gomod):
        return out
    for i, line in enumerate(open(gomod), 1):
        m = re.match(r"\s*(?:require\s+)?([\w./-]+)\s+(v[\d.]+)\s*$", line)
        if not m:
            continue
        for a in adv:
            if a["ecosystem"] == "go" and a["package"] == m.group(1) and ver(m.group(2)) < ver(a["vulnerable_below"]):
                out.append({"rule": a["id"], "severity": a["severity"], "file": "go.mod", "line": i,
                            "snippet": line.strip(), "message": f'{a["summary"]}; fixed in {a["fixed"]}'})
    return out


def scan(repo):
    return sast(repo) + deps(repo)


def to_sarif(findings):
    return {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "demo-scan"}}, "results": [
        {"ruleId": f["rule"], "level": "error", "message": {"text": f["message"]},
         "locations": [{"physicalLocation": {"artifactLocation": {"uri": f["file"]},
                                             "region": {"startLine": f["line"]}}}]} for f in findings]}]}


if __name__ == "__main__":
    fs = scan(sys.argv[1])
    if "--sarif" in sys.argv:
        json.dump(to_sarif(fs), open(sys.argv[sys.argv.index("--sarif") + 1], "w"), indent=1)
    for f in fs:
        print(json.dumps(f))
