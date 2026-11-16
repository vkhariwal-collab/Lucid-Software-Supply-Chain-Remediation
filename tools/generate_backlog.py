#!/usr/bin/env python3
"""Generates a synthetic security backlog shaped like the one Lucid described:
~2,000 GitLab repos (Java, TypeScript, Python, Go), several scanners, one Jira ticket per raw finding.
Deterministic (seed 7). No Lucid data."""
import csv
import datetime as dt
import json
import os
import random

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "backlog")
rnd = random.Random(7)
AS_OF = dt.date(2026, 11, 16)
LANGS = ["java"] * 30 + ["ts"] * 30 + ["python"] * 25 + ["go"] * 15
EXT = {"java": "java", "ts": "ts", "python": "py", "go": "go"}
DOMAINS = ["ota", "vehicle", "telemetry", "retail", "dms", "service", "warranty", "mfg", "supply", "fin",
           "hr", "data", "charging", "fleet", "dealer", "identity", "portal", "mobile-api", "plm", "quality"]
NOUNS = ["api", "svc", "worker", "gateway", "sync", "exporter", "ingest", "jobs", "bff", "tools", "adapter", "ui"]

SAMPLES = [  # the six real repos under fleet/
    dict(name="svc-warranty-docs", lang="java", owner_source="codeowners", owners=["@warranty-platform/backend"], tests="good"),
    dict(name="ota-artifact-api", lang="go", owner_source="codeowners", owners=["@ota-platform/cloud"], tests="good"),
    dict(name="retail-portal-bff", lang="ts", owner_source="codeowners", owners=["@retail-systems/web"], tests="good"),
    dict(name="service-reports", lang="python", owner_source="committers", owners=["a.rao", "m.chen"], tests="thin"),
    dict(name="dealer-tools-legacy", lang="python", owner_source="none", owners=[], tests="none"),
    dict(name="fleet-exports", lang="go", owner_source="codeowners", owners=["@fleet-data/exports"], tests="good"),
]
SAMPLE_FINDINGS = {  # (repo, root cause) -> (file, line) matching tools/scan.py on fleet/
    ("svc-warranty-docs", "CWE-22"): ("src/main/java/com/lucid/warranty/AttachmentStore.java", 16),
    ("ota-artifact-api", "CWE-22"): ("artifacts.go", 13),
    ("retail-portal-bff", "CWE-22"): ("src/invoices.ts", 6),
    ("service-reports", "CWE-22"): ("reports/files.py", 6),
    ("dealer-tools-legacy", "CWE-22"): ("tools/templates.py", 9),
    ("fleet-exports", "CWE-22"): ("exports.go", 14),
    ("ota-artifact-api", "DEMO-ADV-2026-0007"): ("go.mod", 5),
    ("fleet-exports", "DEMO-ADV-2026-0007"): ("go.mod", 5),
}

# id, kind, title, severity, languages, repos affected, fix pattern
CATALOG = [
    ("CWE-22", "code", "Path traversal in file-serving helpers", "high", ["java", "go", "python", "ts"], 143, "containment check + exploit test"),
    ("CWE-89", "code", "SQL built by string concatenation", "critical", ["java", "python", "go"], 61, "parameterised queries"),
    ("CWE-79", "code", "Unescaped HTML in portal views", "high", ["ts"], 118, "framework escaping"),
    ("CWE-611", "code", "XML parser allows external entities", "high", ["java"], 74, "secure parser factory"),
    ("CWE-502", "code", "Unsafe deserialisation", "critical", ["java", "python"], 39, "allow-listed types"),
    ("CWE-798", "code", "Hard-coded credentials", "high", ["java", "ts", "python", "go"], 212, "move to secrets manager + rotate"),
    ("CWE-327", "code", "Weak hash (MD5/SHA-1) for integrity", "medium", ["java", "ts", "python", "go"], 260, "SHA-256"),
    ("CWE-918", "code", "Server-side request forgery", "high", ["go", "ts", "python"], 47, "egress allow-list"),
    ("CWE-1333", "code", "Regex denial of service", "medium", ["ts", "java"], 95, "bounded regex"),
    ("CWE-532", "code", "VIN or PII written to logs", "high", ["java", "ts", "python", "go"], 88, "structured redaction"),
    ("CWE-295", "code", "TLS certificate verification disabled", "high", ["java", "ts", "python", "go"], 56, "remove override"),
    ("DEMO-ADV-2026-0007", "dependency", "go-archive < 1.4.1 (Zip Slip)", "critical", ["go"], 41, "bump to 1.4.1"),
    ("DEMO-ADV-2026-0012", "dependency", "demo-xml (Java) < 2.9 (XXE)", "critical", ["java"], 190, "bump + parser config"),
    ("DEMO-ADV-2026-0015", "dependency", "demo-http (npm) < 4.2 (prototype pollution)", "high", ["ts"], 240, "bump"),
    ("DEMO-ADV-2026-0021", "dependency", "demo-yaml (PyPI) < 6.1 (unsafe load)", "high", ["python"], 130, "bump + safe_load"),
    ("DEMO-ADV-2026-0030", "dependency", "demo-jwt < 3.4 (algorithm confusion)", "critical", ["java", "ts"], 66, "bump + pin algorithms"),
    ("DEMO-ADV-2026-0033", "container", "Base image demo-linux 3.18 (OpenSSL)", "high", ["java", "ts", "python", "go"], 310, "rebase image"),
    ("DEMO-ADV-2026-0040", "dependency", "demo-logging (Java) < 2.17 (lookup RCE)", "critical", ["java"], 28, "bump"),
]
for i in range(22):  # long tail
    CATALOG.append((f"TAIL-{i+1:02d}", rnd.choice(["code", "dependency"]), f"Long-tail finding type {i+1}",
                    rnd.choice(["medium", "low", "medium", "high"]), rnd.sample(["java", "ts", "python", "go"], 2),
                    rnd.randint(1, 15), "case by case"))


def main():
    os.makedirs(OUT, exist_ok=True)
    repos, seen = [], set()
    for s in SAMPLES:
        repos.append(dict(s, last_commit="2023-04-11" if s["tests"] == "none" else "2026-10-30", sample=True))
        seen.add(s["name"])
    while len(repos) < 2000:
        name = f"{rnd.choice(DOMAINS)}-{rnd.choice(NOUNS)}-{rnd.randint(1, 999):03d}"
        if name in seen:
            continue
        seen.add(name)
        u = rnd.random()
        src = "codeowners" if u < 0.78 else ("committers" if u < 0.92 else "none")
        owners = [f"@{name.split('-')[0]}-team"] if src == "codeowners" else (
            [f"eng{rnd.randint(1, 400):03d}" for _ in range(2)] if src == "committers" else [])
        t = rnd.random()
        repos.append(dict(name=name, lang=rnd.choice(LANGS), owner_source=src, owners=owners,
                          tests="good" if t < 0.55 else ("thin" if t < 0.85 else "none"),
                          last_commit=str(AS_OF - dt.timedelta(days=rnd.randint(1, 1200))), sample=False))
    by_lang = {}
    for r in repos:
        if not r["sample"]:
            by_lang.setdefault(r["lang"], []).append(r)

    raw = []
    for rid, kind, title, sev, langs, n, fix in CATALOG:
        pool = [r for l in langs for r in by_lang[l]]
        chosen = [r["name"] for r in rnd.sample(pool, min(n, len(pool)))]
        samples = [repo for (repo, rc) in SAMPLE_FINDINGS if rc == rid]
        chosen = samples + chosen[: max(0, n - len(samples))]
        for repo in chosen:
            lang = next(r["lang"] for r in repos if r["name"] == repo)
            first = AS_OF - dt.timedelta(days=rnd.randint(3, 150))
            if (repo, rid) in SAMPLE_FINDINGS:
                locs = [SAMPLE_FINDINGS[(repo, rid)]]
            elif kind == "code":
                locs = [(f"src/{rnd.choice(['handlers', 'store', 'util', 'jobs'])}/m{rnd.randint(1, 60)}.{EXT[lang]}",
                         rnd.randint(5, 400)) for _ in range(rnd.choice([1, 1, 2, 3, 4]))]
            elif kind == "container":
                locs = [("Dockerfile", 1)]
            else:
                locs = [({"go": "go.mod", "java": "pom.xml", "ts": "package-lock.json", "python": "requirements.txt"}[lang], rnd.randint(3, 40))]
            for f, line in locs:
                scanners = ["sast-a"] if kind == "code" else (["container-scan"] if kind == "container" else ["dependency-scan"])
                if kind == "code" and rnd.random() < 0.45:
                    scanners.append("sast-b")
                if kind != "code" and rnd.random() < 0.4:
                    scanners.append("container-scan" if kind == "dependency" else "dependency-scan")
                if (repo, rid) in SAMPLE_FINDINGS:
                    scanners = ["sast-a", "sast-b"] if kind == "code" else ["dependency-scan", "container-scan"]
                for sc in scanners:
                    raw.append(dict(scanner=sc, repo=repo, rule=rid, severity=sev, file=f, line=line,
                                    first_seen=str(first + dt.timedelta(days=rnd.randint(0, 2)))))
    rnd.shuffle(raw)
    with open(os.path.join(OUT, "jira_queue.csv"), "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["key", "status", "priority", "created", "scanner", "repo", "rule", "file", "line", "summary"])
        for i, f in enumerate(raw):
            f["jira"] = f"PSEC-{10001 + i}"
            w.writerow([f["jira"], rnd.choice(["To Do", "To Do", "In Triage"]), f["severity"].title(), f["first_seen"],
                        f["scanner"], f["repo"], f["rule"], f["file"], f["line"], f'{f["scanner"]}: {f["rule"]} in {f["repo"]}/{f["file"]}'])
    json.dump(repos, open(os.path.join(OUT, "inventory.json"), "w"), indent=0)
    json.dump([dict(id=c[0], kind=c[1], title=c[2], severity=c[3], langs=c[4], fix=c[6]) for c in CATALOG],
              open(os.path.join(OUT, "root_causes.json"), "w"), indent=1)
    for sc in ["sast-a", "sast-b", "dependency-scan", "container-scan"]:
        json.dump([f for f in raw if f["scanner"] == sc], open(os.path.join(OUT, f"scanner_{sc}.json"), "w"))
    print(f"backlog: {len(repos)} repos, {len(raw)} raw scanner findings = {len(raw)} Jira tickets")


if __name__ == "__main__":
    main()
