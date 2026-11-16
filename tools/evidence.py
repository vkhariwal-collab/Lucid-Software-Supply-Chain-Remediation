#!/usr/bin/env python3
"""Steps 2-4: apply a campaign's fixes and produce a safe-fix evidence pack per merge request.

For each repo: scan before/after, run existing tests, Devin-written characterization tests and the
exploit regression test on the vulnerable baseline (must fail) and on the fix (must pass),
check the diff is minimal and signatures are unchanged, resolve an owner, and draft the Jira updates.
Usage: evidence.py <campaign_id>"""
import csv
import difflib
import glob
import json
import os
import re
import shutil
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import scan  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENV = dict(os.environ, GOFLAGS="-mod=mod", GOPROXY="off", GOTOOLCHAIN="local", PYTHONDONTWRITEBYTECODE="1")
NODE = shutil.which("node") or os.path.expanduser("~/.local/node/bin/node")
SIG = re.compile(r"^\s*(func |public |export function|def )")


def group(name):
    n = name.lower()
    return "exploit" if "securityregression" in n.replace("_", "") else ("char" if "characterization" in n else "existing")


def run(cmd, cwd):
    p = subprocess.run(cmd, cwd=cwd, env=ENV, capture_output=True, text=True, timeout=600)
    return p.returncode == 0, (p.stdout + p.stderr)[-1500:]


def run_tests(lang, repo):
    """Returns {group: (passed|None, log)}; None means the repo has no tests in that group."""
    res = {}
    if lang == "python":
        files = sorted(glob.glob(os.path.join(repo, "tests", "test_*.py")))
        for g in ("existing", "char", "exploit"):
            mods = ["tests." + os.path.basename(f)[:-3] for f in files if group(os.path.basename(f)) == g]
            res[g] = run(["python3", "-m", "unittest", "-q"] + mods, repo) if mods else (None, "")
    elif lang == "ts":
        files = sorted(glob.glob(os.path.join(repo, "tests", "*.test.ts")))
        for g in ("existing", "char", "exploit"):
            fs = [os.path.relpath(f, repo) for f in files if group(os.path.basename(f)) == g]
            res[g] = run([NODE, "--experimental-strip-types", "--no-warnings", "--test"] + fs, repo) if fs else (None, "")
    elif lang == "go":
        funcs = []
        for f in glob.glob(os.path.join(repo, "*_test.go")):
            funcs += re.findall(r"^func (Test\w+)\(", open(f).read(), re.M)
        for g in ("existing", "char", "exploit"):
            fs = [f for f in funcs if group(f) == g]
            res[g] = run(["go", "test", "-count=1", "-run", "^(" + "|".join(fs) + ")$", "./..."], repo) if fs else (None, "")
    elif lang == "java":
        build = os.path.join(repo, "build")
        srcs = glob.glob(os.path.join(repo, "src", "**", "*.java"), recursive=True)
        ok, log = run(["javac", "-d", build] + srcs, repo)
        tests = sorted(glob.glob(os.path.join(repo, "src", "test", "java", "**", "*Test.java"), recursive=True))
        for g in ("existing", "char", "exploit"):
            cls = [os.path.relpath(t, os.path.join(repo, "src", "test", "java"))[:-5].replace(os.sep, ".")
                   for t in tests if group(os.path.basename(t)) == g]
            if not cls:
                res[g] = (None, "")
                continue
            if not ok:
                res[g] = (False, log)
                continue
            outs = [run(["java", "-cp", build, c], repo) for c in cls]
            res[g] = (all(o[0] for o in outs), "\n".join(o[1] for o in outs))
    return res


def copy_tree(src, dst):
    shutil.copytree(src, dst, dirs_exist_ok=True)


def diff(base, after, files):
    out, add, rem, sig = [], 0, 0, []
    for rel in files:
        a = open(os.path.join(base, rel)).read().splitlines() if os.path.exists(os.path.join(base, rel)) else []
        b = open(os.path.join(after, rel)).read().splitlines()
        d = list(difflib.unified_diff(a, b, "a/" + rel, "b/" + rel, lineterm="", n=1))
        out += d
        add += sum(1 for x in d if x.startswith("+") and not x.startswith("+++"))
        rem += sum(1 for x in d if x.startswith("-") and not x.startswith("---"))
        sa = {x.strip() for x in a if SIG.match(x)}
        sb = {x.strip() for x in b if SIG.match(x)}
        sig += sorted(sa ^ sb)
    return "\n".join(out), add, rem, sig


def owner(name, repo_dir, inventory):
    co = os.path.join(repo_dir, "CODEOWNERS")
    if os.path.exists(co):
        return "CODEOWNERS", open(co).read().split()[1:]
    inv = inventory.get(name, {})
    if inv.get("owner_source") == "committers":
        return "recent committers (suggested, confirm)", inv["owners"]
    return "none found: routed to product security", ["@product-security"]


def fmt(r):
    return "n/a (none)" if r[0] is None else ("pass" if r[0] else "FAIL")


def main(cid):
    cdir = os.path.join(ROOT, "campaigns", cid)
    camp = json.load(open(os.path.join(cdir, "campaign.json")))
    inventory = {r["name"]: r for r in json.load(open(os.path.join(ROOT, "backlog", "inventory.json")))}
    tickets = list(csv.DictReader(open(os.path.join(ROOT, "backlog", "jira_queue.csv"))))
    work = os.path.join(ROOT, ".work", cid)
    shutil.rmtree(work, ignore_errors=True)
    os.makedirs(work)
    os.symlink(os.path.join(ROOT, "libs"), os.path.join(work, "libs"))
    edir = os.path.join(ROOT, "reports", "evidence", cid)
    shutil.rmtree(edir, ignore_errors=True)
    os.makedirs(edir)
    summary, jira, all_ok = [], [], True

    for i, r in enumerate(camp["repos"], 1):
        name, lang = r["name"], r["lang"]
        base = os.path.join(ROOT, "fleet", name)
        pdir = os.path.join(cdir, "patches", name)
        before, after = os.path.join(work, "before", name), os.path.join(work, "after", name)
        copy_tree(base, before)
        copy_tree(base, after)
        fix_files = []
        if os.path.isdir(os.path.join(pdir, "fix")):
            copy_tree(os.path.join(pdir, "fix"), after)
            fix_files = sorted(os.path.relpath(f, os.path.join(pdir, "fix"))
                               for f in glob.glob(os.path.join(pdir, "fix", "**", "*"), recursive=True) if os.path.isfile(f))
        test_files = []
        if os.path.isdir(os.path.join(pdir, "tests")):
            copy_tree(os.path.join(pdir, "tests"), before)
            copy_tree(os.path.join(pdir, "tests"), after)
            test_files = sorted(os.path.relpath(f, os.path.join(pdir, "tests"))
                                for f in glob.glob(os.path.join(pdir, "tests", "**", "*"), recursive=True) if os.path.isfile(f))

        f_before = scan.scan(base)
        f_after = scan.scan(after)
        hit_b = [f for f in f_before if f["rule"] == camp["rule"]]
        hit_a = [f for f in f_after if f["rule"] == camp["rule"]]
        key = lambda f: (f["rule"], f["file"], f["snippet"])  # noqa: E731
        new = [f for f in f_after if key(f) not in {key(x) for x in f_before} and f["rule"] != camp["rule"]]
        t_before = run_tests(lang, before)
        t_after = run_tests(lang, after)
        patch, add, rem, sig = diff(base, after, fix_files)
        osrc, owners = owner(name, base, inventory)
        keys = [t["key"] for t in tickets if t["repo"] == name and t["rule"] == camp["rule"]]

        checks = [("Scanner: " + camp["rule"] + " findings", str(len(hit_b)), str(len(hit_a)), len(hit_b) > 0 and not hit_a),
                  ("New findings introduced (any rule)", "-", str(len(new)), not new)]
        if r["action"] == "fix":
            checks += [
                ("Existing tests", fmt(t_before["existing"]), fmt(t_after["existing"]),
                 t_before["existing"][0] is not False and t_after["existing"][0] is not False),
                ("Characterization tests (Devin-written, lock current behaviour)", fmt(t_before["char"]), fmt(t_after["char"]),
                 t_before["char"][0] is not False and t_after["char"][0] is not False),
                ("Exploit regression test (must FAIL before, pass after)", fmt(t_before["exploit"]), fmt(t_after["exploit"]),
                 t_before["exploit"][0] is False and t_after["exploit"][0] is True),
                ("Public signatures changed", "-", str(len(sig)), not sig)]
            ok = all(c[3] for c in checks)
            verdict = ("READY FOR OWNER REVIEW" if osrc == "CODEOWNERS" else ("READY: routed to product security" if osrc.startswith("none") else "READY: owner to confirm")) if ok else "BLOCKED"
            transition = "Fix in review" if ok else "Needs engineer"
        else:
            checks += [("Existing tests (unchanged code)", fmt(t_before["existing"]), fmt(t_after["existing"]),
                        t_after["existing"][0] is not False)]
            ok = all(c[3] for c in checks)
            verdict = "FALSE POSITIVE: needs security approval" if ok else "BLOCKED"
            transition = "Proposed false positive"
        all_ok &= ok
        mr = f"!{4100 + i}"
        L = [f"# Evidence pack: {name} · {camp['id']}", "",
             f"**Verdict: {verdict}**  ·  simulated GitLab MR {mr}  ·  language: {lang}", "",
             f"- Owner: {', '.join(owners)} ({osrc})",
             f"- Jira tickets closed by this MR: {len(keys)} ({', '.join(keys)}): duplicates from multiple scanners", "",
             "| Check | Before (vulnerable) | After (fix) | OK |", "|---|---|---|---|"]
        L += [f"| {c[0]} | {c[1]} | {c[2]} | {'yes' if c[3] else 'NO'} |" for c in checks]
        if r["action"] == "false_positive":
            L += ["", "**Justification:** " + r["justification"], "",
                  "The suppression is an inline, reviewable comment; it closes the finding only after product-security approval."]
        L += ["", f"## Change ({len(fix_files)} file(s), +{add} / -{rem} lines; tests added: {len(test_files)})", "",
              "```diff", patch or "(no code change)", "```", ""]
        if test_files:
            L += ["Tests added: " + ", ".join(f"`{t}`" for t in test_files), ""]
        if t_before.get("exploit", (None,))[0] is False:
            L += ["<details><summary>Exploit test output on the vulnerable code</summary>", "", "```",
                  t_before["exploit"][1].strip()[-900:], "```", "</details>", ""]
        open(os.path.join(edir, f"{name}.md"), "w").write("\n".join(L))
        summary.append((name, lang, verdict, len(hit_b), len(hit_a), fmt(t_before["exploit"]), fmt(t_after["exploit"]),
                        add + rem, ", ".join(owners), len(keys)))
        for k in keys:
            jira.append(dict(ticket=k, transition=transition, mr=mr, evidence=f"reports/evidence/{cid}/{name}.md",
                             labels=["devin-campaign", cid]))
        print(f"  {name:<20} {lang:<6} {verdict:<40} findings {len(hit_b)}->{len(hit_a)}  exploit {fmt(t_before['exploit'])}->{fmt(t_after['exploit'])}")

    S = [f"# Campaign: {camp['title']}", "", f"Severity: {camp['severity']} · repos in this demo slice: {len(summary)}", "",
         "| Repo | Lang | Verdict | Findings before → after | Exploit test before → after | Lines changed | Owner | Jira tickets |",
         "|---|---|---|---|---|---|---|---|"]
    S += [f"| {s[0]} | {s[1]} | {s[2]} | {s[3]} → {s[4]} | {s[5]} → {s[6]} | {s[7]} | {s[8]} | {s[9]} |" for s in summary]
    S += ["", f"Jira updates drafted: {len(jira)} (see `out/jira_updates_{cid}.json`). Evidence per MR in `reports/evidence/{cid}/`."]
    open(os.path.join(ROOT, "reports", f"campaign_{cid}.md"), "w").write("\n".join(S) + "\n")
    os.makedirs(os.path.join(ROOT, "out"), exist_ok=True)
    json.dump(jira, open(os.path.join(ROOT, "out", f"jira_updates_{cid}.json"), "w"), indent=1)
    print(f"  -> {len(summary)} MRs, {len(jira)} Jira tickets updated; all checks {'PASS' if all_ok else 'FAILED'}")
    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main(sys.argv[1])
