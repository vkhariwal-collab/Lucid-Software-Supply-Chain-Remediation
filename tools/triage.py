#!/usr/bin/env python3
"""Step 1: turn the Jira queue into a short list of remediation campaigns.
raw scanner findings -> cross-scanner dedupe -> group by root cause -> rank by severity and SLA -> waves by owner/tests."""
import collections
import csv
import datetime as dt
import json
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
B = os.path.join(ROOT, "backlog")
SEV_W = {"critical": 10, "high": 4, "medium": 1, "low": 0.2}


def main():
    sla = json.load(open(os.path.join(ROOT, "config", "sla.json")))
    as_of = dt.date.fromisoformat(sla["as_of"])
    repos = {r["name"]: r for r in json.load(open(os.path.join(B, "inventory.json")))}
    rc = {c["id"]: c for c in json.load(open(os.path.join(B, "root_causes.json")))}
    tickets = list(csv.DictReader(open(os.path.join(B, "jira_queue.csv"))))

    uniq = {}
    for t in tickets:
        fp = (t["repo"], t["rule"], t["file"], t["line"])
        u = uniq.setdefault(fp, dict(repo=t["repo"], rule=t["rule"], sev=t["priority"].lower(),
                                     first=t["created"], tickets=[], scanners=set()))
        u["tickets"].append(t["key"]); u["scanners"].add(t["scanner"]); u["first"] = min(u["first"], t["created"])

    camps = collections.defaultdict(lambda: dict(findings=0, tickets=0, repos=set(), overdue=0, waves=collections.Counter()))
    for u in uniq.values():
        c = camps[u["rule"]]
        c["findings"] += 1; c["tickets"] += len(u["tickets"]); c["repos"].add(u["repo"])
        if (as_of - dt.date.fromisoformat(u["first"])).days > sla[u["sev"]]:
            c["overdue"] += 1
    for rid, c in camps.items():
        for name in c["repos"]:
            r = repos[name]
            wave = "C" if r["owner_source"] == "none" else ("B" if r["tests"] == "none" else "A")
            c["waves"][wave] += 1
        c["score"] = SEV_W[rc[rid]["severity"]] * c["findings"] + 2 * SEV_W[rc[rid]["severity"]] * c["overdue"]
    ranked = sorted(camps.items(), key=lambda kv: -kv[1]["score"])

    crit_high = sum(1 for u in uniq.values() if u["sev"] in ("critical", "high"))
    top10 = sum(c["findings"] for rid, c in ranked[:10] if rc[rid]["severity"] in ("critical", "high"))
    dup = len(tickets) - len(uniq)
    no_owner = sum(1 for r in repos.values() if r["owner_source"] == "none")
    no_tests = sum(1 for r in repos.values() if r["tests"] == "none")

    os.makedirs(os.path.join(ROOT, "reports"), exist_ok=True)
    L = ["# Triage: from Jira queue to remediation campaigns", "",
         "Synthetic backlog (no Lucid data). SLAs in `config/sla.json` are assumptions: "
         + ", ".join(f"{k} {sla[k]} d" for k in ("critical", "high", "medium", "low")) + f"; as of {sla['as_of']}.", "",
         "| Stage | Count |", "|---|---|",
         f"| Repositories | {len(repos):,} ({no_owner} with no owner, {no_tests} with no tests) |",
         f"| Jira tickets (one per raw scanner finding) | {len(tickets):,} |",
         f"| Unique findings after cross-scanner dedupe | {len(uniq):,} ({dup:,} duplicate tickets) |",
         f"| Root causes = campaigns | {len(camps)} |",
         f"| Critical + high unique findings | {crit_high:,} |",
         f"| Share of critical + high covered by the top 10 campaigns | {100 * top10 / crit_high:.0f}% |", "",
         "## Ranked campaigns (top 12)", "",
         "Waves: **A** owner + tests → MR with evidence; **B** owner, no tests → characterization tests first; "
         "**C** no owner → product-security queue with owner suggestion.", "",
         "| # | Campaign | Severity | Repos | Unique findings | Jira tickets | Past SLA | Fix pattern | Waves A/B/C |",
         "|---|---|---|---|---|---|---|---|---|"]
    out = []
    for i, (rid, c) in enumerate(ranked, 1):
        r = rc[rid]
        row = dict(rank=i, id=rid, title=r["title"], severity=r["severity"], repos=len(c["repos"]), findings=c["findings"],
                   tickets=c["tickets"], overdue=c["overdue"], fix=r["fix"], waves=dict(c["waves"]))
        out.append(row)
        if i <= 12:
            L.append(f"| {i} | `{rid}` {r['title']} | {r['severity']} | {row['repos']} | {c['findings']} | {c['tickets']} | "
                     f"{c['overdue']} | {r['fix']} | {c['waves']['A']}/{c['waves']['B']}/{c['waves']['C']} |")
    demo = [rid for rid in ("DEMO-ADV-2026-0007", "CWE-22")]
    L += ["", "## Demo slice", "",
          "This repo remediates two campaigns end to end on six real sample repos under `fleet/`:"]
    for rid in demo:
        row = next(o for o in out if o["id"] == rid)
        L.append(f"- `{rid}` (rank {row['rank']}): {row['repos']} repos in the backlog, {row['tickets']} Jira tickets.")
    open(os.path.join(ROOT, "reports", "triage.md"), "w").write("\n".join(L) + "\n")
    json.dump(out, open(os.path.join(B, "campaigns.json"), "w"), indent=1)
    print(f"tickets {len(tickets):,} -> unique {len(uniq):,} -> campaigns {len(camps)}; "
          f"top-10 campaigns cover {100 * top10 / crit_high:.0f}% of critical+high")
    for o in out[:8]:
        print(f"  #{o['rank']:<2} {o['id']:<20} {o['severity']:<8} repos {o['repos']:>3}  tickets {o['tickets']:>4}  past SLA {o['overdue']:>3}")


if __name__ == "__main__":
    main()
