# 10-minute run of show (supply-chain remediation)

| Time | Show | Line to land |
|---|---|---|
| 0:00 | `reports/triage.md` funnel | "5,601 tickets are really 40 problems. 10 of them cover most of your critical and high findings." |
| 2:00 | Campaign table, waves A/B/C | "Owned repos with tests go first; no-test repos get characterization tests; orphans go to your team with a suggested owner." |
| 3:00 | `make campaign-dep` | "One critical advisory, one version bump, an exploit test that fails before and passes after." |
| 5:00 | `make campaign-cwe22`, open the Java and dealer-tools packs | "Same fix pattern in four languages. The repo with no tests got tests before it got a fix." |
| 7:00 | fleet-exports pack | "Not every finding needs code. This one is a false positive, with a justification your team approves." |
| 8:00 | `make naive-fix` | "This is what 'lower finding count' gets you. The gate blocks it because nested paths broke." |
| 9:00 | `out/jira_updates_*.json` | "Tickets move with the MR and its evidence; your SLA report updates itself." |

Ask: one real campaign (their choice of root cause) across 20–30 repos, with the CISO's team setting the evidence bar.
