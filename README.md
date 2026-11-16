# lucid-supplychain-remediation-demo

Synthetic demo (no Lucid code or data): Devin closes a security backlog **by root cause**, with
**evidence that every fix is safe**, across Java, TypeScript, Python and Go repos.

| Step | Command | What it shows |
|---|---|---|
| 1 Triage | `make triage` | 2,000 repos, 4 scanners, 5,601 Jira tickets → 3,898 unique findings → 40 root-cause campaigns, ranked by severity and SLA; waves by owner and tests |
| 2 Dependency campaign | `make campaign-dep` | Critical go-archive Zip Slip: version bump in 2 repos, exploit test fails before and passes after |
| 3 Code campaign | `make campaign-cwe22` | CWE-22 across 4 languages: owned repos, a repo with no tests (characterization tests first), a repo with no owner (routed to product security), and a false positive closed with justification |
| 4 Safety gate | `make naive-fix` | A plausible "fix" that breaks nested invoice paths is **BLOCKED** by the gate |
| Gate self-test | `make gate-selftest` | A suppression comment with an exploit test that only fails on an import error, and a no-tests repo fixed without characterization tests, are both **BLOCKED** |
| All | `make demo` | Steps 1–4 and the gate self-test in order |

Outputs: `reports/triage.md`, `reports/campaign_*.md`, one evidence pack per MR in `reports/evidence/`,
and drafted Jira transitions in `out/jira_updates_*.json`.

**Evidence pack per MR:** scanner finding gone and no new findings · no scanner suppressions added by a fix ·
existing tests pass · characterization tests where there were none · exploit test fails on an assertion (not a
build or import error) on the old code and passes on the fix · minimal diff, no public signatures removed or changed ·
owner from CODEOWNERS, else suggested committers, else product security · linked Jira tickets.
`tools/evidence.py` exits 0 when every MR passes, 2 when any MR is BLOCKED, and 1 on a gate error.

**Layout:** `fleet/` six sample repos at their vulnerable state · `libs/go-archive` v1.4.0 (vulnerable) and v1.4.1 ·
`campaigns/<id>/` playbook, campaign definition, and the fix + tests per repo · `tools/` generator, triage,
scanner, evidence gate · `prompts/` the Devin prompts · `AGENTS.md` campaign rules · `.gitlab/` illustrative CI job.

**Requirements:** Python 3.10+, Go 1.23+, JDK 17, Node 22.6+ (TypeScript runs with `--experimental-strip-types`). Offline.

**Simplifications:** the scanner is a small rule-based stand-in for GitLab SAST / Semgrep / dependency scanning;
advisories and package names are synthetic; MRs and Jira updates are simulated as files; SLAs are assumptions
in `config/sla.json`. Demo script: `docs/demo_script.md`.
