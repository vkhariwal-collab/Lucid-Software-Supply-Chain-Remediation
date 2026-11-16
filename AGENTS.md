# Instructions for Devin (and humans)

## Campaign rules
- One campaign = one root cause and one fix pattern (see `campaigns/*/playbook.md`). Never mix fixes in one MR.
- One MR per repo. Keep the diff minimal; do not change public signatures, formatting or unrelated code.
- Every MR ships with an evidence pack from `tools/evidence.py`. No evidence, no MR.

## Safe-fix evidence (all required)
1. The scanner finding for the campaign rule is gone, and no new findings appear.
2. Existing tests pass before and after.
3. If the repo has no tests: write characterization tests first that pass on the unchanged code.
4. An exploit regression test that FAILS on the vulnerable code and passes on the fix.
5. If any check fails, the MR is BLOCKED and the ticket goes to "Needs engineer". Do not weaken tests.

## False positives
- Close only with a written justification and an inline `cwe22-safe:` style comment; product security approves.

## Ownership
- Assign reviewers from CODEOWNERS. Else suggest recent committers. Else route to `@product-security`.

## Data
- Synthetic code and data only. Never paste secrets or production data into tickets or MRs.
