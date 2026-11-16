Run the CWE-22 campaign on fleet/<repo> following campaigns/CWE-22-path-traversal/playbook.md and AGENTS.md.
Write the exploit test first and show it failing. If the repo has no tests, write characterization tests first.
Make the smallest fix, run tools/evidence.py CWE-22-path-traversal, and open one MR with the evidence pack.
If any check fails, stop and explain; do not weaken tests.
