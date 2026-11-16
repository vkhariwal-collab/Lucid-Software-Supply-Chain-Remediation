PY := python3
export PATH := $(HOME)/.local/node/bin:$(PATH)
.PHONY: help backlog triage scan campaign-cwe22 campaign-dep naive-fix demo clean

help:            ## list targets
	@grep -E '^[a-z0-9-]+:.*##' $(MAKEFILE_LIST) | sed 's/:.*##/\t/'

backlog:         ## generate the synthetic backlog: 2,000 repos, 4 scanners, Jira queue
	$(PY) tools/generate_backlog.py

triage: backlog  ## Step 1: Jira queue -> deduped findings -> ranked root-cause campaigns
	$(PY) tools/triage.py

scan:            ## scan the six sample repos as they are today
	@for r in fleet/*; do echo "== $$r"; $(PY) tools/scan.py $$r; done

campaign-dep: triage   ## Step 2: critical dependency campaign (go-archive Zip Slip), 2 repos
	$(PY) tools/evidence.py DEMO-ADV-2026-0007-go-archive

campaign-cwe22: triage ## Step 3: code campaign (CWE-22) across Java, Go, TS, Python; incl. no-tests, no-owner, false positive
	$(PY) tools/evidence.py CWE-22-path-traversal

naive-fix: triage      ## Step 4: a plausible-looking fix that breaks behaviour; the gate must BLOCK it
	@! $(PY) tools/evidence.py CWE-22-naive-fix-example && echo "\nGate blocked the naive fix, as intended."

demo: triage campaign-dep campaign-cwe22 naive-fix ## everything, in demo order
	@echo "\nAll demo checks passed. Reports in reports/, Jira drafts in out/."

clean:
	rm -rf .work reports/* out backlog/*
