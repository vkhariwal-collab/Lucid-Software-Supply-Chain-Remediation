PY := python3
export PATH := $(HOME)/.local/node/bin:$(PATH)
.PHONY: help backlog triage scan campaign-cwe22 campaign-dep naive-fix gate-selftest demo clean

# evidence.py exits 2 when an MR is BLOCKED and 1 when the gate itself errors; only 2 counts as "blocked".
expect_blocked = $(PY) tools/evidence.py $(1); rc=$$?; if [ $$rc -eq 2 ]; then printf '%s\n' "  gate blocked $(1), as intended"; \
	else echo "  $(1): expected BLOCKED (exit 2), got exit $$rc"; exit 1; fi

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
	@$(call expect_blocked,CWE-22-naive-fix-example)

gate-selftest: triage  ## the gate must BLOCK a suppressed non-fix and a no-tests repo without characterization tests
	@$(call expect_blocked,CWE-22-gate-bypass-example)
	@$(call expect_blocked,CWE-22-no-tests-example)

demo: triage campaign-dep campaign-cwe22 naive-fix gate-selftest ## everything, in demo order
	@printf "\nAll demo checks passed. Reports in reports/, Jira drafts in out/.\n"

clean:
	rm -rf .work reports/* out backlog/*
