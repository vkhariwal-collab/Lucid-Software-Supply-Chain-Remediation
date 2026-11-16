Read backlog/jira_queue.csv and backlog/inventory.json. Deduplicate findings reported by more than one
scanner, group them by root cause, and rank campaigns by severity and time past SLA (config/sla.json).
For each campaign, split repos into waves: A (owner + tests), B (owner, no tests), C (no owner).
Write reports/triage.md. Do not change any repo.
