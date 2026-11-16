# Playbook: upgrade go-archive to v1.4.1 (DEMO-ADV-2026-0007, Zip Slip)

1. Bump `example.com/go-archive` to v1.4.1 in `go.mod` (here also the local `replace` path). No other change.
2. Add an exploit test: a bundle with a `../escaped.txt` entry must not write outside the destination.
3. Run existing tests and the exploit test before and after; `tools/evidence.py` must report READY.
4. v1.4.1 returns `ErrUnsafePath` for bad entries. Check callers that ignore errors; note them in the MR.
