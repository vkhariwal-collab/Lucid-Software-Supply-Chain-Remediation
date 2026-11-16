# Playbook: CWE-22 path traversal in file-serving helpers

**Trigger:** scanner rule CWE-22 on a join of a base directory and a caller-supplied name.

**Procedure (per repo, one Devin session each)**
1. Read the flagged function and its callers. Decide: real (caller input reaches the join) or false positive (constant or validated upstream). For a false positive, write the justification and add an inline `cwe22-safe:` comment; stop.
2. If the repo has no tests for the function, write characterization tests that pass on the unchanged code.
3. Write the exploit test first: `../secret`, `a/../../secret`, and an absolute path must be rejected. Confirm it fails.
4. Apply the language pattern; keep nested sub-paths working and keep error types for missing files:
   - Go: `if !filepath.IsLocal(name) { return ErrInvalidPath }`
   - Java: `root.resolve(name).normalize()` then `startsWith(root)`
   - Python: `os.path.realpath` then `os.path.commonpath([root, path]) == root`
   - TypeScript: `path.resolve(root, name)` then `startsWith(root + path.sep)`
5. Run `tools/evidence.py`; open the MR only if the verdict is READY.

**Do not:** strip directory components (`basename`): it breaks nested paths (see `CWE-22-naive-fix-example`).
**Reviewer note:** the Go, Java and TypeScript patterns are lexical, so symlinks inside the store are followed;
the Python pattern (`realpath`) resolves them and rejects links that point outside. Flag if the store is user-writable.
