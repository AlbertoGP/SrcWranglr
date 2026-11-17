---
name: aavr-static-analysis
description: Select, configure, and run applicable deterministic static-analysis tools against a C or C++ repository. Use after a baseline build exists to run compiler diagnostics, clang-tidy, Semgrep, CodeQL, compiler analyzers, or Coccinelle while preserving raw output and normalizing warnings as unconfirmed candidates.
---

# AAVR Static Analysis

Use the lightest applicable tools first. Avoid running every analyzer without a reason.

## Select tools

Prefer this order when supported:

1. existing project lint or security jobs
2. compiler diagnostics
3. `clang-tidy` using a valid compilation database
4. Run flawfinder on code base. Investigate the output
5. Semgrep for structural patterns and targeted rules; load `aavr-semgrep-database` when a private corpus is configured
6. CodeQL for data flow and repository-scale queries
7. Clang Static Analyzer for path-sensitive checks
8. Coccinelle for C-specific semantic variants

Document why each tool is applicable or skipped.

## Preserve reproducibility

For each run, create `.aavr/runs/<run-id>/` containing:

- `command.txt`
- `environment.json`
- `stdout.log`
- `stderr.log`
- native machine-readable result when available
- `status.json`

Do not hide non-zero exits. Distinguish tool failure from findings.

## Normalize candidates

Write one JSON object per line to `.aavr/findings/candidates.jsonl`:

```json
{
  "id": "AAVR-CAND-0001",
  "tool": "",
  "rule": "",
  "category": "",
  "file": "",
  "line": 0,
  "message": "",
  "raw_artifact": "",
  "initial_confidence": "low|medium|high",
  "validation_status": "unreviewed",
  "duplicate_of": null
}
```

Deduplicate only when results describe the same root cause and code path. Preserve provenance from all tools.

## Analysis discipline

- Do not call a warning a vulnerability.
- Check whether the file and target are built.
- Check whether data is attacker-controlled.
- Check surrounding validation and error paths.
- Prefer targeted queries derived from the attack-surface map.
- Do not enable broad autofixes.

## Handoff

Load `aavr-finding-triage` for the strongest candidates. Include the raw artifact paths and relevant source locations.
