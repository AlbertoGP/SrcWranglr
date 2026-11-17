---
name: aavr-harness-generation
description: Design, implement, build, and smoke-test a focused fuzz harness for a previously selected C or C++ target. Use only after target selection establishes the API, attacker-relevant input model, initialization, invariants, reset strategy, and engine. Store generated work outside production source and verify target reachability.
---

# AAVR Harness Generation

Generate a harness for the selected boundary, not for the easiest callable function.

## Study the target

Read:

- implementation and declaration
- representative callers
- initialization and teardown paths
- error-handling and ownership contracts
- required object state and invariants
- existing tests and sample inputs

## Design input mapping

Choose the simplest encoding that reaches meaningful behavior:

- raw byte buffer for naturally byte-oriented parsers
- bounded field extraction for structured APIs
- operation sequence for state machines
- file or process driver when in-process use is unrealistic

Avoid consuming most input bytes as arbitrary control values when that prevents deep parsing. Avoid rejecting nearly every input.

## Implement safely

- Place source beneath `.aavr/harnesses/<target>/`.
- Do not modify production source unless explicitly required and approved.
- Initialize once outside the iteration when safe.
- Reset mutable state every iteration.
- Release iteration-owned resources.
- Suppress only expected target logging, never sanitizer diagnostics.
- Add time, size, recursion, and allocation bounds when required for harness stability.

## Build and smoke test

1. Compile with the selected engine and sanitizers.
2. Run at least one known-valid seed when available.
3. Run a short mutation smoke test.
4. Confirm the intended target and nontrivial branches are reached.
5. Check for per-iteration leaks, stale state, and harness-only crashes.

## Output

Create:

```text
.aavr/harnesses/<target>/
├── harness source
├── build.sh or exact-build-command.txt
├── README.md
├── seeds/
├── dictionary.txt          # when useful
├── smoke-test.log
└── coverage-summary.json
```

`README.md` must document the input model, invariants, initialization, reset strategy, build command, execution command, and known limitations.

## Gate

Do not begin a longer campaign until the harness compiles, reaches target logic, and survives a bounded smoke test.
