---
name: aavr-crash-triage
description: Reproduce, minimize, debug, and classify crashes, hangs, sanitizer reports, assertion failures, or anomalous terminations found during testing or fuzzing. Use when a concrete failure artifact exists. Identify the root cause rather than only the crash location, determine attacker control, and preserve exact reproduction evidence.
---

# AAVR Crash Triage

Treat the original artifact as evidence. Preserve it before minimization.

## Reproduce

Record:

- target revision and dirty state
- exact binary and build configuration
- sanitizer and environment settings
- original input hash and path
- exact invocation
- exit status, signal, timeout, and resource limits

Reproduce multiple times. Note nondeterminism.

## Minimize

Use engine-native minimization when appropriate, then verify that the minimized input preserves the same root cause. Keep both original and minimized artifacts.

## Debug

- Obtain a symbolized sanitizer trace or debugger backtrace.
- Inspect the faulting values and relevant object state.
- Trace backward to the first violated invariant.
- Distinguish root cause from detection site.
- Determine which bytes, fields, operations, or scheduling conditions are attacker-controlled.
- Check whether the failure is in the harness, dependency, or target.

## Classify

Use a precise category such as:

- out-of-bounds read or write
- use-after-free
- double or invalid free
- integer overflow or truncation
- uninitialized use
- data race
- assertion or deliberate abort
- resource exhaustion
- infinite loop or pathological complexity
- non-security defect
- harness defect

## Output

Create `.aavr/crashes/<crash-id>/`:

```text
original-input
minimized-input
reproduce.sh
build-info.json
sanitizer.log
backtrace.txt
analysis.json
README.md
```

`analysis.json` must include:

```json
{
  "reproducible": false,
  "deterministic": false,
  "root_cause_location": {},
  "detection_location": {},
  "attacker_control": [],
  "required_conditions": [],
  "category": "",
  "security_relevance": "confirmed|likely|uncertain|none",
  "duplicate_of": null,
  "next_actions": []
}
```

Do not assign exploitability solely from the crash class.
