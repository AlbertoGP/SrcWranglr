---
name: aavr-fuzz-target-selection
description: Evaluate and rank C or C++ APIs, parsers, and state transitions for fuzzing suitability. Use after attack-surface mapping or finding triage and before harness generation. Select targets based on attacker relevance, reachability, initialization cost, determinism, reset requirements, coverage potential, and dependency complexity.
---

# AAVR Fuzz Target Selection

Select a valuable boundary before writing a harness.

## Candidate requirements

For each candidate, establish:

- attacker-relevant input model
- concrete API or process boundary
- required initialization and dependencies
- state and lifecycle requirements
- reset or isolation strategy
- expected path depth and coverage signal
- deterministic behavior
- execution cost
- corpus and dictionary opportunities
- known blockers

Read real callers. Do not infer usage from a declaration alone.

## Score candidates

Score 0 to 5 and explain:

- attacker relevance
- default reachability
- parser or state complexity
- memory-safety potential
- API isolation
- initialization cost, reverse scored
- reset difficulty, reverse scored
- expected executions per second
- corpus availability
- observability and coverage potential

A high total does not override a fundamental blocker.

## Select engine

- Prefer libFuzzer for in-process, deterministic library boundaries.
- Prefer AFL++ when process-level behavior, forkserver operation, or broader instrumentation is advantageous.
- Prefer a custom driver only when standard engines cannot model the interface.
- Do not select kernel fuzzing machinery without a kernel-specific plan.

## Output

Write `.aavr/harnesses/selection.json`:

```json
{
  "selected_target": "",
  "symbol_or_entry": "",
  "score": 0,
  "engine": "",
  "input_model": "single-buffer|structured|sequence|process",
  "initialization": [],
  "reset_strategy": "",
  "required_invariants": [],
  "seed_sources": [],
  "dictionary_sources": [],
  "blocking_issues": [],
  "rejected_candidates": []
}
```

## Gate

Do not load `aavr-harness-generation` until the target API, initialization, input model, and reset strategy are explicit.
