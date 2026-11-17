---
name: aavr-finding-triage
description: Triage scanner results and manually discovered code patterns into evidence-backed vulnerability candidates. Use after static analysis or code review to establish attacker control, source-to-sink flow, reachability, constraints, violated safety properties, duplicates, exploitability assumptions, and a concrete validation plan.
---

# AAVR Finding Triage

Convert warnings into defensible hypotheses. Reject aggressively when material evidence is absent.

## Analyze each candidate

Answer with source evidence:

1. Where does the relevant data originate?
2. Can an attacker influence it under realistic deployment assumptions?
3. Which functions and transformations carry it to the operation?
4. Which checks, types, protocol limits, or invariants constrain it?
5. Is the code built and reachable in the assessed configuration?
6. What exact safety property could fail?
7. What runtime state and input conditions are required?
8. What experiment would confirm or reject the hypothesis?
9. Is this the root cause, a symptom, or a duplicate?

Trace callers and callees far enough to resolve material uncertainty. Do not stop at the warning line.

## Classification

Use exactly one:

- `confirmed`: reproduced with direct supporting evidence
- `likely`: strong path evidence; a material validation step remains
- `speculative`: plausible but missing material evidence
- `rejected`: unreachable, safely constrained, duplicate, tool error, or otherwise unsupported
- `blocked`: required build, input, platform, or environment is unavailable

Severity is separate from confidence. Do not assign high severity to an uncertain path merely because the sink is dangerous.

## Output

Write `.aavr/findings/<id>.json`:

```json
{
  "id": "",
  "title": "",
  "classification": "",
  "confidence": "low|medium|high",
  "severity": "informational|low|medium|high|critical|unassigned",
  "source": {},
  "path": [],
  "sink": {},
  "checks_and_constraints": [],
  "violated_property": "",
  "required_conditions": [],
  "impact_hypothesis": "",
  "evidence": [],
  "validation_plan": [],
  "duplicates": [],
  "open_questions": []
}
```

## Language discipline

Avoid unsupported phrases such as “potential RCE,” “clearly exploitable,” or “looks vulnerable.” State what is known, inferred, and unverified.

## Handoff

Use `aavr-sanitizer-validation` for runtime proof, `aavr-fuzz-target-selection` for discovery around a reachable parser, or `aavr-report` when no further validation is justified.
