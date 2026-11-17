---
name: aavr-fuzz-campaign
description: Execute and monitor a bounded libFuzzer, AFL++, or compatible fuzzing campaign using a validated harness. Use after harness generation and smoke testing to record runtime parameters, corpus growth, coverage, execution speed, hangs, crashes, sanitizer failures, and an explicit stopping reason.
---

# AAVR Fuzz Campaign

Run controlled stages. Do not launch an indefinite campaign by default.

## Preflight

Verify:

- exact harness revision and build command
- sanitizer configuration
- initial corpus and dictionary
- target reachability from smoke testing
- output directories
- CPU, memory, storage, and timeout constraints
- crash and hang reproduction commands

## Stages

1. Harness validation: 30 to 60 seconds.
2. Corpus validation: confirm seeds parse and mutate usefully.
3. Bounded campaign: use the requested limit or a conservative short limit.
4. Extended campaign: require explicit approval and documented resources.

## Monitor

Record at intervals:

- elapsed time
- executions and executions per second
- corpus size and growth
- coverage or feature counts
- timeout and OOM rates
- sanitizer events
- unique crashes and hangs
- worker health

Stop early when:

- intended code is not reached
- coverage does not move after reasonable corpus checks
- the harness leaks or accumulates stale state
- timeouts dominate
- output storage grows unexpectedly
- a reproducible crash requires triage
- the environment becomes unstable

## Output

Store each campaign under `.aavr/runs/<run-id>/fuzz/` with:

```text
command.txt
config.json
stdout.log
stderr.log
corpus/
crashes/
hangs/
metrics.jsonl
summary.json
```

`summary.json` must include the stopping reason and whether results are complete, partial, or invalid.

## Handoff

Load `aavr-crash-triage` for every unique crash or hang. Do not infer root cause from the fuzzer filename or top stack frame.
