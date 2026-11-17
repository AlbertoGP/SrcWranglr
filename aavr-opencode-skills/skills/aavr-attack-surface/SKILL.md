---
name: aavr-attack-surface
description: Map attacker-accessible input boundaries and security-sensitive components in a native-code repository. Use after reconnaissance to prioritize manual review, static analysis, sanitizer validation, and fuzzing. Trace network, file, IPC, device, environment, plugin, and command-line inputs toward parsers, trust transitions, and dangerous operations.
---

# AAVR Attack-Surface Mapping

Prioritize code by realistic attacker influence, not by file size or suspicious names.

## Identify input origins

Consider:

- network packets, messages, requests, and peer state
- untrusted files and embedded metadata
- IPC, RPC, shared memory, sockets, and message buses
- device descriptors, firmware data, kernel interfaces, and ioctl payloads
- plugins, modules, scripts, and dynamically loaded content
- environment variables, configuration, and command-line values crossing trust boundaries
- data from lower-privileged users or sandboxed processes

## Trace each surface

For each input origin, identify:

1. entry point or dispatcher
2. parser or decoder
3. transformations and normalization
4. validation and bounds checks
5. ownership and lifetime transitions
6. integer conversions and allocation decisions
7. sensitive sinks or state transitions
8. privilege and sandbox context
9. exposure assumptions
10. suitable test or fuzz boundary

Verify reachability through call sites and build configuration.

## Rank surfaces

Score from 0 to 5:

- attacker control
- default exposure
- parser complexity
- memory-unsafety potential
- privilege impact
- state-machine complexity
- validation weakness
- testability

Explain each high score. Do not convert the sum directly into severity.

## Output

Write `.aavr/surfaces/map.json` with entries:

```json
{
  "id": "SURFACE-001",
  "origin": "",
  "trust": "untrusted|partially-trusted|trusted",
  "entry_point": "",
  "parser": "",
  "transformations": [],
  "checks": [],
  "sinks": [],
  "privilege_context": "",
  "exposure_assumptions": [],
  "candidate_fuzz_boundary": "",
  "scores": {},
  "priority": "high|medium|low",
  "evidence": []
}
```

Also produce `.aavr/surfaces/priority.md` listing the top surfaces and why they matter.

## Stop condition

If attacker influence cannot be established, mark the surface uncertain. Never label internal-only code remotely reachable without evidence.
