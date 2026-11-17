---
name: aavr-repository-recon
description: Inspect an unfamiliar C or C++ repository and produce structured security reconnaissance. Use before building, scanning, editing, or fuzzing to identify languages, build systems, targets, tests, dependencies, parsers, privilege boundaries, externally influenced inputs, existing fuzzers, and security-relevant components.
---

# AAVR Repository Reconnaissance

Inspect before changing or building the repository.

## Establish identity

Record:

- absolute repository root
- current commit and dirty state
- submodules and vendored dependencies
- primary languages and generated code
- target platforms and architectures
- build systems and package managers
- CI workflows that reveal canonical commands

Prefer repository-native evidence such as `README`, contribution guides, CI files, build manifests, and test scripts.

## Inventory security-relevant structure

Locate:

- executable and library entry points
- network listeners and protocol dispatch
- file, archive, image, audio, and document parsing
- IPC, RPC, plugin, device, and kernel interfaces
- authentication and authorization boundaries
- command execution and dynamic loading
- memory ownership boundaries and custom allocators
- length-prefixed buffers, integer-controlled allocations, and state machines
- existing tests, fuzzers, sanitizer jobs, and security tooling

Use targeted searches rather than dumping the entire tree into context.

## Do not over-interpret names

Verify candidate surfaces through callers and data flow. A function named `parse` may consume trusted configuration; a generic helper may receive remote input.

## Output

Write `.aavr/recon/repository.json`:

```json
{
  "target_revision": "",
  "dirty": false,
  "languages": [],
  "build_systems": [],
  "canonical_build_evidence": [],
  "targets": [],
  "tests": [],
  "dependencies": [],
  "entry_points": [],
  "input_surfaces": [],
  "parsers": [],
  "privilege_boundaries": [],
  "existing_fuzzers": [],
  "existing_security_tooling": [],
  "candidate_components": [],
  "unknowns": []
}
```

Also write `.aavr/recon/summary.md` with concise evidence links to files and line ranges.

## Stop condition

Stop and report blockers when the repository root, likely build path, or scope cannot be determined. Do not invent a build command.
