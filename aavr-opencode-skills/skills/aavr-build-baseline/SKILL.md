---
name: aavr-build-baseline
description: Establish and document a clean baseline build and test result for a C or C++ repository. Use after reconnaissance and before sanitizer instrumentation, static analysis that requires a build database, patches, or fuzzing. Preserve exact commands, environment, compiler versions, warnings, generated configuration, and pre-existing failures.
---

# AAVR Build Baseline

Prove what the unmodified repository does before adding instrumentation.

## Prepare safely

- Record the target revision and dirty state.
- Prefer an out-of-tree build directory beneath `.aavr/baseline/` when supported.
- Use the repository's documented or CI-derived command first.
- Do not silently install system packages or run `sudo`.
- Do not change production defaults merely to obtain a successful build.

## Record environment

Capture:

- OS and architecture
- compiler and linker versions
- build-tool versions
- relevant environment variables, excluding secrets
- configure or generation command
- build command
- test command
- selected target and feature flags

## Execute baseline

1. Configure or generate.
2. Build without sanitizer changes.
3. Run the smallest canonical test set, then the normal suite when practical.
4. Record warnings and failures exactly.
5. Generate `compile_commands.json` when the build system supports it without invasive changes.

Classify every failure as:

- configuration failure
- missing dependency
- compiler error
- linker error
- test failure
- environmental limitation
- unsupported target
- unknown

## Output

Create:

```text
.aavr/baseline/
├── environment.json
├── commands.json
├── configure.log
├── build.log
├── test.log
├── compile_commands.json   # when available
└── summary.json
```

`summary.json` must include:

```json
{
  "baseline_status": "passed|failed|partial|blocked",
  "build_reproducible": false,
  "tests_reproducible": false,
  "preexisting_failures": [],
  "warnings": [],
  "artifacts": [],
  "next_requirements": []
}
```

## Gate

Do not attribute later failures to instrumentation until they are compared with this baseline.
