---
name: aavr-sanitizer-validation
description: Configure, build, and test C or C++ targets under appropriate runtime sanitizers. Use to establish a sanitized baseline, validate memory-safety or undefined-behavior hypotheses, or prepare a target for fuzzing. Make minimal reversible build changes and preserve complete compiler and runtime evidence.
---

# AAVR Sanitizer Validation

Choose instrumentation based on the hypothesis and toolchain constraints.

## Select sanitizer

- ASan: out-of-bounds, use-after-free, double free, invalid free
- UBSan: integer and language undefined behavior
- LSan: leaks affecting services or repeated iterations
- MSan: uninitialized reads only when dependencies can be instrumented correctly
- TSan: data races when the target and workload are suitable
- KASAN or KCSAN: kernel targets using an appropriate kernel workflow

Do not combine sanitizers blindly. Record unsupported combinations and platform limitations.

## Build separately

- Preserve the normal baseline.
- Prefer a dedicated build directory beneath `.aavr/runs/<run-id>/build/`.
- Prefer debug symbols and frame pointers.
- Keep optimization low enough for diagnostics but high enough to preserve realistic behavior.
- Record all flags and environment variables.

A common user-space starting point is:

```text
-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1
```

Adapt to the repository rather than forcing these flags into every target.

## Validate

1. Build the intended target.
2. Run existing tests to establish a sanitized baseline.
3. Reproduce the candidate with the smallest controlled input or test.
4. Capture full reports and symbolized stacks.
5. Repeat to check determinism.
6. Compare failures with the normal baseline.

Classify outcomes:

- confirmed sanitizer finding
- candidate not reproduced
- build blocked
- runtime blocked
- failure in unrelated code
- instrumentation incompatibility
- inconclusive

## Output

Store commands and logs under `.aavr/runs/<run-id>/`. Update the finding with:

```json
{
  "validation_method": "sanitizer",
  "sanitizers": [],
  "reproduction_command": "",
  "result": "",
  "stack_artifact": "",
  "input_artifact": "",
  "deterministic": false,
  "notes": []
}
```

Never mark a finding confirmed solely because the instrumented build emits unrelated sanitizer output.
