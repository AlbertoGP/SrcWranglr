# Semgrep Rule Quality Checklist

## Root cause

- State the violated invariant.
- Identify the attacker-controlled or security-relevant value.
- Separate essential semantics from incidental syntax.
- Identify the safe pattern that must not match.

## Rule design

- Use a stable, namespaced ID.
- Prefer the narrowest construct that models the invariant.
- Use taint mode only when local matching is insufficient.
- Avoid matching comments, generated code, or tests unless intentional.
- Add metadata for confidence, maturity, category, platform, and attack surface.

## Tests

- Include a known-positive fixture.
- Include a known-negative fixture.
- Add realistic syntactic and type variants.
- Run `semgrep --test` or the corpus-native test command.
- Scan a representative clean corpus.
- Record unexpected matches and their causes.

## Promotion

- Confirm the ID is unique.
- Confirm test results are reproducible.
- Record Semgrep version and rule file hash.
- Mark unreviewed rules experimental.
- Obtain explicit approval before replacing a stable production rule.
