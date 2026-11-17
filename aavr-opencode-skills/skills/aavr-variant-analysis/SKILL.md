---
name: aavr-variant-analysis
description: Search a C or C++ repository for additional instances of a confirmed or strongly supported vulnerability pattern. Use only after the root cause, violated invariant, relevant types, and control-flow or data-flow conditions are understood. Create targeted structural, semantic, CodeQL, Semgrep, or Coccinelle searches and manually validate every result.
---

# AAVR Variant Analysis

Search for the violated invariant, not merely identical syntax.

## Define the pattern

Extract from the root cause:

- unsafe invariant
- attacker-controlled source type
- transformation or missing check
- sink or lifetime operation
- relevant data types and ownership model
- control-flow preconditions
- fixed or safe pattern, when available

Separate essential properties from incidental names and formatting.

## Build searches incrementally

1. Start with direct structural searches near the affected API.
2. Generalize names while preserving semantics.
3. Use Semgrep for syntax and local flow.
4. Use CodeQL for interprocedural source-to-sink or type relationships.
5. Use Coccinelle for C semantic patches and API patterns.
6. Compare patches or sibling implementations when useful.

Create small known-positive and known-negative examples for custom rules when practical.

## Validate every match

For each candidate, check:

- code is built in scope
- input is attacker-influenced
- required state is reachable
- equivalent checks are absent
- ownership and type semantics match
- the same safety property can fail

Do not count search hits as variants until validated.

## Output

Create `.aavr/variants/<finding-id>/`:

```text
pattern.md
queries/
raw-results/
validated.jsonl
rejected.jsonl
summary.md
```

Each result must record evidence, classification, and rejection reason when applicable.

## Completion

State search limitations explicitly: unsupported languages, generated code, missing build variants, unavailable dependencies, or query blind spots.
