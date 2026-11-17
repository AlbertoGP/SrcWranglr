---
name: aavr-semgrep-rule-authoring
description: Create, refine, test, and review Semgrep rules for confirmed or strongly supported C or C++ vulnerability patterns. Use when converting an understood root cause or unsafe invariant into a reusable private rule, reducing false positives, adding positive and negative fixtures, or preparing targeted variant analysis. Keep experimental work separate from the production rule corpus until tests and review pass.
---

# AAVR Semgrep Rule Authoring

Author rules from understood security invariants, not from vague suspicious syntax.

## Establish the source pattern

Require one of:

- a confirmed finding
- a strongly supported finding with a precise unsafe invariant
- an explicit rule-development request with known-positive and known-negative examples

Extract:

- attacker-controlled source or relevant object state
- transformation or missing validation
- dangerous sink or lifetime operation
- required type and control-flow constraints
- safe pattern that must not match
- expected language and build variants

Do not create a broad production rule merely from one scanner warning.

## Work outside production rules

Create an experimental workspace beneath `.aavr/semgrep-authoring/<rule-id>/` or the corpus's documented development directory. Do not overwrite an existing rule silently.

Use this layout:

```text
<rule-id>/
├── rule.yml
├── positive.c
├── negative.c
├── test-output.log
├── rationale.md
└── review.json
```

Follow the corpus naming, metadata, severity, and directory conventions. Consult `references/rule-quality-checklist.md` before promotion.

## Author incrementally

1. Write the narrowest rule that detects the known-positive case.
2. Add a known-negative case representing the safe invariant.
3. Add realistic syntactic variants.
4. Add type, metavariable, pattern-inside, pattern-not, or taint constraints only when justified.
5. Run Semgrep's rule tests.
6. Execute against the target repository and a representative clean corpus.
7. Review every match and record false-positive causes.
8. Generalize only while tests remain discriminating.

Prefer local patterns for local invariants and taint mode only when source-to-sink modeling materially improves precision.

## Metadata requirements

Record at minimum:

- stable rule ID
- languages
- message
- severity
- CWE or category when defensible
- confidence
- maturity (`experimental`, `beta`, or `stable`)
- attack-surface tags
- technology or platform tags
- references to the originating internal finding when permitted

Do not assign a CWE, severity, or exploitability claim that the evidence does not support.

## Test requirements

Require:

- at least one positive fixture
- at least one negative fixture
- no unexpected test matches
- a documented target scan
- a documented clean-corpus or sibling-project scan when practical
- review of generated or vendored code noise

For variant-analysis rules, manually validate every repository match before counting it as a variant.

## Promotion gate

Promote into the production corpus only when:

- tests pass
- the rule ID is unique
- metadata is complete
- expected false positives are documented
- rule scope matches the unsafe invariant
- another reviewer or explicit user approval is available

Otherwise leave the rule marked experimental and report what remains uncertain.

## Handoff

After a validated rule scan, load `aavr-variant-analysis` and `aavr-finding-triage`. Preserve rule revision, file hash, Semgrep version, and raw results with every candidate.
