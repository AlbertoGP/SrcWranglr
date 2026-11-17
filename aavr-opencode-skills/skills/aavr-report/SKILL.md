---
name: aavr-report
description: Generate an evidence-backed AAVR vulnerability research report from repository reconnaissance, build, analysis, validation, fuzzing, crash, and variant artifacts. Use to summarize current scope, methodology, findings, rejected candidates, coverage, limitations, reproduction steps, and recommended next actions without overstating certainty.
---

# AAVR Report

Report what was actually executed and observed. Do not fill gaps with plausible-sounding claims.

## Establish report identity

Include:

- repository and target revision
- dirty state
- assessment scope and exclusions
- date and environment
- tool versions
- build configuration
- artifact root

## Methodology

List completed and skipped phases. For every skipped phase, provide the reason. Separate commands executed successfully from attempts that failed or were blocked.

## Findings

Group findings by:

1. confirmed
2. likely
3. speculative
4. rejected
5. blocked

For each retained finding include:

- title and identifier
- classification, confidence, and severity
- affected code and build target
- attacker-controlled input
- source-to-sink or lifetime path
- violated safety property
- required conditions and constraints
- security impact supported by evidence
- exact reproduction steps
- sanitizer, debugger, test, or fuzz evidence
- remediation direction
- open questions

Do not hide rejected candidates; summarize why high-signal false positives were rejected.

## Coverage and limitations

Document:

- attack surfaces reviewed and omitted
- tools and query suites used
- test and sanitizer coverage
- fuzz targets, duration, corpus, and coverage signal
- unsupported build variants or platforms
- environmental and time constraints
- evidence that remains unavailable

## Output

Write `.aavr/reports/aavr-report.md` and `.aavr/reports/aavr-report.json`.

The JSON should index every artifact path used to support each claim. The Markdown report should be readable without the JSON but must not embed excessive raw logs.

## Final quality checks

- Verify every finding path and command.
- Verify classifications match available evidence.
- Remove unsupported severity or exploitability language.
- Distinguish root cause from crash location.
- Confirm secrets and private paths are not included accidentally.
- State whether the report is preliminary or final.
