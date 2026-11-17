---
name: aavr-semgrep-database
description: Query, select, and execute rules from an external private AAVR Semgrep rule database. Use after repository reconnaissance or attack-surface mapping when a large local Semgrep corpus is available. Build or refresh a compact rule index, select relevant rules by language, platform, CWE, category, technology, attack surface, confidence, maturity, or profile, preserve exact rule provenance and raw JSON, and hand unconfirmed matches to AAVR finding triage.
---

# AAVR Semgrep Database

Use the configured external rule corpus without loading the entire database into model context.

## Locate the corpus

Resolve the rules root in this order:

1. explicit user-provided path
2. `AAVR_SEMGREP_RULES`
3. `semgrep.rules_path` in `~/.config/aavr/config.json`
4. project-local `.aavr/config.json`

Never guess a private path. Stop with a clear configuration requirement when no corpus is available.

## Keep the corpus external

Do not copy a large private rule database into the OpenCode skill directory or target repository. Treat the database as read-only unless the user explicitly invokes rule authoring.

Record:

- absolute rules root
- database Git revision and dirty state when applicable
- index generation time
- selected rule IDs and paths
- file hashes
- Semgrep version
- target revision

## Index before selection

Use the installed `aavr-semgrep-index` wrapper to generate a compact index. For a project-local installation, use `.opencode/bin/aavr-semgrep-index` when `.opencode/bin` is not on `PATH`:

```bash
aavr-semgrep-index \
  --rules-root "$AAVR_SEMGREP_RULES" \
  --output .aavr/semgrep/rule-index.json
```

Do not read thousands of YAML files into context. Inspect the index and only open individual rule files when debugging selection, validating a match, or authoring a rule.

## Select contextually

Use reconnaissance and attack-surface artifacts to choose filters. Prefer stable high- and medium-confidence rules first. Exclude deprecated and experimental rules unless explicitly requested or no mature coverage exists.

```bash
aavr-semgrep-select \
  --index .aavr/semgrep/rule-index.json \
  --language c \
  --attack-surface network-parser \
  --confidence high,medium \
  --output .aavr/semgrep/selection.json \
  --paths-output .aavr/semgrep/selected-rules.txt
```

Use a profile file when the corpus defines reusable selections such as `network-daemon`, `file-parser`, `linux-kernel`, or `embedded-firmware`.

## Execute deterministically

Use the installed `aavr-semgrep-run` wrapper rather than inventing a large shell command:

```bash
aavr-semgrep-run \
  --rules-root "$AAVR_SEMGREP_RULES" \
  --selection .aavr/semgrep/selection.json \
  --target . \
  --run-dir .aavr/runs/semgrep-001
```

The wrapper must preserve the command, stdout, stderr, status, raw Semgrep JSON, selected rule list, and tool version. Treat tool failure separately from a zero-result scan.

## Normalize and triage

Convert every result into an AAVR candidate while preserving:

```json
{
  "tool": "semgrep",
  "rule_id": "",
  "rule_path": "",
  "rule_file_sha256": "",
  "rules_database_revision": "",
  "semgrep_version": "",
  "profile": "",
  "selection_reasons": [],
  "raw_artifact": "",
  "validation_status": "unreviewed"
}
```

Do not classify a match as a vulnerability. Load `aavr-finding-triage` for the strongest candidates and verify build inclusion, attacker control, reachability, constraints, and the violated safety property.

## Selection discipline

- Prefer attack-surface-aware subsets over running the entire database.
- Run a broad baseline only when the corpus size and project size make it practical.
- Record skipped rule families and reasons.
- Do not enable autofix.
- Do not modify production source.
- Do not expose private rule contents in reports unless explicitly allowed.

## Outputs

Create:

```text
.aavr/semgrep/
├── rule-index.json
├── selection.json
├── selected-rules.txt
└── summary.md
```

Store each execution beneath `.aavr/runs/<run-id>/` and append normalized candidates to `.aavr/findings/candidates.jsonl`.
