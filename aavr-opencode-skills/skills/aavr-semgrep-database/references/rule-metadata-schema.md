# AAVR Semgrep Rule Metadata Schema

The indexer accepts arbitrary Semgrep metadata but recognizes these fields for selection:

```yaml
rules:
  - id: aavr.c.integer.allocation-truncation
    languages: [c, cpp]
    message: Integer-controlled allocation may be undersized
    severity: WARNING
    metadata:
      category: [integer-overflow, undersized-allocation]
      cwe: [CWE-190, CWE-131]
      technology: [native]
      attack_surface: [file-parser, network-parser]
      confidence: high
      maturity: stable
      tags: [memory-safety, allocation]
```

Accepted aliases:

- `category`, `categories`, or `vulnerability_class`
- `cwe` or `cwes`
- `technology` or `technologies`
- `attack_surface`, `attack_surfaces`, or `attack-surfaces`
- `maturity` or `status`
- `tag` or `tags`

Use lowercase canonical values where practical. Keep IDs stable. Treat the rule file's SHA-256 and database Git revision as provenance, not as rule metadata.
