#!/usr/bin/env python3
# Build a compact, reproducible index for a local Semgrep rule corpus.

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError as exc:
    raise SystemExit("PyYAML is required: python -m pip install pyyaml") from exc


def as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        out: list[str] = []
        for item in value:
            out.extend(as_list(item))
        return sorted(set(out))
    if isinstance(value, dict):
        return sorted(str(k) for k, enabled in value.items() if enabled)
    text = str(value).strip()
    return [text] if text else []


def first(metadata: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in metadata:
            return metadata[key]
    return None


def git_info(root: Path) -> dict[str, Any]:
    def run(*args: str) -> str | None:
        try:
            return subprocess.check_output(
                ["git", "-C", str(root), *args],
                text=True,
                stderr=subprocess.DEVNULL,
            ).strip()
        except (OSError, subprocess.CalledProcessError):
            return None

    revision = run("rev-parse", "HEAD")
    status = run("status", "--porcelain") if revision else None
    return {"revision": revision, "dirty": bool(status) if status is not None else None}


def parse_rule_file(path: Path, root: Path) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    errors: list[dict[str, str]] = []
    try:
        raw = path.read_bytes()
        document = yaml.safe_load(raw) or {}
    except Exception as exc:  # YAML diagnostics must survive indexing.
        return [], [{"path": str(path.relative_to(root)), "error": str(exc)}]

    rule_items = document.get("rules") if isinstance(document, dict) else None
    if not isinstance(rule_items, list):
        return [], []

    digest = hashlib.sha256(raw).hexdigest()
    indexed: list[dict[str, Any]] = []
    for offset, rule in enumerate(rule_items):
        if not isinstance(rule, dict):
            errors.append({"path": str(path.relative_to(root)), "error": f"rule {offset} is not a mapping"})
            continue
        metadata = rule.get("metadata") if isinstance(rule.get("metadata"), dict) else {}
        rule_id = str(rule.get("id", "")).strip()
        if not rule_id:
            errors.append({"path": str(path.relative_to(root)), "error": f"rule {offset} has no id"})
            continue

        categories = as_list(first(metadata, "category", "categories", "vulnerability_class"))
        cwes = as_list(first(metadata, "cwe", "cwes"))
        technologies = as_list(first(metadata, "technology", "technologies"))
        surfaces = as_list(first(metadata, "attack_surface", "attack-surfaces", "attack_surfaces"))
        tags = as_list(first(metadata, "tags", "tag"))
        confidence = as_list(first(metadata, "confidence"))
        maturity = as_list(first(metadata, "maturity", "status"))

        indexed.append({
            "id": rule_id,
            "path": str(path.relative_to(root)),
            "document_rule_index": offset,
            "file_sha256": digest,
            "languages": as_list(rule.get("languages")),
            "severity": str(rule.get("severity", "")).lower(),
            "mode": str(rule.get("mode", "search")).lower(),
            "message": str(rule.get("message", "")),
            "categories": categories,
            "cwe": cwes,
            "technologies": technologies,
            "attack_surfaces": surfaces,
            "confidence": confidence,
            "maturity": maturity,
            "tags": tags,
            "metadata": metadata,
        })
    return indexed, errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rules-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    root = args.rules_root.expanduser().resolve()
    if not root.is_dir():
        parser.error(f"rules root is not a directory: {root}")

    rules: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    paths = sorted({*root.rglob("*.yml"), *root.rglob("*.yaml")})
    for path in paths:
        found, failed = parse_rule_file(path, root)
        rules.extend(found)
        errors.extend(failed)

    duplicates: dict[str, list[str]] = {}
    by_id: dict[str, list[str]] = {}
    for rule in rules:
        by_id.setdefault(rule["id"], []).append(rule["path"])
    duplicates = {rule_id: locations for rule_id, locations in by_id.items() if len(locations) > 1}

    output = {
        "schema_version": 1,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "rules_root": str(root),
        "database_git": git_info(root),
        "files_scanned": len(paths),
        "rule_count": len(rules),
        "duplicates": duplicates,
        "parse_errors": errors,
        "rules": sorted(rules, key=lambda item: (item["id"], item["path"])),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"output": str(args.output), "rule_count": len(rules), "parse_errors": len(errors), "duplicates": len(duplicates)}))
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
