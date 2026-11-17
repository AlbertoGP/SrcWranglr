#!/usr/bin/env python3
# Select a context-relevant subset from an AAVR Semgrep rule index.

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


def split_values(values: list[str] | None) -> set[str]:
    out: set[str] = set()
    for value in values or []:
        out.update(part.strip().lower() for part in value.split(",") if part.strip())
    return out


def normalized(values: Any) -> set[str]:
    if values is None:
        return set()
    if not isinstance(values, list):
        values = [values]
    return {str(value).strip().lower() for value in values if str(value).strip()}


def load_profile(path: Path | None) -> dict[str, Any]:
    if path is None:
        return {}
    data = json.loads(path.read_text())
    if not isinstance(data, dict):
        raise ValueError("profile must contain a JSON object")
    return data


def merge_filter(cli: list[str] | None, profile: dict[str, Any], key: str) -> set[str]:
    values = list(cli or [])
    profile_value = profile.get(key, [])
    if isinstance(profile_value, str):
        values.append(profile_value)
    elif isinstance(profile_value, list):
        values.extend(str(v) for v in profile_value)
    return split_values(values)


def intersects(rule: dict[str, Any], field: str, wanted: set[str]) -> bool:
    return not wanted or bool(normalized(rule.get(field)) & wanted)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--index", required=True, type=Path)
    parser.add_argument("--profile", type=Path)
    parser.add_argument("--language", action="append")
    parser.add_argument("--category", action="append")
    parser.add_argument("--cwe", action="append")
    parser.add_argument("--technology", action="append")
    parser.add_argument("--attack-surface", action="append")
    parser.add_argument("--confidence", action="append")
    parser.add_argument("--maturity", action="append")
    parser.add_argument("--tag", action="append")
    parser.add_argument("--include-experimental", action="store_true")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--paths-output", type=Path)
    args = parser.parse_args()

    index = json.loads(args.index.read_text())
    profile = load_profile(args.profile)
    filters = {
        "languages": merge_filter(args.language, profile, "languages"),
        "categories": merge_filter(args.category, profile, "categories"),
        "cwe": merge_filter(args.cwe, profile, "cwe"),
        "technologies": merge_filter(args.technology, profile, "technologies"),
        "attack_surfaces": merge_filter(args.attack_surface, profile, "attack_surfaces"),
        "confidence": merge_filter(args.confidence, profile, "confidence"),
        "maturity": merge_filter(args.maturity, profile, "maturity"),
        "tags": merge_filter(args.tag, profile, "tags"),
    }

    include_experimental = args.include_experimental or bool(profile.get("include_experimental", False))
    excluded_maturity = normalized(profile.get("exclude_maturity", ["deprecated"]))
    if not include_experimental:
        excluded_maturity.add("experimental")

    selected: list[dict[str, Any]] = []
    rejected_by_maturity = 0
    for rule in index.get("rules", []):
        maturity = normalized(rule.get("maturity"))
        if maturity & excluded_maturity:
            rejected_by_maturity += 1
            continue
        if all(intersects(rule, field, wanted) for field, wanted in filters.items()):
            selected.append(rule)

    unique_paths = sorted({rule["path"] for rule in selected})
    reasons = [f"{field}={','.join(sorted(values))}" for field, values in filters.items() if values]
    if not reasons:
        reasons.append("no explicit metadata filters")
    if not include_experimental:
        reasons.append("experimental rules excluded")

    output = {
        "schema_version": 1,
        "index": str(args.index),
        "rules_root": index.get("rules_root"),
        "database_git": index.get("database_git"),
        "profile": str(args.profile) if args.profile else None,
        "filters": {key: sorted(value) for key, value in filters.items()},
        "selection_reasons": reasons,
        "selected_rule_count": len(selected),
        "selected_file_count": len(unique_paths),
        "rejected_by_maturity": rejected_by_maturity,
        "selected_rules": selected,
        "selected_paths": unique_paths,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, indent=2, sort_keys=True) + "\n")
    if args.paths_output:
        args.paths_output.parent.mkdir(parents=True, exist_ok=True)
        args.paths_output.write_text("".join(f"{path}\n" for path in unique_paths))
    print(json.dumps({"output": str(args.output), "selected_rules": len(selected), "selected_files": len(unique_paths)}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
