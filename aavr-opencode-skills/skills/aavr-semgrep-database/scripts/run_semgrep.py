#!/usr/bin/env python3
# Run a selected local Semgrep subset and preserve reproducible artifacts.

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import shlex
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


def load_selection(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text())
    if not isinstance(data, dict) or not isinstance(data.get("selected_paths"), list):
        raise ValueError("selection JSON must contain selected_paths")
    return data


def resolve_rule(root: Path, relative: str) -> Path:
    candidate = (root / relative).resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"selected rule escapes rules root: {relative}") from exc
    if not candidate.is_file():
        raise FileNotFoundError(f"selected rule does not exist: {candidate}")
    return candidate


def semgrep_version(binary: str) -> str | None:
    try:
        return subprocess.check_output([binary, "--version"], text=True, stderr=subprocess.STDOUT).strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rules-root", required=True, type=Path)
    parser.add_argument("--selection", required=True, type=Path)
    parser.add_argument("--target", default=".", type=Path)
    parser.add_argument("--run-dir", required=True, type=Path)
    parser.add_argument("--semgrep-bin", default="semgrep")
    parser.add_argument("--extra-arg", action="append", default=[])
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    root = args.rules_root.expanduser().resolve()
    target = args.target.expanduser().resolve()
    selection = load_selection(args.selection)
    selected_paths = [resolve_rule(root, str(path)) for path in selection["selected_paths"]]
    if not selected_paths:
        parser.error("selection contains no rule files")
    if not target.exists():
        parser.error(f"target does not exist: {target}")

    run_dir = args.run_dir.resolve()
    run_dir.mkdir(parents=True, exist_ok=True)
    raw_json = run_dir / "semgrep-results.json"
    command = [args.semgrep_bin, "scan"]
    for rule_path in selected_paths:
        command.extend(["--config", str(rule_path)])
    command.extend(["--json", "--output", str(raw_json)])
    command.extend(args.extra_arg)
    command.append(str(target))

    (run_dir / "command.txt").write_text(shlex.join(command) + "\n")
    (run_dir / "selection.json").write_text(json.dumps(selection, indent=2, sort_keys=True) + "\n")
    start = time.monotonic()
    started_at = dt.datetime.now(dt.timezone.utc).isoformat()

    if args.dry_run:
        status = {
            "status": "dry-run",
            "started_at": started_at,
            "duration_seconds": 0.0,
            "exit_code": None,
            "selected_rule_files": len(selected_paths),
            "semgrep_version": semgrep_version(args.semgrep_bin),
        }
        (run_dir / "stdout.log").write_text("")
        (run_dir / "stderr.log").write_text("")
        (run_dir / "status.json").write_text(json.dumps(status, indent=2) + "\n")
        print(json.dumps(status))
        return 0

    try:
        proc = subprocess.run(command, text=True, capture_output=True, check=False)
    except FileNotFoundError:
        status = {
            "status": "tool-unavailable",
            "started_at": started_at,
            "duration_seconds": time.monotonic() - start,
            "exit_code": 127,
            "selected_rule_files": len(selected_paths),
            "semgrep_version": None,
        }
        (run_dir / "stdout.log").write_text("")
        (run_dir / "stderr.log").write_text(f"Semgrep executable not found: {args.semgrep_bin}\n")
        (run_dir / "status.json").write_text(json.dumps(status, indent=2) + "\n")
        print(json.dumps(status), file=sys.stderr)
        return 127

    (run_dir / "stdout.log").write_text(proc.stdout)
    (run_dir / "stderr.log").write_text(proc.stderr)
    finding_count: int | None = None
    if raw_json.exists():
        try:
            result = json.loads(raw_json.read_text())
            finding_count = len(result.get("results", [])) if isinstance(result, dict) else None
        except (OSError, json.JSONDecodeError):
            finding_count = None

    status = {
        "status": "completed" if proc.returncode == 0 else "failed",
        "started_at": started_at,
        "duration_seconds": round(time.monotonic() - start, 6),
        "exit_code": proc.returncode,
        "selected_rule_files": len(selected_paths),
        "finding_count": finding_count,
        "semgrep_version": semgrep_version(args.semgrep_bin),
        "target": str(target),
        "rules_root": str(root),
        "database_git": selection.get("database_git"),
    }
    (run_dir / "status.json").write_text(json.dumps(status, indent=2, sort_keys=True) + "\n")
    print(json.dumps(status))
    return proc.returncode


if __name__ == "__main__":
    sys.exit(main())
