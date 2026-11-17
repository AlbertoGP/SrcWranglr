#!/usr/bin/env bash
set -euo pipefail
BASE="${XDG_CONFIG_HOME:-$HOME/.config}/opencode"
BIN_DIR="${AAVR_BIN_DIR:-$HOME/.local/bin}"
for d in "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"/skills/aavr-*; do
  [ -d "$d" ] || continue
  rm -rf "$BASE/skills/$(basename "$d")"
done
for f in "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"/commands/aavr*.md; do
  [ -f "$f" ] || continue
  rm -f "$BASE/commands/$(basename "$f")"
done
rm -f "$BIN_DIR/aavr-semgrep-index" "$BIN_DIR/aavr-semgrep-select" "$BIN_DIR/aavr-semgrep-run"
printf 'Removed the bundled AAVR skills, commands, and helper binaries from %s\n' "$BASE"
