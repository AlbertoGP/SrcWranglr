#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  ./install.sh                    Install globally to ~/.config/opencode
  ./install.sh --global           Same as above
  ./install.sh --project [PATH]   Install into PATH/.opencode (default: current directory)
  ./install.sh --skills-only      Install skills and helper binaries, but not slash commands
EOF
}

MODE=global
TARGET=""
INSTALL_COMMANDS=1

while [ "$#" -gt 0 ]; do
  case "$1" in
    --global) MODE=global ;;
    --project) MODE=project; shift; TARGET="${1:-.}" ;;
    --skills-only) INSTALL_COMMANDS=0 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"

if [ "$MODE" = global ]; then
  BASE="${XDG_CONFIG_HOME:-$HOME/.config}/opencode"
  BIN_DIR="${AAVR_BIN_DIR:-$HOME/.local/bin}"
else
  BASE="$(cd "$TARGET" && pwd)/.opencode"
  BIN_DIR="$BASE/bin"
fi

mkdir -p "$BASE/skills"
cp -R "$SCRIPT_DIR/skills/." "$BASE/skills/"
mkdir -p "$BIN_DIR"
cp "$SCRIPT_DIR"/bin/aavr-semgrep-* "$BIN_DIR/"
chmod +x "$BIN_DIR"/aavr-semgrep-*

if [ "$INSTALL_COMMANDS" -eq 1 ]; then
  mkdir -p "$BASE/commands"
  cp -R "$SCRIPT_DIR/commands/." "$BASE/commands/"
fi

printf 'Installed %s AAVR skills to %s/skills\n' "$(find "$SCRIPT_DIR/skills" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ')" "$BASE"
printf 'Installed Semgrep helper commands to %s\n' "$BIN_DIR"
if [ "$MODE" = global ]; then
  case ":${PATH:-}:" in
    *":$BIN_DIR:"*) ;;
    *) printf 'Add %s to PATH to call aavr-semgrep-index/select/run directly.\n' "$BIN_DIR" ;;
  esac
fi
if [ "$INSTALL_COMMANDS" -eq 1 ]; then
  printf 'Installed AAVR commands to %s/commands\n' "$BASE"
fi
printf 'Restart OpenCode, then run /aavr or ask the model to use the AAVR workflow.\n'
