#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
REPO_DIR="$(pwd)"
LOG_FILE="$REPO_DIR/.build-watch.log"
PID_FILE="$REPO_DIR/.build-watch.pid"

echo "Installing dependencies"
npm install

echo "Building"
npm run build

echo "Linking beam globally"
npm link

if [[ -f "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
  kill "$(cat "$PID_FILE")" 2>/dev/null || true
fi

echo "Starting background rebuild watcher (so 'beam' always reflects current source)"
nohup npm run build:watch >"$LOG_FILE" 2>&1 &
echo $! > "$PID_FILE"
disown

echo
echo "Done. 'beam' now runs globally from this checkout and stays in sync automatically."
echo "Watcher PID $(cat "$PID_FILE"), logs at $LOG_FILE. Stop it with: kill \$(cat $PID_FILE)"
beam --version

if [[ -t 0 ]]; then
  read -r -p "Start the beam collector in the background now (survives reboot/logout)? [Y/n] " answer
  answer=${answer:-Y}
  if [[ "$answer" =~ ^[Yy] ]]; then
    beam service install
  else
    echo "Skipped. Run 'beam service install' whenever you want it running in the background, or 'beam start' to run it in the foreground."
  fi
else
  echo "Non-interactive shell: skipped the background-start prompt. Run 'beam service install' to start it in the background."
fi

echo
echo "Detecting installed agents and wiring beam's hook into every one found (Claude Code, Codex, Cursor, Copilot CLI, Gemini CLI)..."
beam agent install-all
