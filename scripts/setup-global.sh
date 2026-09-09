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
