#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
REPO_DIR="$(pwd)"
LOG_FILE="$REPO_DIR/.build-watch.log"
PID_FILE="$REPO_DIR/.build-watch.pid"
VERSION="$(node -p "require('./package.json').version")"

# Same indigo used for beam's own banner (src/color.ts) and green/red for the step results below
# -- only when stdout is a real terminal and the user hasn't opted out via NO_COLOR.
if [[ -t 1 ]] && [[ -z "${NO_COLOR:-}" ]]; then
  C_INDIGO=$'\033[38;5;99m'; C_GREEN=$'\033[32m'; C_RED=$'\033[31m'; C_RESET=$'\033[0m'
else
  C_INDIGO=""; C_GREEN=""; C_RED=""; C_RESET=""
fi

echo "${C_INDIGO}"' __    ___  ____  __ _  ____  ____  ____   __   _  _
 / _\  / __)(  __)(  ( \(_  _)(  _ \(  __) / _\ ( \/ )
/    \( (_ \ ) _) /    /  )(   ) _ ( ) _) /    \/ \/ \
\_/\_/ \___/(____)\_)__) (__) (____/(____)\_/\_/\_)(_/'"${C_RESET}"
echo "beam $VERSION setup"
echo

# Belt-and-suspenders: run_step below already hides every command's stdout/stderr (banner
# included) unless it fails, but suppress beam's own repeated banner too in case anything
# downstream calls 'beam' outside a run_step.
export BEAM_NO_BANNER=1

DOTS=(. .. ...)

# Runs "$@" while animating "label." / "label.." / "label..." in place, then collapses it to a
# single ✔/✖ result line. All of the command's output (stdout+stderr, banner included) goes to
# $STEP_LOG instead of the terminal -- a healthy run stays quiet; callers decide what to surface
# from the log on failure (or to mine out of it on success, e.g. a config path). Falls back to
# plain "label..." when stdout isn't a TTY (piped/CI logs), since there's nothing to animate.
run_step() {
  local label="$1"; shift
  STEP_LOG="$(mktemp)"
  if [[ ! -t 1 ]]; then
    echo "$label..."
    "$@" >"$STEP_LOG" 2>&1
    local status=$?
    [[ $status -eq 0 ]] && echo "${C_GREEN}✔${C_RESET} $label" || echo "${C_RED}✖${C_RESET} $label"
    return $status
  fi

  "$@" >"$STEP_LOG" 2>&1 &
  local pid=$! i=0
  while kill -0 "$pid" 2>/dev/null; do
    printf "\r\033[K%s%s" "$label" "${DOTS[$i]}"
    i=$(( (i + 1) % 3 ))
    sleep 0.35
  done
  wait "$pid"; local status=$?
  printf "\r\033[K"
  [[ $status -eq 0 ]] && echo "${C_GREEN}✔${C_RESET} $label" || echo "${C_RED}✖${C_RESET} $label"
  return $status
}
trap 'rm -f "${STEP_LOG:-}"' EXIT

# A tiny box-drawn two-column table for the final summary, mirroring prompts.ts's renderTable so
# the CLI's own 'beam setup' and this script's output feel like one product.
print_table() {
  local labels=() values=() lw=0 vw=0
  while [[ $# -gt 0 ]]; do labels+=("$1"); values+=("$2"); shift 2; done
  for l in "${labels[@]}"; do (( ${#l} > lw )) && lw=${#l}; done
  for v in "${values[@]}"; do (( ${#v} > vw )) && vw=${#v}; done
  printf '┌%s┬%s┐\n' "$(printf '─%.0s' $(seq 1 $((lw+2))))" "$(printf '─%.0s' $(seq 1 $((vw+2))))"
  for i in "${!labels[@]}"; do printf '│ %-*s │ %-*s │\n' "$lw" "${labels[$i]}" "$vw" "${values[$i]}"; done
  printf '└%s┴%s┘\n' "$(printf '─%.0s' $(seq 1 $((lw+2))))" "$(printf '─%.0s' $(seq 1 $((vw+2))))"
}

run_step "Installing dependencies" npm install || { cat "$STEP_LOG" >&2; exit 1; }
run_step "Building beam" bash -c "npm run build && chmod +x dist/cli.js" || { cat "$STEP_LOG" >&2; exit 1; }

if ! run_step "Linking beam globally" npm link; then
  if grep -q "EACCES" "$STEP_LOG"; then
    cat "$STEP_LOG" >&2
    cat <<'EOF' >&2

✖ Could not link beam globally: npm's global install folder isn't writable by your user.

  Quick fix (one-time, needs your password):
    sudo npm link

  Permanent fix (no sudo ever again) -- point npm's global prefix at your home directory:
    mkdir -p ~/.npm-global
    npm config set prefix ~/.npm-global
    echo 'export PATH=~/.npm-global/bin:$PATH' >> ~/.zshrc && source ~/.zshrc
    npm link

See the README for details, then re-run: npm run setup:global
EOF
  else
    cat "$STEP_LOG" >&2
  fi
  exit 1
fi

if ! run_step "Verifying beam is on PATH" beam --version; then
  cat "$STEP_LOG" >&2
  cat <<'EOF' >&2

✖ 'beam' linked, but isn't resolving on PATH in this shell.
  Find npm's global bin folder and add it to PATH:
    export PATH="$(npm config get prefix)/bin:$PATH"
  Then re-run: npm run setup:global
EOF
  exit 1
fi

if [[ -f "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
  kill "$(cat "$PID_FILE")" 2>/dev/null || true
fi
nohup npm run build:watch >"$LOG_FILE" 2>&1 &
echo $! > "$PID_FILE"
disown

SERVICE_STATUS="skipped"
if [[ -t 0 ]]; then
  read -r -p $'\nStart the beam collector in the background now (survives reboot/logout)? [Y/n] ' answer
  answer=${answer:-Y}
else
  echo "Non-interactive shell: skipping the background-start prompt."
  answer="n"
fi
if [[ "$answer" =~ ^[Yy] ]]; then
  if run_step "Starting the background collector" beam service install; then
    SERVICE_STATUS="running"
  else
    cat "$STEP_LOG" >&2
    SERVICE_STATUS="failed to start (see above)"
  fi
else
  SERVICE_STATUS="not started (run 'beam service install' later)"
fi

if run_step "Wiring hooks into installed agents" beam agent install-all; then
  AGENT_SUMMARY="$(grep -E '^✔ (Installed|Already installed) for ' "$STEP_LOG" | sed -E 's/^✔ (Installed|Already installed) for //' | paste -sd, - | sed 's/,/, /g')"
  [[ -z "$AGENT_SUMMARY" ]] && AGENT_SUMMARY="none detected on this machine"
else
  cat "$STEP_LOG" >&2
  AGENT_SUMMARY="failed (see above)"
fi

STUDIO_STATUS="not opened -- run 'beam studio' once the collector is running"
if beam token >/dev/null 2>&1; then
  if run_step "Opening beam studio" beam studio; then
    STUDIO_STATUS="opened in your browser"
  else
    cat "$STEP_LOG" >&2
    STUDIO_STATUS="failed to open (see above)"
  fi
fi

DASHBOARD_STATUS="not connected -- run 'beam connect'"
beam whoami >/dev/null 2>&1 && DASHBOARD_STATUS="connected"

echo
print_table \
  "beam" "v$VERSION, linked to this checkout" \
  "Watcher" "PID $(cat "$PID_FILE") -- keeps 'beam' in sync with source" \
  "Service" "$SERVICE_STATUS" \
  "Agent hooks" "$AGENT_SUMMARY" \
  "Dashboard" "$DASHBOARD_STATUS" \
  "Studio" "$STUDIO_STATUS"
echo
echo "Useful next commands:"
echo "  beam connect         link this device to your dashboard"
echo "  beam studio          open the activity dashboard"
echo "  beam service status  check whether the collector is running"
echo "  beam agent list      check hook status per agent"
